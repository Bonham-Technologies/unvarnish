from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from unvarnish.artifacts import hash_inputs, write_artifact
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.git import (
    AiFingerprints,
    AuthorStats,
    ChurnEntry,
    CommitInfo,
    GitStats,
    WeeklyBucket,
)
from unvarnish.util.gitcmd import GitError, git, is_git_repo

LOG_FORMAT = "%x1e%H%x1f%aN%x1f%aE%x1f%aI%x1f%B%x1d"

AI_FINGERPRINT_FILES = [
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".cursor", ".clinerules",
    ".windsurfrules", ".github/copilot-instructions.md", ".aider.conf.yml", ".aiderignore",
]
COAUTHOR_RE = re.compile(r"(?im)^co-authored-by:[ \t]*([^<\n]*?)[ \t]*(?:<([^>\n]*)>)?[ \t]*$")
AI_NAME_RE = re.compile(r"(?i)claude|copilot|chatgpt|openai|aider|codex|windsurf")
# Names people also have: count them only with a bot-like identity.
AMBIGUOUS_AI_NAME_RE = re.compile(r"(?i)\b(devin|cline|cursor|gemini)\b")
BOT_IDENTITY_RE = re.compile(r"(?i)\[bot\]|noreply|-ai\b|\bai-|\bbot\b")
AI_EMAIL_RE = re.compile(r"(?i)@(anthropic\.com|openai\.com|cursor\.(com|sh)|"
                         r"cognition\.ai|codeium\.com)$|^copilot@github\.com$")
BOT_RE = re.compile(r"(?i)\[bot\]|(^|\W)bot@|dependabot|renovate|github-actions")
AI_MESSAGE_RE = re.compile(
    r"(?i)\b(generated (?:by|with) (?:claude|chatgpt|copilot|cursor|ai)"
    r"|ai[- ]generated|vibe[- ]coded)\b"
)


@dataclass
class ParsedCommit:
    sha: str
    author: str
    email: str
    date: datetime
    body: str
    added: int = 0
    deleted: int = 0
    files: list[tuple[str, int]] = field(default_factory=list)


RENAME_RE = re.compile(r"^(.*?)\{([^{}]*?) => ([^{}]*?)\}(.*)$")


def is_bulk_commit(added: int, deleted: int, threshold: int) -> bool:
    """A single commit adding more than `threshold` lines (spec: "adding"); large deletions
    are clean-ups, not unreviewed generation."""
    return added > threshold


def rename_target(path: str) -> str:
    """The new path of a `--numstat` rename: `src/{old => new}/x` or `old => new`."""
    m = RENAME_RE.match(path)
    if m:
        prefix, _, new, suffix = m.groups()
        return re.sub(r"/{2,}", "/", f"{prefix}{new}{suffix}").lstrip("/")
    if " => " in path:
        return path.split(" => ", 1)[1]
    return path


def ai_coauthors(body: str) -> set[str]:
    """AI tools named in Co-Authored-By trailers, by name or, when there is none, email."""
    found: set[str] = set()
    for name, email in COAUTHOR_RE.findall(body):
        name, email = name.strip(), email.strip()
        ident = f"{name} {email}"
        if (AI_EMAIL_RE.search(email) or AI_NAME_RE.search(name)
                or (AMBIGUOUS_AI_NAME_RE.search(name) and BOT_IDENTITY_RE.search(ident))):
            found.add(name or email)
    return found


def parse_log(raw: str) -> list[ParsedCommit]:
    commits: list[ParsedCommit] = []
    for chunk in raw.split("\x1e")[1:]:
        head, _, rest = chunk.partition("\x1d")
        try:
            sha, name, email, date_s, body = head.split("\x1f", 4)
        except ValueError:
            continue
        c = ParsedCommit(sha=sha, author=name, email=email,
                         date=datetime.fromisoformat(date_s), body=body)
        for line in rest.strip("\n").splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            a, d, path = parts
            path = rename_target(path)
            a_i = int(a) if a.isdigit() else 0
            d_i = int(d) if d.isdigit() else 0
            c.added += a_i
            c.deleted += d_i
            c.files.append((path, a_i + d_i))
        commits.append(c)
    return commits


def _merge_identities(commits: list[ParsedCommit]) -> list[list[ParsedCommit]]:
    """Union-find over (normalised name, normalised email) keys."""
    parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(x: tuple[str, str]) -> tuple[str, str]:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: tuple[str, str], b: tuple[str, str]) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for c in commits:
        union(("n", c.author.strip().lower()), ("e", c.email.strip().lower()))
    grouped: dict[tuple[str, str], list[ParsedCommit]] = defaultdict(list)
    for c in commits:
        grouped[find(("e", c.email.strip().lower()))].append(c)
    return list(grouped.values())


class GitPhase:
    name = "git"
    reads_source = True  # fails when the source is gone (UNVAR-31)
    depends_on: tuple[str, ...] = ()  # the repository's history, not the census

    def _threshold(self, ctx: ToolContext) -> int:
        return int(ctx.config.scanners.get("generated_bulk", {}).get("commit_lines", 2000))

    def inputs_hash(self, ctx: ToolContext) -> str:
        if not is_git_repo(ctx.source_root):
            return hash_inputs(["no-git"])
        try:
            head = git(["rev-parse", "HEAD"], cwd=ctx.source_root).strip()
            count = git(["rev-list", "--all", "--count"], cwd=ctx.source_root).strip()
        except GitError:
            return hash_inputs(["git-unreadable"])
        return hash_inputs([head, count, str(self._threshold(ctx))])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.git]

    def run(self, ctx: ToolContext) -> PhaseResult:
        stats = self._compute(ctx, self._threshold(ctx))
        write_artifact(ctx.paths.git, stats, produced_by=self.name,
                       inputs_hash=self.inputs_hash(ctx))
        msg = f"{stats.commit_count} commits" if stats.available else f"skipped: {stats.reason}"
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, message=msg)

    def _compute(self, ctx: ToolContext, threshold: int) -> GitStats:
        root = ctx.source_root
        if not is_git_repo(root):
            return GitStats(tool=ctx.tool, available=False, reason="no .git directory",
                            large_commit_threshold=threshold)
        try:
            raw = git(["log", "--all", "--numstat", f"--format={LOG_FORMAT}"], cwd=root)
        except GitError as exc:
            text = str(exc)
            if "does not have any commits" in text:
                reason = "repository has no commits"
            else:
                detail = text.split(": ", 1)[-1].splitlines()[0] if text else "?"
                reason = f"git log failed: {detail}"[:300]
            return GitStats(tool=ctx.tool, available=False, reason=reason,
                            large_commit_threshold=threshold)
        commits = parse_log(raw)
        if not commits:
            return GitStats(tool=ctx.tool, available=False, reason="repository has no commits",
                            large_commit_threshold=threshold)
        commits.sort(key=lambda c: c.date)

        # authors: one person may commit under several emails (work, GitHub noreply);
        # merge identities that share a normalised name or an email.
        groups = _merge_identities(commits)
        authors: list[AuthorStats] = []
        bots: list[AuthorStats] = []
        for members in groups:
            names = Counter(c.author for c in members)
            emails = Counter(c.email for c in members)
            name, email = names.most_common(1)[0][0], emails.most_common(1)[0][0]
            lines = sum(c.added + c.deleted for c in members)
            stat = AuthorStats(name=name, email=email, commits=len(members),
                               lines_changed=lines, share=0.0)
            (bots if BOT_RE.search(name) or BOT_RE.search(email) else authors).append(stat)
        total_lines = sum(a.lines_changed for a in authors)
        human_commits = sum(a.commits for a in authors) or 1
        for group in (authors, bots):
            group.sort(key=lambda a: (-a.lines_changed, -a.commits, a.name))
        for a in authors:
            a.share = (
                (a.lines_changed / total_lines) if total_lines else (a.commits / human_commits)
            )
        cumulative, bus_factor = 0.0, 0
        for a in authors:
            cumulative += a.share
            bus_factor += 1
            if cumulative >= 0.8:
                break

        # velocity
        weeks: dict = defaultdict(lambda: [0, 0])
        for c in commits:
            start = c.date.date() - timedelta(days=c.date.weekday())
            weeks[start][0] += 1
            weeks[start][1] += c.added + c.deleted
        velocity = [WeeklyBucket(week_start=k, commits=v[0], lines_changed=v[1])
                    for k, v in sorted(weeks.items())]

        # churn
        churn: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for c in commits:
            for path, lines in c.files:
                churn[path][0] += 1
                churn[path][1] += lines
        hotspots = sorted(
            (ChurnEntry(path=p, changes=v[0], lines_changed=v[1]) for p, v in churn.items()),
            key=lambda e: (-e.changes, -e.lines_changed, e.path),
        )[:20]

        # AI fingerprints
        trailers: dict[str, int] = defaultdict(int)
        patterns = 0
        for c in commits:
            for name in ai_coauthors(c.body):
                trailers[name] += 1  # commits with this co-author, not trailer lines
            if AI_MESSAGE_RE.search(c.body):
                patterns += 1
        fp_files = [f for f in AI_FINGERPRINT_FILES if (root / f).exists()]

        large = [
            CommitInfo(sha=c.sha, date=c.date, author=c.author, lines_added=c.added,
                       lines_deleted=c.deleted, files=len(c.files),
                       message_head=c.body.strip().splitlines()[0] if c.body.strip() else "")
            for c in commits if is_bulk_commit(c.added, c.deleted, threshold)
        ]

        return GitStats(
            tool=ctx.tool, available=True, commit_count=len(commits),
            first_commit=commits[0].date, last_commit=commits[-1].date,
            active_days=len({c.date.date() for c in commits}),
            authors=authors, bots=bots, bus_factor=bus_factor,
            top_author_share=authors[0].share if authors else None,
            large_commits=large, large_commit_threshold=threshold,
            weekly_velocity=velocity, churn_hotspots=hotspots,
            ai_fingerprints=AiFingerprints(files=fp_files, coauthor_trailers=dict(trailers),
                                           message_patterns=patterns),
        )
