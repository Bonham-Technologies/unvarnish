# Autopilot: local rules for this repository

This file belongs to this repository. `bin/vendor-claude-setup` in bonham-ops created it
once and never changes it, so rules here survive every refresh of the vendored policy.
It loads in every session, like `.claude/rules/autopilot.md`.

Where this file conflicts with the autopilot policy (`.claude/rules/autopilot.md` and the
role files in `.claude/autopilot/`), this file wins, except for the hard rules
(**Always**) and the `ap-owner-merge` criteria, which it can only make stricter.

Put each rule under a heading that names the policy section it changes, such as
`## Ticket classes`, `## Steward` or `## Builder, step 2`, and say whether it adds to
that section or replaces part of it. A rule that applies only to one role is still read
by every role, so name the role.

## Ticket classes

Adds to the `ap-owner-merge` criteria (owner decision on BORG-70, 2026-11-05): every change
under `site/` is `ap-owner-merge`, whoever wrote it, because the site is public and
outward-facing. Applies to the steward when it classes a ticket, and to the builder and
dependabot roles when they build or merge.

## Builder, step 6

Adds (owner decision on BORG-70): never merge, or turn on auto-merge for, a PR from a fork
(its `head.repo.full_name` is not this repository) or one whose author (`user.login`) is
anyone other than the owner (`mrbonha`) or `dependabot[bot]`. Label it `needs-owner`
instead. Applies to the builder and dependabot roles, and to any thread asked to merge.
