from __future__ import annotations


def plural(n: int, singular: str, plural_form: str | None = None) -> str:
    """"1 finding", "2 findings", "0 findings"; pass `plural_form` for irregular nouns."""
    return f"{n} {pluralize(n, singular, plural_form)}"


def pluralize(n: int, singular: str, plural_form: str | None = None) -> str:
    """The noun alone, in the form that agrees with `n`."""
    if n == 1:
        return singular
    if plural_form is not None:
        return plural_form
    if singular.endswith("y") and singular[-2:-1] not in ("a", "e", "i", "o", "u"):
        return singular[:-1] + "ies"
    if singular.endswith(("s", "x", "z", "ch", "sh")):
        return singular + "es"
    return singular + "s"


def is_are(n: int) -> str:
    """"is" for exactly one, otherwise "are"."""
    return "is" if n == 1 else "are"
