# Fixture: a marking whose category is not in the closed enum

**CM-402** — A requirement with no scenario, carrying a non-testable marking
whose category is not one of the four permitted values. It must fail closed:
the marking exempts nothing and the requirement stays an orphan.

> **Non-testable — convenient.** "convenient" is not one of process,
> documentation, meta or external, so this marker must not excuse anything at
> all, and the requirement below must still be reported.
