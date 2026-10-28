#!/usr/bin/env python3
"""Generate/refresh the dev->main PR description from conventional commits.

Usage: pr-describe.py <base-sha> <head-sha> <pr-number>

Writes body.md. An auto-generated section lives between HTML-comment markers and
is regenerated on every run; anything outside the markers (notes you add by
hand) is preserved.
"""
import re
import subprocess
import sys

base, head, pr = sys.argv[1], sys.argv[2], sys.argv[3]

subjects = subprocess.check_output(
    ["git", "log", "--no-merges", "--reverse", "--format=%s", f"{base}..{head}"],
    text=True,
).splitlines()

# Each group: display heading, the conventional-commit types it collects, and a
# (singular, plural) label for the one-line title summary.
GROUPS = [
    ("Features", {"feat"}, ("feature", "features")),
    ("Fixes", {"fix"}, ("fix", "fixes")),
    ("Documentation", {"docs"}, ("doc", "docs")),
    ("Tests", {"test"}, ("test", "tests")),
    ("Maintenance", {"chore", "ci", "build", "refactor", "perf", "style"}, ("maintenance change", "maintenance changes")),
]
OTHER_LABEL = ("other change", "other changes")


def ctype(subject):
    m = re.match(r"([a-z]+)(\([^)]*\))?!?:", subject)
    return m.group(1) if m else None


buckets = {name: [] for name, *_ in GROUPS}
other = []
for s in subjects:
    t = ctype(s)
    for name, types, _ in GROUPS:
        if t in types:
            buckets[name].append(s)
            break
    else:
        other.append(s)

out = ["## What", "", "Promotes `dev` to `main`.", ""]
for name, *_ in GROUPS:
    if buckets[name]:
        out.append(f"### {name}")
        out += [f"- {s}" for s in buckets[name]]
        out.append("")
if other:
    out.append("### Other")
    out += [f"- {s}" for s in other]
    out.append("")
# The checklist stays in the PR template (outside the markers) so ticked boxes
# survive; the auto block is just the commit summary and is safe to regenerate.
auto = "\n".join(out).strip()

START, END = "<!-- dev-pr:auto -->", "<!-- /dev-pr:auto -->"
block = f"{START}\n{auto}\n{END}"

cur = subprocess.check_output(
    ["gh", "pr", "view", pr, "--json", "body", "-q", ".body"], text=True
)
if cur.strip() == "null":
    cur = ""

if START in cur and END in cur:
    new = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _m: block, cur, flags=re.S)
elif cur.strip():
    new = cur.rstrip() + "\n\n" + block + "\n"
else:
    new = block + "\n"

with open("body.md", "w") as f:
    f.write(new)


# Title: a mechanical one-line summary, e.g. "Promote dev to main: 1 feature, 3
# fixes". Counts follow the same grouping as the body.
def plural(n, labels):
    return f"{n} {labels[0] if n == 1 else labels[1]}"


parts = [plural(len(buckets[name]), labels) for name, _, labels in GROUPS if buckets[name]]
if other:
    parts.append(plural(len(other), OTHER_LABEL))
title = "Promote dev to main"
if parts:
    title += ": " + ", ".join(parts)

# Only set the title when the maintainer hasn't given the PR one of their own --
# it's empty or still an auto title -- so a hand-edited title survives a later
# push (the auto body block is preserved separately, via its markers).
cur_title = subprocess.check_output(
    ["gh", "pr", "view", pr, "--json", "title", "-q", ".title"], text=True
).strip()
if cur_title in ("", "null") or cur_title.startswith("Promote dev to main"):
    with open("title.txt", "w") as f:
        f.write(title)
