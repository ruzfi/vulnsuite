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

GROUPS = [
    ("Features", {"feat"}),
    ("Fixes", {"fix"}),
    ("Documentation", {"docs"}),
    ("Tests", {"test"}),
    ("Maintenance", {"chore", "ci", "build", "refactor", "perf", "style"}),
]


def ctype(subject):
    m = re.match(r"([a-z]+)(\([^)]*\))?!?:", subject)
    return m.group(1) if m else None


buckets = {name: [] for name, _ in GROUPS}
other = []
for s in subjects:
    t = ctype(s)
    for name, types in GROUPS:
        if t in types:
            buckets[name].append(s)
            break
    else:
        other.append(s)

out = ["## What", "", "Promotes `dev` to `main`.", ""]
for name, _ in GROUPS:
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
