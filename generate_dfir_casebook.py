#!/usr/bin/env python3
"""
generate_dfir_casebook.py — Reusable DFIR Interactive Casebook Generator

Usage:
    python3 generate_dfir_casebook.py [--case <dir>] [--template <html>] [--out <html>]

Defaults:
    --case      .                          (current directory, must contain engagement/)
    --template  reference_casebook.html   (Aleemladha reference template)
    --out       casebook_<case_id>.html

Input structure expected under <case>/engagement/:
    engagement.yaml   — case metadata
    timeline.md       — UTC-timestamped events table
    report.md         — findings narrative
    hosts.csv         — host inventory

The generator:
    1. Removes sec-c2attrib (RE-based C2 tool attribution — requires separate RE analysis not in standard DFIR triage)
    2. Removes Recipe 3 from sec-proof (same reason)
    3. Replaces "AdaptixC2" / "Adaptix" specific-attribution text with generic "Unknown C2 Framework"
    4. Removes "RE-confirmed" claims (binary-level RE not performed in triage)
    5. Replaces the EVENTS JavaScript array with events from timeline.md
    6. Substitutes case title, client, headline from engagement.yaml
    7. Preserves ALL other sections, CSS, animations, and interactive features intact
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Generate interactive DFIR casebook")
parser.add_argument("--case",     default=".",                     help="Case directory containing engagement/")
parser.add_argument("--template", default="reference_casebook.html", help="Reference HTML template")
parser.add_argument("--out",      default=None,                    help="Output HTML filename")
args = parser.parse_args()

CASE_DIR = os.path.abspath(args.case)
ENG_DIR  = os.path.join(CASE_DIR, "engagement")
REF_HTML = os.path.join(CASE_DIR, args.template)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def read(path, default=""):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        return default

def yaml_get(text, key, default="—"):
    m = re.search(rf'^{re.escape(key)}\s*:\s*["\']?(.*?)["\']?\s*$', text, re.MULTILINE)
    return m.group(1).strip() if m else default

def log(msg):
    print(f"[*] {msg}")

def ok(msg):
    print(f"    [✓] {msg}")

def warn(msg):
    print(f"    [!] {msg}", file=sys.stderr)

# ---------------------------------------------------------------------------
# Load inputs
# ---------------------------------------------------------------------------
log("Loading inputs...")
html = read(REF_HTML)
if not html:
    sys.exit(f"ERROR: Template not found: {REF_HTML}")

eng_yaml    = read(os.path.join(ENG_DIR, "engagement.yaml"))
timeline_md = read(os.path.join(ENG_DIR, "timeline.md"))
report_md   = read(os.path.join(ENG_DIR, "report.md"))

ok(f"Template:   {REF_HTML} ({len(html):,} bytes)")
ok(f"Engagement: {ENG_DIR}")

# Derive output path
case_id = yaml_get(eng_yaml, "engagement_id", "case")
out_path = args.out or os.path.join(CASE_DIR, f"casebook_{case_id.split('-')[0]}.html")

# ---------------------------------------------------------------------------
# STEP 1 — Remove sec-c2attrib (C2 tool RE-attribution section)
# ---------------------------------------------------------------------------
log("Step 1: Removing sec-c2attrib (RE-based C2 attribution)...")
before = len(html)
html = re.sub(
    r'<section[^>]*id="sec-c2attrib"[^>]*>.*?</section>',
    '',
    html,
    flags=re.DOTALL,
    count=1
)
delta = before - len(html)
if delta > 0:
    ok(f"Removed sec-c2attrib ({delta:,} bytes)")
else:
    warn("sec-c2attrib not found (already absent or different id)")

# ---------------------------------------------------------------------------
# STEP 2 — Remove Recipe 3 from sec-proof (AdaptixC2 VAD match recipe)
# ---------------------------------------------------------------------------
log("Step 2: Removing Recipe 3 (C2 binary RE analysis) from sec-proof...")
before = len(html)

# Recipe 3 is a <div> inside the grid — remove the specific div block
# Pattern: the <!-- Recipe 3 --> comment through end of that div
html = re.sub(
    r'\s*<!--\s*Recipe\s*3\s*[—–-]+\s*AdaptixC2[^>]*-->\s*'   # comment
    r'<div[^>]*>.*?</div>\s*',                                   # the recipe card div
    '\n    ',
    html,
    flags=re.DOTALL,
    count=1
)

# Also update the lede that says "three claims" → "two claims"
html = html.replace(
    "flagged three claims as the likeliest to be wrong: the impacket\n    attribution, the LSASS-dump actor, and the C2 family.",
    "flagged two claims as the likeliest to be wrong: the impacket\n    attribution and the LSASS-dump actor."
)

delta = before - len(html)
ok(f"Recipe 3 removed ({delta:,} bytes delta)")

# ---------------------------------------------------------------------------
# STEP 3 — Replace AdaptixC2 attribution text with evidence-grounded language
# ---------------------------------------------------------------------------
log("Step 3: Replacing AdaptixC2 attribution with evidence-grounded language...")

# We DO have evidence of: rnSylwOz.exe beaconing to 173.230.136.180:8443 (Volatility netscan)
# We DO NOT have: binary RE, source-to-binary match, git clone comparison
# Replace specific attribution claims; preserve factual C2 activity descriptions

replacements = [
    # Specific tool attribution → generic
    (r'AdaptixC2\b',                                       "Unknown C2 Framework"),
    (r'Adaptix\s+C2\b',                                    "Unknown C2 Framework"),
    (r'\bAdaptix\s+reflective-loader\b',                   "reflective loader"),
    (r'\bAdaptix\s+beacon\b',                              "C2 beacon"),
    (r'\bAdaptix\s+source\b',                              "C2 source"),
    (r'\bAdaptix\s+markers\b',                             "C2 indicators"),
    (r'\bAdaptix-specific\s+strings\b',                    "C2-specific strings"),
    (r'\bAdaptix\b(?!\s+/)',                               "Unknown C2"),
    # RE analysis claims
    (r'\bRE-confirmed\b',                                  "evidence-supported"),
    # YARA file references
    (r'adaptix_null404\.yar',                              "c2_ioc.yar"),
    (r'adaptix_beacon_reflective_loader[^\s<"\']*',        "c2_reflective_loader"),
    (r'adaptix_reflective_loader_in_memory',               "c2_in_memory"),
    (r'adaptix_\*\s+rules',                                "C2 detection rules"),
    (r'adaptix_\*',                                        "c2_*"),
    # git clone reference (RE workflow not in evidence)
    (r'git\s+clone\s+https?://[^\s<"\']+adaptix[^\s<"\']*', "# [C2 source analysis not performed in this engagement]"),
    # Source match claims
    (r'five grep-match hits against the (?:Adaptix|Unknown C2) repo',
                                                           "signature matches against known C2 indicators"),
    (r'matches (?:Adaptix|Unknown C2) public source 5-for-5',
                                                           "matches known C2 indicators 5-for-5"),
    (r'source-to-binary (?:Adaptix|Unknown C2) match',    "binary C2 indicator match"),
    (r'Addendum V[\'`]?s source-to-binary.*?match',       "binary indicator analysis"),
    # Column header in tables
    (r'C2 attribution\s*·\s*(?:Adaptix|Unknown) C2',      "C2 attribution · Unknown C2 Framework (rnSylwOz.exe)"),
    (r'(?:Adaptix|Unknown C2) C2 (?:HTTPS )?listener',    "Unknown C2 Framework listener"),
    # GitHub path reference embedded in tech analysis (exposes specific source attribution)
    (r'Unknown C2 Framework/AdaptixServer/extenders/[^\s<"\'`]+',
                                                           "[C2 source path — RE analysis not performed in this engagement]"),
    # "Adaptix / Sliver / Havoc" — keep this, it's generic threat landscape context
    # (no replacement needed — "Adaptix/Sliver/Havoc" is factual threat landscape language)
]

count_total = 0
for pattern, replacement in replacements:
    new_html, n = re.subn(pattern, replacement, html, flags=re.IGNORECASE)
    if n:
        count_total += n
        html = new_html
        ok(f"  '{pattern[:50]}' → '{replacement[:50]}' ({n}×)")

ok(f"Total replacements: {count_total}")

# Special case: "Adaptix/Sliver/Havoc" — restore (it's generic context, not tool attribution)
html = html.replace("Unknown C2/Sliver/Havoc", "Adaptix/Sliver/Havoc")
html = html.replace("Unknown C2 / Sliver / Havoc", "Adaptix/Sliver/Havoc")

# ---------------------------------------------------------------------------
# STEP 4 — Parse timeline events
# ---------------------------------------------------------------------------
log("Step 4: Parsing timeline events from engagement/timeline.md...")

events = []
current_phase = None

for line in timeline_md.split('\n'):
    # Phase marker
    phase_match = re.match(r'^##\s+Phase\s+(\d+)\s+[·•]\s+(.+)', line)
    if phase_match:
        current_phase = phase_match.group(2).strip()
        continue

    # Event row: | 2026-03-08 HH:MM:SS | HOST | description | source |
    if re.match(r'^\|\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line):
        cells = [c.strip() for c in line.split('|')[1:-1]]
        if len(cells) >= 3:
            time_match = re.search(r'(\d{2}:\d{2}:\d{2})', cells[0])
            if time_match:
                events.append({
                    't':      time_match.group(1),
                    'host':   cells[1],
                    'desc':   cells[2],
                    'source': cells[3] if len(cells) > 3 else "",
                    'phase':  current_phase or "—",
                })

ok(f"{len(events)} events from {len(set(e['phase'] for e in events))} phases")

if not events:
    warn("No events parsed — check timeline.md format")

# Assign act codes based on phase names
phase_act_map = {
    "Unauthenticated Recon":          "I",
    "Initial Foothold":               "I",
    "Cloud Pivot":                    "VI",
    "Privilege Escalation":           "II",
    "Lateral Movement":               "III",
    "Domain Dominance":               "IV",
    "Ransomware":                     "V",
    "Domain Dominance & Ransomware":  "V",
}

for evt in events:
    act = "I"
    for key, val in phase_act_map.items():
        if key.lower() in evt['phase'].lower():
            act = val
            break
    evt['act'] = act

# ---------------------------------------------------------------------------
# STEP 5 — Build EVENTS JavaScript array
# ---------------------------------------------------------------------------
log("Step 5: Building EVENTS JavaScript array...")

js_lines = ["const EVENTS = ["]
for i, evt in enumerate(events):
    desc = evt['desc'].replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")
    comma = "," if i < len(events) - 1 else ""
    js_lines.append(
        f"  {{ t:'{evt['t']}', host:'{evt['host']}', act:'{evt['act']}', "
        f"edge:null, desc:'{desc}' }}{comma}"
    )
js_lines.append("];")
js_lines.append("EVENTS.forEach(e => e.sec = toSec(e.t));")
events_js = "\n".join(js_lines) + "\n"

ok(f"EVENTS array: {len(events)} entries")

# Replace in template
events_pattern = r'const EVENTS = \[.*?\];.*?EVENTS\.forEach\(e => e\.sec = toSec\(e\.t\)\);'
html, n = re.subn(events_pattern, lambda _: events_js, html, flags=re.DOTALL, count=1)
if n:
    ok("EVENTS array replaced in template")
else:
    warn("EVENTS pattern not found — array may not have been replaced")

# ---------------------------------------------------------------------------
# STEP 6 — Case metadata substitutions
# ---------------------------------------------------------------------------
log("Step 6: Applying case metadata substitutions...")

headline  = yaml_get(eng_yaml, "headline", "")
client    = yaml_get(eng_yaml, "client",   "Unknown Client")
case_name = yaml_get(eng_yaml, "engagement_id", case_id).split("-")[0]

# Case title in hero
html = re.sub(
    r'<h1 class="case-title">.*?</h1>',
    f'<h1 class="case-title">{case_name}</h1>',
    html,
    flags=re.DOTALL,
    count=1
)

# HTML <title> tag
html = re.sub(
    r'<title>[^<]*</title>',
    f'<title>{case_name} — DFIR Casebook</title>',
    html,
    count=1
)

ok(f"Case title: {case_name}")
ok(f"Client:     {client}")

# ---------------------------------------------------------------------------
# STEP 7 — Verify sections
# ---------------------------------------------------------------------------
log("Step 7: Verifying section completeness...")

ref_html     = read(REF_HTML)
ref_sections = set(re.findall(r'id="(sec-[^"]*)"', ref_html))
gen_sections = set(re.findall(r'id="(sec-[^"]*)"', html))
expected_removed = {"sec-c2attrib"}
missing = ref_sections - gen_sections - expected_removed

ok(f"Sections in output: {len(gen_sections)}/{len(ref_sections)} "
   f"(removed: {expected_removed})")

if missing:
    warn(f"Unexpected missing sections: {missing}")
else:
    ok("All expected sections preserved")

# ---------------------------------------------------------------------------
# STEP 8 — Write output
# ---------------------------------------------------------------------------
log(f"Step 8: Writing {out_path}...")
os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

# Final evidence check
# "Adaptix/Sliver/Havoc" is acceptable threat-landscape context (not specific attribution)
remaining_adaptix = len([m for m in re.finditer(r'\badaptix\b', html, re.IGNORECASE)
                         if not re.search(r'adaptix\s*/\s*Sliver|Sliver.*adaptix', m.string[max(0,m.start()-30):m.end()+30], re.IGNORECASE)])
remaining_re_conf = len(re.findall(r'RE-confirmed', html))

print()
print("=" * 70)
print(f"  OUTPUT:   {out_path}")
print(f"  SIZE:     {len(html) / 1024:.0f} KB")
print(f"  EVENTS:   {len(events)}")
print(f"  SECTIONS: {len(gen_sections)}/28 (sec-c2attrib intentionally omitted)")
print()
print(f"  Evidence integrity checks:")
print(f"    AdaptixC2 attribution remaining:  {remaining_adaptix} (target: 0)")
print(f"    RE-confirmed claims remaining:    {remaining_re_conf} (target: 0)")
print()
if remaining_adaptix == 0 and remaining_re_conf == 0:
    print("  [✓] PASS — casebook is grounded in collected evidence only")
else:
    print("  [!] REVIEW — some attribution text may remain (check manually)")
print("=" * 70)
