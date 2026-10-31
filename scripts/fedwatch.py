#!/usr/bin/env python3
"""
fedwatch — watch the FedRAMP Consolidated Rules for changes and explain them.

Reads two versions of fedramp-consolidated-rules.json from a clone of
https://github.com/FedRAMP/rules, compares every rule (FRR), definition (FRD),
Key Security Indicator (KSI) and control parameter/guidance entry (CTL), and
writes a plain-English report of what was added, removed and changed.

Standard library only.

Commands
  check     Compare the last-processed upstream commit with upstream HEAD.
            Used by the daily GitHub Action.
  backfill  Rebuild one report per day of upstream history (portfolio archive).
  diff      Compare any two upstream refs and print Markdown to stdout.
  site      Rebuild docs/index.html and docs/feed.xml from existing reports.
  send-email  Email a report as a newsletter (SMTP settings come from env).
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import html
import json
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict
from pathlib import Path

RULES_FILE = "fedramp-consolidated-rules.json"
UPSTREAM_WEB = "https://github.com/FedRAMP/rules"
ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REPORTS = DOCS / "reports"
STATE = ROOT / "state" / "last.json"
SITE_URL = os.environ.get("SITE_URL", "https://pscybergeek.github.io/fedramp-rules-watch").rstrip("/")
SITE_TITLE = "FedRAMP Rules Watch"

# A record key looks like VDR-CSO-DET, FRD-ACV, KSI-CNA-EIS or AC-06-01.
RECORD_ID = re.compile(r"^[A-Z]{2,4}(?:-[A-Z0-9]{2,}){1,3}$")
KIND = {"FRR": "Rule", "FRD": "Definition", "KSI": "Key Security Indicator", "CTL": "Control parameter/guidance"}
IGNORED_FIELDS = {"updated"}          # FedRAMP's own changelog; surfaced separately, never diffed
SET_FIELDS = {"controls", "terms", "alts", "affects", "related"}
FORCE_RANK = {"MUST": 3, "MUST NOT": 3, "SHOULD": 2, "SHOULD NOT": 2, "MAY": 1}
MAPPING_FIELDS = {"controls", "terms", "alts", "related"}
TIMEFRAME_FIELDS = {"timeframe_num", "timeframe_type", "timeframe_num_min", "timeframe_num_max"}
UNITS = {"bizdays": "business days", "days": "days", "months": "months", "years": "years", "hours": "hours", "weeks": "weeks"}
KEYWORD_RX = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b")


# ───────────────────────────── git helpers ─────────────────────────────

def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def load_at(repo: Path, sha: str) -> dict:
    return json.loads(git(repo, "show", f"{sha}:{RULES_FILE}"))


def commits_touching(repo: Path, since_sha: str | None, until: str = "HEAD") -> list[dict]:
    rng = f"{since_sha}..{until}" if since_sha else until
    out = git(repo, "log", "--reverse", "--format=%H%x1f%cI%x1f%s", rng, "--", RULES_FILE)
    rows = []
    for line in out.splitlines():
        sha, date, subject = line.split("\x1f", 2)
        rows.append({"sha": sha, "short": sha[:7], "date": date, "subject": subject,
                     "url": f"{UPSTREAM_WEB}/commit/{sha}"})
    return rows


# ───────────────────────────── flattening ─────────────────────────────

def index_records(doc: dict) -> dict[str, dict]:
    """Every rule-like record keyed by its ID, with where it lives in the file."""
    found: dict[str, dict] = {}

    def walk(node, path):
        if not isinstance(node, dict):
            return
        for key, val in node.items():
            if "info" not in path and path and isinstance(val, dict) and RECORD_ID.match(key):
                found[key] = {"id": key, "section": path[0], "path": "/".join(path), "data": val}
                continue
            walk(val, path + [key])

    for top in ("FRR", "FRD", "KSI", "CTL"):
        if top in doc:
            walk(doc[top], [top])
    for rec in found.values():
        rec["kind"] = KIND.get(rec["section"], rec["section"])
        rec["family"] = family_of(rec)
        rec["name"] = rec["data"].get("name") or rec["data"].get("term") or ""
        rec["text"] = primary_text(rec["data"])
    return found


def family_of(rec: dict) -> str:
    parts = rec["path"].split("/")
    if rec["section"] == "FRD":
        return "FRD"
    if rec["section"] == "CTL":
        return f"CTL {parts[1]}"
    return parts[1]


def primary_text(d: dict) -> str:
    """The sentence a reader most cares about: the obligation itself."""
    for key in ("statement", "definition"):
        if isinstance(d.get(key), str):
            return d[key]
    if isinstance(d.get("varies_by_class"), dict):
        lines = []
        for cls, body in sorted(d["varies_by_class"].items()):
            text = primary_text(body) if isinstance(body, dict) else str(body)
            if text:
                lines.append(f"Class {cls.upper()}: {text}")
        if lines:
            return "\n".join(lines)
    if isinstance(d.get("guidance"), list):
        return "\n".join(map(str, d["guidance"]))
    if isinstance(d.get("parameters"), list):
        return "\n".join(f"{p.get('parameterId', '?')} = {p.get('value', '')}" for p in d["parameters"] if isinstance(p, dict))
    return ""


def timeframe(d: dict) -> str:
    unit = UNITS.get(d.get("timeframe_type"), d.get("timeframe_type") or "")
    if "timeframe_num" in d:
        n = d["timeframe_num"]
    elif "timeframe_num_min" in d or "timeframe_num_max" in d:
        n = f"{d.get('timeframe_num_min', '?')}–{d.get('timeframe_num_max', '?')}"
    else:
        return ""
    if unit and str(n) == "1":
        unit = unit.rstrip("s").replace("business day", "business day")
    return f"{n} {unit}".strip()


def in_primary(field: str, d: dict) -> bool:
    """Is this field part of what primary_text() shows for this record?"""
    leaf = field.split(".")[0].split("[")[0]
    if leaf in ("statement", "definition"):
        return True
    if any(isinstance(d.get(k), str) for k in ("statement", "definition")):
        return False
    if leaf == "varies_by_class":
        return field.endswith((".statement", ".definition")) or ".guidance" in field or ".parameters" in field
    if leaf == "guidance":
        return isinstance(d.get("guidance"), list) and not isinstance(d.get("varies_by_class"), dict)
    if leaf == "parameters":
        return not isinstance(d.get("varies_by_class"), dict) and not isinstance(d.get("guidance"), list)
    return False


def flatten(node, prefix: str = "", out: dict | None = None) -> dict:
    """Dotted-path → leaf. Short-string lists stay whole so they diff as sets."""
    out = {} if out is None else out
    if isinstance(node, dict):
        for k, v in node.items():
            if not prefix and k in IGNORED_FIELDS:
                continue
            flatten(v, f"{prefix}{k}.", out)
    elif isinstance(node, list):
        key = prefix.rstrip(".")
        if all(isinstance(x, (str, int, float, bool)) for x in node):
            leaf = key.rsplit(".", 1)[-1]
            if leaf in SET_FIELDS or all(isinstance(x, str) and len(x) <= 60 for x in node):
                out[key] = ("set", sorted(map(str, node)))
            else:
                out[key] = ("text", "\n".join(map(str, node)))
        else:
            for i, v in enumerate(node):
                flatten(v, f"{key}[{i}].", out)
    else:
        key = prefix.rstrip(".")
        out[key] = ("text", node) if isinstance(node, str) else ("scalar", node)
    return out


def label(field: str) -> str:
    named = {
        "statement": "Statement", "definition": "Definition", "name": "Name", "term": "Term",
        "force": "Obligation level", "timeframe_type": "Timeframe unit", "timeframe_num": "Timeframe",
        "notes": "Notes", "note": "Note", "danger": "Warning", "controls": "Mapped NIST controls",
        "terms": "Linked defined terms", "alts": "Alternate terms", "affects": "Applies to",
        "related": "Related rules", "guidance": "Guidance", "parameters": "Parameters",
        "following_information": "Required information", "corrective_actions": "Corrective actions",
        "examples": "Examples", "artifacts": "Required artifacts", "notification": "Notification method",
        "schema": "Schema", "tag": "Tag", "purpose": "Purpose", "status": "Status",
        "effective.is": "Effective status", "effective.current_status": "Current status",
        "effective.date.obtain": "Effective date (obtain)", "effective.date.maintain": "Effective date (maintain)",
        "effective.date.optional_adoption": "Optional adoption date",
        "effective.date.grace.default": "Grace period ends",
        "effective.date.grace.until_next_assessment": "Grace until next assessment",
    }
    for prog, name in (("20x.", "20x"), ("rev5.", "Rev5")):
        if field.startswith(prog):
            return f"{name} {label(field[len(prog):]).lower()}"
    if field in named:
        return named[field]
    m = re.match(r"varies_by_class\.([a-z])\.(.+)", field)
    if m:
        return f"Class {m.group(1).upper()} {label(m.group(2)).lower()}"
    m = re.match(r"(\w+)\[(\d+)\]\.?(.*)", field)
    if m:
        base = label(m.group(1)).rstrip("s")
        rest = f" {label(m.group(3)).lower()}" if m.group(3) else ""
        return f"{base} {int(m.group(2)) + 1}{rest}"
    return re.sub(r"\s+", " ", field.replace("_", " ").replace(".", " ")).capitalize()


# ───────────────────────────── text helpers ─────────────────────────────

def norm(s) -> str:
    return " ".join(str(s).split())


def squash(s) -> str:
    return re.sub(r"[\W_]+", "", str(s).lower())


def word_ops(a: str, b: str):
    """[(op, text)] where op ∈ {'=', '-', '+'} — word-level diff."""
    aw, bw = str(a).split(), str(b).split()
    ops = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, aw, bw, autojunk=False).get_opcodes():
        if tag == "equal":
            ops.append(("=", " ".join(aw[i1:i2])))
        else:
            if i2 > i1:
                ops.append(("-", " ".join(aw[i1:i2])))
            if j2 > j1:
                ops.append(("+", " ".join(bw[j1:j2])))
    return ops


def word_counts(a: str, b: str) -> tuple[int, int]:
    removed = sum(len(t.split()) for op, t in word_ops(a, b) if op == "-")
    added = sum(len(t.split()) for op, t in word_ops(a, b) if op == "+")
    return removed, added


def keywords(s: str) -> Counter:
    return Counter(KEYWORD_RX.findall(str(s)))


def fmt_count(c: Counter) -> str:
    return ", ".join(f"{k}×{v}" if v > 1 else k for k, v in sorted(c.items())) or "none"


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# ───────────────────────────── diffing ─────────────────────────────

def diff_fields(a: dict, b: dict) -> list[dict]:
    fa, fb = flatten(a), flatten(b)
    changes = []
    for key in sorted(set(fa) | set(fb), key=lambda k: (k.split(".")[0] != "name", k)):
        va, vb = fa.get(key), fb.get(key)
        if va == vb:
            continue
        kind = (vb or va)[0]
        before = va[1] if va else None
        after = vb[1] if vb else None
        ch = {"field": key, "label": label(key), "type": kind, "before": before, "after": after}
        if kind == "set" and va and vb and va[0] == vb[0] == "set":
            ch["added_items"] = sorted(set(after) - set(before))
            ch["removed_items"] = sorted(set(before) - set(after))
        if isinstance(before, str) and isinstance(after, str):
            if norm(before) == norm(after):
                continue                      # whitespace-only noise
            ch["editorial"] = squash(before) == squash(after)
        changes.append(ch)
    return changes


def explain(rec_a: dict, rec_b: dict, fields: list[dict], new_notes: list[str]) -> dict:
    """Turn field changes into plain-English sentences and a significance grade."""
    by = {c["field"]: c for c in fields}
    sentences, grade = [], "editorial"

    def bump(g):
        nonlocal grade
        order = ["editorial", "mapping", "minor", "substantive"]
        grade = g if order.index(g) > order.index(grade) else grade

    if rec_a["path"] != rec_b["path"]:
        sentences.append(f"Moved from `{rec_a['path']}` to `{rec_b['path']}`.")
        bump("substantive")
    if "name" in by or "term" in by:
        c = by.get("name") or by.get("term")
        sentences.append(f"Renamed from “{c['before']}” to “{c['after']}”.")
        bump("minor")
    if "force" in by:
        c = by["force"]
        ra, rb = FORCE_RANK.get(c["before"] or "", 0), FORCE_RANK.get(c["after"] or "", 0)
        direction = "stronger" if rb > ra else "weaker" if rb < ra else "different"
        sentences.append(f"Obligation level changed from **{c['before'] or 'unset'}** to **{c['after'] or 'unset'}** ({direction} requirement).")
        bump("substantive")
    if TIMEFRAME_FIELDS & set(by):
        ta, tb = timeframe(rec_a["data"]), timeframe(rec_b["data"])
        if ta and tb:
            sentences.append(f"Deadline changed from **{ta}** to **{tb}**.")
            bump("substantive")
        elif tb:
            sentences.append(f"Machine-readable deadline added: **{tb}**.")
            bump("minor")
        else:
            sentences.append(f"Machine-readable deadline removed (was **{ta}**).")
            bump("substantive")

    text_a, text_b = rec_a["text"], rec_b["text"]
    if norm(text_a) != norm(text_b):
        ka, kb = keywords(text_a), keywords(text_b)
        if squash(text_a) == squash(text_b):
            sentences.append("Editorial fix to the wording (punctuation, capitalization or formatting only).")
        elif not text_a:
            sentences.append("Statement text added.")
            bump("substantive")
        elif not text_b:
            sentences.append("Statement text removed.")
            bump("substantive")
        else:
            rm, ad = word_counts(text_a, text_b)
            sentences.append(f"Statement reworded ({plural(rm, 'word')} removed, {plural(ad, 'word')} added).")
            bump("minor" if rm + ad <= 3 else "substantive")
        if ka != kb:
            sentences.append(f"Normative keywords changed: {fmt_count(ka)} → {fmt_count(kb)}.")
            bump("substantive")

    for c in fields:
        f = c["field"]
        leaf = f.split(".")[0]
        if f in ("name", "term", "force") or f in TIMEFRAME_FIELDS:
            continue
        if in_primary(f, rec_a["data"]) or in_primary(f, rec_b["data"]):
            continue  # already explained via the statement comparison above
        if f.rsplit(".", 1)[-1] == "force" and c["before"] and c["after"]:
            ra, rb = FORCE_RANK.get(c["before"], 0), FORCE_RANK.get(c["after"], 0)
            direction = "stronger" if rb > ra else "weaker" if rb < ra else "different"
            sentences.append(f"{c['label']} changed from **{c['before']}** to **{c['after']}** ({direction} requirement).")
            bump("substantive")
        elif c["type"] == "set" and c.get("added_items") is not None:
            bits = []
            if c["added_items"]:
                bits.append("added " + ", ".join(f"`{x}`" for x in c["added_items"]))
            if c["removed_items"]:
                bits.append("removed " + ", ".join(f"`{x}`" for x in c["removed_items"]))
            sentences.append(f"{c['label']}: {'; '.join(bits)}.")
            bump("mapping" if leaf in MAPPING_FIELDS else "minor")
        elif c["type"] == "set" and leaf in MAPPING_FIELDS:
            items = c["after"] if c["before"] is None else c["before"]
            if not items:
                continue
            verb = "added" if c["before"] is None else "removed"
            sentences.append(f"{c['label']} {verb}: " + ", ".join(f"`{x}`" for x in items) + ".")
            bump("mapping")
        elif c["before"] is None:
            sentences.append(f"{c['label']} added.")
            bump("minor")
        elif c["after"] is None:
            sentences.append(f"{c['label']} removed.")
            bump("minor")
        elif c.get("editorial"):
            sentences.append(f"{c['label']}: editorial fix.")
        elif c["type"] == "text" and len(str(c["before"])) > 80:
            rm, ad = word_counts(c["before"], c["after"])
            sentences.append(f"{c['label']} reworded ({plural(rm, 'word')} removed, {plural(ad, 'word')} added).")
            bump("minor")
            if keywords(c["before"]) != keywords(c["after"]):
                sentences.append(f"{c['label']} normative keywords changed: {fmt_count(keywords(c['before']))} → {fmt_count(keywords(c['after']))}.")
                bump("substantive")
        else:
            sentences.append(f"{c['label']} changed from “{c['before']}” to “{c['after']}”.")
            bump("minor")
    if not sentences:
        sentences.append("Structural change with no effect on wording.")
    return {"sentences": sentences, "grade": grade, "fedramp_notes": new_notes}


def new_changelog_notes(a: dict | None, b: dict) -> list[str]:
    seen = {json.dumps(x, sort_keys=True) for x in (a or {}).get("updated", []) if isinstance(x, dict)}
    return [f"{x.get('date', '')}: {x.get('comment', '')}".strip(": ")
            for x in b.get("updated", []) if isinstance(x, dict) and json.dumps(x, sort_keys=True) not in seen]


def info_sections(doc: dict) -> dict[str, tuple[str, dict]]:
    out = {}
    for fam, body in (doc.get("FRR") or {}).items():
        if isinstance(body, dict) and isinstance(body.get("info"), dict):
            out[fam] = (body["info"].get("name", fam), body["info"])
    if isinstance((doc.get("FRD") or {}).get("info"), dict):
        out["FRD"] = (doc["FRD"]["info"].get("name", "FedRAMP Definitions"), doc["FRD"]["info"])
    for fam, body in (doc.get("KSI") or {}).items():
        if isinstance(body, dict):
            meta = {k: v for k, v in body.items() if k != "indicators"}
            out[f"KSI-{fam}"] = (body.get("name", fam), meta)
    top = {k: v for k, v in (doc.get("info") or {}).items() if k not in ("version", "last_updated")}
    out["(all)"] = ("Ruleset-wide settings", top)
    return out


def diff_docs(a: dict, b: dict) -> dict:
    ra, rb = index_records(a), index_records(b)
    added = [rb[k] for k in sorted(set(rb) - set(ra))]
    removed = [ra[k] for k in sorted(set(ra) - set(rb))]

    changed = []
    for k in sorted(set(ra) & set(rb)):
        fields = diff_fields(ra[k]["data"], rb[k]["data"])
        if not fields and ra[k]["path"] == rb[k]["path"]:
            continue
        x = explain(ra[k], rb[k], fields, new_changelog_notes(ra[k]["data"], rb[k]["data"]))
        changed.append({"id": k, "kind": rb[k]["kind"], "family": rb[k]["family"], "name": rb[k]["name"],
                        "path_before": ra[k]["path"], "path": rb[k]["path"],
                        "text_before": ra[k]["text"], "text_after": rb[k]["text"],
                        "fields": fields, **x})

    # A removal plus an addition with near-identical text is almost always an ID change.
    renamed = []
    for r in list(removed):
        best, score = None, 0.0
        for n in added:
            if r["section"] != n["section"] or not r["text"] or not n["text"]:
                continue
            s = difflib.SequenceMatcher(None, norm(r["text"]), norm(n["text"])).ratio()
            if s > score:
                best, score = n, s
        if best and score >= 0.9:
            renamed.append({"from": r["id"], "to": best["id"], "name": best["name"], "kind": best["kind"],
                            "similarity": round(score, 3), "text_before": r["text"], "text_after": best["text"]})
            removed.remove(r)
            added.remove(best)

    meta = []
    ia, ib = info_sections(a), info_sections(b)
    for fam in sorted(set(ia) | set(ib)):
        if fam not in ia:
            meta.append({"family": fam, "name": ib[fam][0], "status": "added", "fields": []})
            continue
        if fam not in ib:
            meta.append({"family": fam, "name": ia[fam][0], "status": "removed", "fields": []})
            continue
        fields = diff_fields(ia[fam][1], ib[fam][1])
        if fields:
            meta.append({"family": fam, "name": ib[fam][0], "status": "changed", "fields": fields})

    slim = lambda r: {"id": r["id"], "kind": r["kind"], "family": r["family"], "name": r["name"],
                      "path": r["path"], "text": r["text"],
                      "force": r["data"].get("force"), "fedramp_notes": new_changelog_notes(None, r["data"])}
    return {"added": [slim(r) for r in added], "removed": [slim(r) for r in removed],
            "renamed": renamed, "changed": changed, "meta": meta}


def is_empty(d: dict) -> bool:
    return not any(d[k] for k in ("added", "removed", "renamed", "changed", "meta"))


# ───────────────────────────── summary ─────────────────────────────

GRADE_ORDER = {"substantive": 0, "minor": 1, "editorial": 2, "mapping": 3}


def headline(d: dict) -> str:
    c = Counter(x["grade"] for x in d["changed"])
    bits = []
    if d["added"]:
        bits.append(f"{len(d['added'])} added")
    if d["removed"]:
        bits.append(f"{len(d['removed'])} removed")
    if d["renamed"]:
        bits.append(f"{len(d['renamed'])} re-IDed")
    if d["changed"]:
        bits.append(f"{len(d['changed'])} changed")
    if any(m["fields"] and any("date" in f["field"] for f in m["fields"]) for m in d["meta"]):
        bits.append("effective dates moved")
    elif d["meta"]:
        bits.append(f"{plural(len(d['meta']), 'ruleset')} updated")
    return ", ".join(bits) or "no changes"


def glance(d: dict) -> list[str]:
    """The paragraph a busy reader would read and nothing else."""
    out = []
    grades = Counter(x["grade"] for x in d["changed"])
    parts = []
    if d["added"]:
        parts.append(f"**{plural(len(d['added']), 'new entry')}**".replace("entrys", "entries"))
    if d["removed"]:
        parts.append(f"**{len(d['removed'])} removed**")
    if d["renamed"]:
        parts.append(f"**{len(d['renamed'])} given a new ID**")
    if d["changed"]:
        parts.append(f"**{len(d['changed'])} changed** ({grades['substantive']} substantive, "
                     f"{grades['minor']} minor, {grades['editorial']} editorial, {grades['mapping']} mapping-only)")
    if parts:
        out.append("This update has " + ", ".join(parts) + ".")

    for field, what in (("controls", "NIST control mappings"), ("terms", "defined-term links")):
        n = sum(1 for x in d["changed"] if any(f["field"] == field for f in x["fields"]))
        if n:
            out.append(f"{what[0].upper() + what[1:]} changed on {plural(n, 'entry')}.".replace("entrys", "entries"))
    for x in d["changed"]:
        for s in x["sentences"]:
            if re.search(r"obligation level|^Deadline|normative keywords|deadline removed", s, re.I):
                out.append(f"`{x['id']}` {x['name']}: {s}")
    for m in d["meta"]:
        for f in m["fields"]:
            if "date" in f["field"] or f["field"].endswith(("current_status", ".is", "status")):
                out.append(f"{m['family']} ({m['name']}): {f['label']} changed from “{f['before']}” to “{f['after']}”.")
        if m["status"] != "changed":
            out.append(f"Ruleset {m['family']} ({m['name']}) {m['status']}.")
    for r in d["added"]:
        out.append(f"New {r['kind'].lower()} `{r['id']}` {r['name']}" + (f" ({r['force']})" if r.get("force") else "") + ".")
    for r in d["removed"]:
        out.append(f"Removed {r['kind'].lower()} `{r['id']}` {r['name']}.")
    for r in d["renamed"]:
        out.append(f"`{r['from']}` now appears as `{r['to']}` ({r['name']}).")
    return out


def highlights(d: dict, n: int = 2) -> list[str]:
    """The most important lines after the count sentence, for list views."""
    lines = glance(d)[1:]
    order = [r"obligation", r"[Dd]eadline", r"keywords", r"date|status", r"^Removed", r"^New ", r"new ID"]
    rank = lambda l: next((i for i, rx in enumerate(order) if re.search(rx, l)), len(order))
    ranked = sorted(lines, key=lambda l: (rank(l), lines.index(l)))
    return ranked[:n]


def sorted_changed(d: dict):
    full = [x for x in d["changed"] if x["grade"] != "mapping"]
    mapping = [x for x in d["changed"] if x["grade"] == "mapping"]
    full.sort(key=lambda x: (GRADE_ORDER[x["grade"]], x["id"]))
    return full, mapping


# ───────────────────────────── markdown ─────────────────────────────

def md_quote(text: str) -> str:
    return "\n".join("> " + (line or " ") for line in str(text).splitlines()) or "> _(empty)_"


def md_inline_diff(a: str, b: str) -> str:
    parts = []
    for op, t in word_ops(a, b):
        parts.append(t if op == "=" else f"~~{t}~~" if op == "-" else f"**{t}**")
    return " ".join(parts)


def render_md(report: dict, link: str | None = None) -> str:
    d, m = report["diff"], report
    L = [f"# FedRAMP rules update — {m['date']}", ""]
    L.append(f"**Version** `{m['from']['version']}` → `{m['to']['version']}` · "
             f"**Upstream** [{m['from']['short']}…{m['to']['short']}]({UPSTREAM_WEB}/compare/{m['from']['sha']}...{m['to']['sha']})")
    if link:
        L.append(f"\n[Read this report on the web]({link})")
    L += ["", "## At a glance", ""]
    L += [f"- {s}" for s in glance(d)] or ["- No changes."]

    if d["meta"]:
        L += ["", "## Effective dates and ruleset settings", ""]
        for x in d["meta"]:
            L.append(f"**{x['family']} — {x['name']}**" + ("" if x["status"] == "changed" else f" ({x['status']})"))
            for f in x["fields"]:
                L.append(md_field(f))
            L.append("")

    if d["added"]:
        L += ["", "## Added", ""]
        for r in d["added"]:
            L += [f"### `{r['id']}` — {r['name'] or '(unnamed)'}",
                  f"_{r['kind']} · {r['path']}" + (f" · {r['force']}" if r.get("force") else "") + "_", "", md_quote(r["text"]), ""]
            L += [f"_FedRAMP's note: {n}_" for n in r["fedramp_notes"]] + [""]

    if d["removed"]:
        L += ["", "## Removed", ""]
        for r in d["removed"]:
            L += [f"### `{r['id']}` — {r['name'] or '(unnamed)'}", f"_{r['kind']} · was at {r['path']}_", "",
                  "**Last statement:**", "", md_quote(r["text"]), ""]

    if d["renamed"]:
        L += ["", "## New IDs for existing entries", ""]
        for r in d["renamed"]:
            L += [f"### `{r['from']}` → `{r['to']}` — {r['name']}",
                  f"_{r['kind']} · text {int(r['similarity'] * 100)}% identical_", ""]
            if norm(r["text_before"]) != norm(r["text_after"]):
                L += ["**Change:** " + md_inline_diff(r["text_before"], r["text_after"]), ""]

    full, mapping = sorted_changed(d)
    if full:
        L += ["", "## Changed", ""]
        for x in full:
            L += [f"### `{x['id']}` — {x['name'] or '(unnamed)'}",
                  f"_{x['kind']} · {x['path']} · **{x['grade']}**_", ""]
            L += [f"- {s}" for s in x["sentences"]]
            L += [f"- _FedRAMP's changelog: {n}_" for n in x["fedramp_notes"]]
            if norm(x["text_before"]) != norm(x["text_after"]):
                L += ["", "**Before**", "", md_quote(x["text_before"]), "", "**After**", "", md_quote(x["text_after"])]
            other = [f for f in x["fields"] if f["type"] == "text" and f["field"].split(".")[0] not in ("statement", "definition", "name", "term")
                     and not f["field"].startswith("varies_by_class") and f["before"] and f["after"]]
            if other:
                L += ["", "<details><summary>Other wording changes</summary>", ""]
                for f in other:
                    L += [f"**{f['label']}:** {md_inline_diff(f['before'], f['after'])}", ""]
                L += ["</details>"]
            L.append("")

    if mapping:
        L += ["", "## Mapping-only updates", "",
              "Cross-references changed but the requirement wording did not.", "",
              "| ID | Name | Change |", "|---|---|---|"]
        for x in mapping:
            L.append(f"| `{x['id']}` | {x['name']} | {' '.join(x['sentences'])} |")

    L += ["", "## Upstream commits", ""]
    L += [f"- [`{c['short']}`]({c['url']}) {c['date'][:10]} — {c['subject']}" for c in m["commits"]]
    L += ["", "---", f"_Generated by [{SITE_TITLE}]({SITE_URL}) from [{UPSTREAM_WEB}]({UPSTREAM_WEB}). "
          "Unofficial; FedRAMP's published rules are authoritative._", ""]
    return "\n".join(L)


def md_field(f: dict) -> str:
    if f["type"] == "set" and f.get("added_items") is not None:
        bits = []
        if f["added_items"]:
            bits.append("added " + ", ".join(f"`{i}`" for i in f["added_items"]))
        if f["removed_items"]:
            bits.append("removed " + ", ".join(f"`{i}`" for i in f["removed_items"]))
        return f"- {f['label']}: {'; '.join(bits)}"
    if f["before"] is None:
        return f"- {f['label']} added: “{f['after']}”"
    if f["after"] is None:
        return f"- {f['label']} removed (was “{f['before']}”)"
    if f["type"] == "text" and len(str(f["before"])) > 80:
        return f"- {f['label']}: {md_inline_diff(f['before'], f['after'])}"
    return f"- {f['label']}: “{f['before']}” → “{f['after']}”"


# ───────────────────────────── html ─────────────────────────────

CSS = """
:root{--bg:#fbfaf7;--fg:#1d1f21;--muted:#62666d;--line:#e3e0d8;--card:#fff;--accent:#0b5cad;
--add:#0f7a3d;--addbg:#e3f4ea;--del:#b42318;--delbg:#fde8e6;--warn:#8a5a00;--warnbg:#fff3d6;--code:#f1efe9}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#121416;--fg:#e7e7e4;--muted:#9ca1a8;--line:#2a2e33;
--card:#1a1d20;--accent:#6aa8ff;--add:#5fd38d;--addbg:#123322;--del:#ff8a80;--delbg:#3a1714;--warn:#f0c060;--warnbg:#33290f;--code:#23272b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 80px}a{color:var(--accent)}
h1{font-size:1.9rem;line-height:1.2;margin:.2em 0 .3em;letter-spacing:-.01em}h2{font-size:1.15rem;margin:2.2em 0 .8em;padding-bottom:.4em;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:0 0 .3em}.muted{color:var(--muted)}.small{font-size:.86rem}
code,.id,blockquote,.diff,td,li{overflow-wrap:anywhere}
code,.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em;background:var(--code);padding:.08em .35em;border-radius:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.glance{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 18px}
.glance li{margin:.25em 0}
.pill{display:inline-block;font-size:.72rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase;padding:.15em .55em;border-radius:99px;margin-left:.4em;vertical-align:.1em}
.substantive{background:var(--warnbg);color:var(--warn)}.minor{background:var(--code);color:var(--muted)}.editorial{background:var(--code);color:var(--muted)}
.added{background:var(--addbg);color:var(--add)}.removed{background:var(--delbg);color:var(--del)}
blockquote{margin:.6em 0;padding:.5em .9em;border-left:3px solid var(--line);white-space:pre-wrap}
blockquote.before{border-color:var(--del)}blockquote.after{border-color:var(--add)}
.lbl{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-top:.8em}
del{background:var(--delbg);color:var(--del);text-decoration:line-through}ins{background:var(--addbg);color:var(--add);text-decoration:none}
.diff{white-space:pre-wrap}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
.list a.row{display:block;text-decoration:none;color:inherit}.list .row:hover{border-color:var(--accent)}
.tbl{overflow-x:auto}header.top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:baseline;margin-bottom:24px}
.brand{font-weight:700;text-decoration:none;color:var(--fg)}
details summary{cursor:pointer;color:var(--muted);font-size:.9rem}
"""

e = html.escape


def h_inline_diff(a: str, b: str) -> str:
    out = []
    for op, t in word_ops(a, b):
        out.append(e(t) if op == "=" else f"<del>{e(t)}</del>" if op == "-" else f"<ins>{e(t)}</ins>")
    return " ".join(out)


def h_md(s: str) -> str:
    """Tiny Markdown subset for our own generated sentences (bold, code)."""
    s = e(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", s)


def page(title: str, body: str, rel: str = "") -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<link rel="alternate" type="application/atom+xml" title="{SITE_TITLE}" href="{rel}feed.xml">
<style>{CSS}</style></head><body><main>
<header class="top"><a class="brand" href="{rel}index.html">{SITE_TITLE}</a>
<span class="small"><a href="{rel}feed.xml">Atom feed</a> · <a href="{UPSTREAM_WEB}">Source rules</a></span></header>
{body}
<p class="small muted" style="margin-top:48px">Unofficial summaries generated automatically from
<a href="{UPSTREAM_WEB}">FedRAMP/rules</a>. FedRAMP's published rules are authoritative.</p>
</main></body></html>"""


def render_html(report: dict) -> str:
    d, m = report["diff"], report
    B = [f"<p class='muted small'>{e(m['date'])}</p><h1>{e(headline(d)).capitalize()}</h1>",
         f"<p class='muted'>Version <code>{e(m['from']['version'])}</code> → <code>{e(m['to']['version'])}</code> · "
         f"<a href='{UPSTREAM_WEB}/compare/{m['from']['sha']}...{m['to']['sha']}'>upstream diff</a> · "
         f"<a href='{e(m['slug'])}.md'>Markdown</a> · <a href='{e(m['slug'])}.json'>JSON</a></p>",
         "<h2>At a glance</h2><ul class='glance'>" + "".join(f"<li>{h_md(s)}</li>" for s in glance(d)) + "</ul>"]

    if d["meta"]:
        B.append("<h2>Effective dates and ruleset settings</h2>")
        for x in d["meta"]:
            B.append(f"<div class='card'><h3>{e(x['family'])} — {e(x['name'])}</h3><ul>")
            for f in x["fields"]:
                B.append(f"<li>{h_md(md_field(f)[2:]) if f['type'] != 'text' or len(str(f['before'] or '')) <= 80 else e(f['label']) + ': <span class=diff>' + h_inline_diff(f['before'], f['after']) + '</span>'}</li>")
            B.append("</ul></div>")

    if d["added"]:
        B.append("<h2>Added</h2>")
        for r in d["added"]:
            B.append(f"<div class='card'><h3><span class='id'>{e(r['id'])}</span> {e(r['name'])}<span class='pill added'>new</span></h3>"
                     f"<div class='small muted'>{e(r['kind'])} · {e(r['path'])}{' · ' + e(r['force']) if r.get('force') else ''}</div>"
                     f"<blockquote class='after'>{e(r['text'])}</blockquote>"
                     + "".join(f"<p class='small muted'>FedRAMP's note: {e(n)}</p>" for n in r["fedramp_notes"]) + "</div>")
    if d["removed"]:
        B.append("<h2>Removed</h2>")
        for r in d["removed"]:
            B.append(f"<div class='card'><h3><span class='id'>{e(r['id'])}</span> {e(r['name'])}<span class='pill removed'>removed</span></h3>"
                     f"<div class='small muted'>{e(r['kind'])} · was at {e(r['path'])}</div>"
                     f"<div class='lbl'>Last statement</div><blockquote class='before'>{e(r['text'])}</blockquote></div>")
    if d["renamed"]:
        B.append("<h2>New IDs for existing entries</h2>")
        for r in d["renamed"]:
            B.append(f"<div class='card'><h3><span class='id'>{e(r['from'])}</span> → <span class='id'>{e(r['to'])}</span> {e(r['name'])}</h3>"
                     f"<div class='small muted'>text {int(r['similarity'] * 100)}% identical</div>"
                     + (f"<div class='diff'>{h_inline_diff(r['text_before'], r['text_after'])}</div>" if norm(r['text_before']) != norm(r['text_after']) else "")
                     + "</div>")

    full, mapping = sorted_changed(d)
    if full:
        B.append("<h2>Changed</h2>")
        for x in full:
            B.append(f"<div class='card'><h3><span class='id'>{e(x['id'])}</span> {e(x['name'])}<span class='pill {x['grade']}'>{x['grade']}</span></h3>"
                     f"<div class='small muted'>{e(x['kind'])} · {e(x['path'])}</div><ul>"
                     + "".join(f"<li>{h_md(s)}</li>" for s in x["sentences"])
                     + "".join(f"<li class='muted'>FedRAMP's changelog: {e(n)}</li>" for n in x["fedramp_notes"]) + "</ul>")
            if norm(x["text_before"]) != norm(x["text_after"]):
                B.append(f"<div class='lbl'>Before</div><blockquote class='before'>{e(x['text_before'])}</blockquote>"
                         f"<div class='lbl'>After</div><blockquote class='after'>{e(x['text_after'])}</blockquote>"
                         f"<details><summary>Word-level changes</summary><div class='diff'>{h_inline_diff(x['text_before'], x['text_after'])}</div></details>")
            other = [f for f in x["fields"] if f["type"] == "text" and f["field"].split(".")[0] not in ("statement", "definition", "name", "term")
                     and not f["field"].startswith("varies_by_class") and f["before"] and f["after"]]
            if other:
                B.append("<details><summary>Other wording changes</summary>" + "".join(
                    f"<p><strong>{e(f['label'])}:</strong> <span class='diff'>{h_inline_diff(f['before'], f['after'])}</span></p>" for f in other) + "</details>")
            B.append("</div>")
    if mapping:
        B.append("<h2>Mapping-only updates</h2><p class='muted small'>Cross-references changed; requirement wording did not.</p>"
                 "<div class='tbl'><table><tr><th>ID</th><th>Name</th><th>Change</th></tr>"
                 + "".join(f"<tr><td><code>{e(x['id'])}</code></td><td>{e(x['name'])}</td><td>{h_md(' '.join(x['sentences']))}</td></tr>" for x in mapping)
                 + "</table></div>")
    B.append("<h2>Upstream commits</h2><ul class='small'>" + "".join(
        f"<li><a href='{e(c['url'])}'><code>{e(c['short'])}</code></a> {e(c['date'][:10])} — {e(c['subject'])}</li>" for c in m["commits"]) + "</ul>")
    return page(f"{headline(d).capitalize()} — {m['date']} · {SITE_TITLE}", "\n".join(B), rel="../")


def load_reports() -> list[dict]:
    reps = [json.loads(p.read_text()) for p in REPORTS.glob("*.json")]
    return sorted(reps, key=lambda r: (r["date"], r["to"]["version"]), reverse=True)


def build_site() -> None:
    reps = load_reports()
    rows = []
    for r in reps:
        g = Counter(x["grade"] for x in r["diff"]["changed"])
        sub = g["substantive"] + len(r["diff"]["added"]) + len(r["diff"]["removed"])
        rows.append(f"<a class='row card' href='reports/{e(r['slug'])}.html'><div class='small muted'>{e(r['date'])} · "
                    f"<code>{e(r['to']['version'])}</code></div><strong>{e(headline(r['diff'])).capitalize()}</strong>"
                    + (f"<span class='pill substantive'>{sub} substantive</span>" if sub else "")
                    + "".join(f"<div class='small muted'>{h_md(line)}</div>" for line in highlights(r['diff'])) + "</a>")
    latest = reps[0]["to"] if reps else {"version": "—"}
    body = (f"<h1>What changed in the FedRAMP rules</h1>"
            f"<p>A daily check of <a href='{UPSTREAM_WEB}'>FedRAMP/rules</a>, the machine-readable Consolidated Rules for 2026. "
            f"When the file changes, this site explains which rules, definitions, Key Security Indicators and control parameters were "
            f"added, removed or reworded, with the before and after text.</p>"
            f"<p class='small muted'>Latest version tracked: <code>{e(latest['version'])}</code> · {len(reps)} reports · "
            f"Subscribe: <a href='feed.xml'>Atom feed</a> or watch the <a href='https://github.com/PSCyberGeek/fedramp-rules-watch'>GitHub repo</a> (Issues).</p>"
            f"<h2>Reports</h2><div class='list'>{''.join(rows) or '<p>No reports yet.</p>'}</div>")
    (DOCS / "index.html").write_text(page(SITE_TITLE, body))
    (DOCS / ".nojekyll").write_text("")

    now = (reps[0]["to"]["date"] if reps else "2026-01-01T00:00:00Z")
    entries = []
    for r in reps[:50]:
        url = f"{SITE_URL}/reports/{r['slug']}.html"
        updated = r["to"]["date"] if "T" in r["to"]["date"] else r["date"] + "T00:00:00Z"
        summary = "<ul>" + "".join(f"<li>{h_md(s)}</li>" for s in glance(r["diff"])[:25]) + "</ul>"
        entries.append(f"""<entry><title>{e(r['date'])}: {e(headline(r['diff']))}</title>
<link href="{e(url)}"/><id>{e(url)}</id><updated>{e(updated)}</updated>
<summary type="html">{e(summary)}</summary></entry>""")
    (DOCS / "feed.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>{SITE_TITLE}</title>
<subtitle>Plain-English diffs of the FedRAMP Consolidated Rules</subtitle>
<link href="{SITE_URL}/feed.xml" rel="self"/><link href="{SITE_URL}/"/>
<id>{SITE_URL}/</id><updated>{now}</updated><author><name>{SITE_TITLE}</name></author>
{''.join(entries)}
</feed>
""")


# ───────────────────────────── email newsletter ─────────────────────────────

def render_email(rep: dict, max_items: int = 12) -> tuple[str, str, str]:
    """(subject, html, text). Inline styles only, because mail clients strip <style>."""
    d = rep["diff"]
    url = f"{SITE_URL}/reports/{rep['slug']}.html"
    subject = f"FedRAMP rules {rep['to']['version']}: {headline(d)}"
    ink, muted, line, accent = "#1d1f21", "#62666d", "#e3e0d8", "#0b5cad"
    font = "font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;"
    code = "font-family:Menlo,Consolas,monospace;font-size:13px;background:#f1efe9;padding:1px 5px;border-radius:4px;"
    ins = "background:#e3f4ea;color:#0f7a3d;text-decoration:none;"
    dele = "background:#fde8e6;color:#b42318;text-decoration:line-through;"

    def md(t: str) -> str:
        t = e(t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        return re.sub(r"`(.+?)`", rf"<span style='{code}'>\1</span>", t)

    def wdiff(a: str, b: str) -> str:
        return " ".join(e(t) if op == "=" else f"<del style='{dele}'>{e(t)}</del>" if op == "-" else f"<ins style='{ins}'>{e(t)}</ins>"
                        for op, t in word_ops(a, b))

    def card(title: str, meta: str, body: str) -> str:
        return (f"<div style='border:1px solid {line};border-radius:8px;padding:14px 16px;margin:12px 0;background:#fff'>"
                f"<div style='font-weight:600;font-size:15px'>{title}</div>"
                f"<div style='color:{muted};font-size:12px;margin:2px 0 8px'>{meta}</div>{body}</div>")

    H = [f"<div style='{font}color:{ink};background:#fbfaf7;padding:24px 12px'>"
         f"<div style='max-width:640px;margin:0 auto'>"
         f"<div style='font-size:13px;color:{muted}'>FedRAMP Rules Watch · {e(rep['date'])}</div>"
         f"<h1 style='font-size:22px;margin:6px 0 4px'>{e(headline(d)).capitalize()}</h1>"
         f"<div style='font-size:13px;color:{muted}'>Version <span style='{code}'>{e(rep['from']['version'])}</span> → "
         f"<span style='{code}'>{e(rep['to']['version'])}</span></div>",
         f"<h2 style='font-size:16px;margin:22px 0 8px'>At a glance</h2>"
         f"<ul style='margin:0;padding-left:20px;line-height:1.55;font-size:14px'>"
         + "".join(f"<li style='margin:4px 0'>{md(x)}</li>" for x in glance(d)[:20]) + "</ul>"]
    T = [subject, f"Version {rep['from']['version']} -> {rep['to']['version']}", "", "AT A GLANCE"]
    T += ["- " + re.sub(r"[*`]", "", x) for x in glance(d)[:20]]

    shown = 0
    full, mapping = sorted_changed(d)
    items = ([("added", r) for r in d["added"]] + [("removed", r) for r in d["removed"]]
             + [("changed", x) for x in full])
    if items:
        H.append("<h2 style='font-size:16px;margin:24px 0 4px'>Details</h2>")
        T += ["", "DETAILS"]
    for kind, x in items[:max_items]:
        shown += 1
        if kind == "added":
            H.append(card(f"<span style='{code}'>{e(x['id'])}</span> {e(x['name'])} · <span style='color:#0f7a3d'>new</span>",
                          f"{e(x['kind'])} · {e(x['path'])}", f"<div style='font-size:14px;line-height:1.5;white-space:pre-wrap'>{e(x['text'])}</div>"))
            T += ["", f"NEW {x['id']} {x['name']}", x["text"]]
        elif kind == "removed":
            H.append(card(f"<span style='{code}'>{e(x['id'])}</span> {e(x['name'])} · <span style='color:#b42318'>removed</span>",
                          f"{e(x['kind'])} · was at {e(x['path'])}",
                          f"<div style='font-size:14px;line-height:1.5;color:{muted};white-space:pre-wrap'>{e(x['text'])}</div>"))
            T += ["", f"REMOVED {x['id']} {x['name']}", x["text"]]
        else:
            body = "<ul style='margin:0 0 8px;padding-left:18px;font-size:14px;line-height:1.5'>" + "".join(
                f"<li>{md(sx)}</li>" for sx in x["sentences"]) + "</ul>"
            if norm(x["text_before"]) != norm(x["text_after"]):
                body += (f"<div style='font-size:12px;color:{muted};text-transform:uppercase;letter-spacing:.04em'>What changed in the text</div>"
                         f"<div style='font-size:14px;line-height:1.55;white-space:pre-wrap'>{wdiff(x['text_before'], x['text_after'])}</div>")
            H.append(card(f"<span style='{code}'>{e(x['id'])}</span> {e(x['name'])} · {e(x['grade'])}",
                          f"{e(x['kind'])} · {e(x['path'])}", body))
            T += ["", f"CHANGED {x['id']} {x['name']} ({x['grade']})"] + ["- " + re.sub(r"[*`]", "", sx) for sx in x["sentences"]]
            if norm(x["text_before"]) != norm(x["text_after"]):
                T += ["BEFORE: " + x["text_before"], "AFTER:  " + x["text_after"]]
    rest = len(items) - shown + len(mapping)
    more = f"{plural(rest, 'more entry')} in the full report. ".replace("entrys", "entries") if rest else ""
    H.append(f"<p style='margin:24px 0;font-size:14px'>{e(more)}<a href='{e(url)}' style='display:inline-block;background:{accent};"
             f"color:#fff;padding:9px 16px;border-radius:6px;text-decoration:none;font-weight:600'>Read the full report</a></p>"
             f"<p style='font-size:12px;color:{muted};border-top:1px solid {line};padding-top:12px'>Unofficial summary generated from "
             f"<a href='{UPSTREAM_WEB}' style='color:{muted}'>FedRAMP/rules</a>. FedRAMP's published rules are authoritative. "
             f"Archive: <a href='{SITE_URL}/' style='color:{muted}'>{SITE_URL.split('//')[-1]}</a></p></div></div>")
    T += ["", more + "Full report: " + url, "", "Unofficial summary. FedRAMP's published rules are authoritative."]
    return subject, "".join(H), "\n".join(T)


def send_email(rep: dict) -> None:
    import smtplib
    import ssl
    from email.message import EmailMessage
    user, password = os.environ.get("SMTP_USERNAME"), os.environ.get("SMTP_PASSWORD")
    recipients = [a.strip() for a in os.environ.get("MAIL_TO", "").replace(";", ",").split(",") if a.strip()]
    if not (user and password and recipients):
        print("Email skipped: set SMTP_USERNAME, SMTP_PASSWORD and MAIL_TO secrets to enable it.")
        return
    subject, html_body, text_body = render_email(rep)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{SITE_TITLE} <{os.environ.get('MAIL_FROM') or user}>"
    msg["To"] = msg["From"] if len(recipients) > 1 else recipients[0]   # multiple recipients go in Bcc
    msg.set_content(text_body)
    msg.add_alternative(f"<!doctype html><html><body style='margin:0'>{html_body}</body></html>", subtype="html")
    host, port = os.environ.get("SMTP_HOST") or "smtp.gmail.com", int(os.environ.get("SMTP_PORT") or 465)
    with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=30) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg, to_addrs=recipients)
    print(f"Emailed {len(recipients)} recipient(s): {subject}")


def cmd_send_email(args) -> int:
    reps = load_reports()
    rep = next((r for r in reps if r["slug"] == args.slug), None) if args.slug else (reps[0] if reps else None)
    if not rep:
        print("No report found to send.")
        return 1
    if args.preview:
        subject, html_body, _ = render_email(rep)
        Path(args.preview).write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>{e(subject)}</title></head>"
                                      f"<body style='margin:0'>{html_body}</body></html>")
        print(f"Preview written to {args.preview}")
        return 0
    send_email(rep)
    return 0


# ───────────────────────────── report I/O ─────────────────────────────

def make_report(repo: Path, from_sha: str, to_sha: str) -> dict | None:
    a, b = load_at(repo, from_sha), load_at(repo, to_sha)
    d = diff_docs(a, b)
    if is_empty(d):
        return None
    to_date = git(repo, "show", "-s", "--format=%cI", to_sha).strip()
    from_date = git(repo, "show", "-s", "--format=%cI", from_sha).strip()
    date = to_date[:10]
    slug = date
    i = 2
    while (REPORTS / f"{slug}.json").exists() and json.loads((REPORTS / f"{slug}.json").read_text())["to"]["sha"] != to_sha:
        slug, i = f"{date}-{i}", i + 1
    return {
        "slug": slug, "date": date,
        "from": {"sha": from_sha, "short": from_sha[:7], "date": from_date, "version": (a.get("info") or {}).get("version", "?")},
        "to": {"sha": to_sha, "short": to_sha[:7], "date": to_date, "version": (b.get("info") or {}).get("version", "?")},
        "commits": commits_touching(repo, from_sha, to_sha),
        "summary": {"headline": headline(d), "glance": glance(d)},
        "diff": d,
    }


def write_report(rep: dict) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    base = REPORTS / rep["slug"]
    base.with_suffix(".json").write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    base.with_suffix(".md").write_text(render_md(rep, f"{SITE_URL}/reports/{rep['slug']}.html"))
    base.with_suffix(".html").write_text(render_html(rep))
    return base


def issue_body(rep: dict, limit: int = 60000) -> str:
    md = render_md(rep, f"{SITE_URL}/reports/{rep['slug']}.html")
    if len(md) <= limit:
        return md
    head = md[: limit - 400]
    head = head[: head.rfind("\n### ")] if "\n### " in head else head
    return head + f"\n\n---\n**Report truncated for GitHub.** [Read the full report]({SITE_URL}/reports/{rep['slug']}.html).\n"


def set_output(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    for k, v in kv.items():
        print(f"{k}={v}")
        if path:
            with open(path, "a") as fh:
                fh.write(f"{k}={v}\n")


def read_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def write_state(sha: str, version: str) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"upstream_sha": sha, "version": version,
                                 "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}, indent=1) + "\n")


# ───────────────────────────── commands ─────────────────────────────

def cmd_check(args) -> int:
    repo = Path(args.upstream)
    head = git(repo, "log", "-1", "--format=%H", "--", RULES_FILE).strip()
    state = read_state()
    last = state.get("upstream_sha")
    if not last:
        write_state(head, load_at(repo, head)["info"]["version"])
        print(f"First run: baseline set to {head[:7]}. Future changes will be reported.")
        set_output(changed="false")
        return 0
    if last == head:
        print(f"No new commits to {RULES_FILE} since {last[:7]}.")
        # GitHub disables scheduled workflows after 60 days without repo activity.
        # FedRAMP once went 61 days between updates, so touch the state file every 45.
        stamp = dt.datetime.fromisoformat(state.get("updated_at", "1970-01-01T00:00:00+00:00"))
        if dt.datetime.now(dt.timezone.utc) - stamp > dt.timedelta(days=45):
            write_state(head, state.get("version", "?"))
            print("Keepalive: state timestamp refreshed so the schedule stays enabled.")
        set_output(changed="false")
        return 0
    rep = make_report(repo, last, head)
    write_state(head, load_at(repo, head)["info"]["version"])
    if not rep:
        print("Upstream changed, but only in ignored fields (changelog/whitespace).")
        set_output(changed="false")
        return 0
    write_report(rep)
    build_site()
    Path(args.issue_file).write_text(issue_body(rep))
    title = f"FedRAMP rules {rep['to']['version']}: {rep['summary']['headline']}"
    print(title)
    set_output(changed="true", slug=rep["slug"], title=title.replace("\n", " "))
    return 0


def cmd_backfill(args) -> int:
    repo = Path(args.upstream)
    commits = commits_touching(repo, None)
    commits = [c for c in commits if c["date"][:10] >= args.since]
    base = git(repo, "log", "-1", "--format=%H", f"--before={args.since}T00:00:00Z", "--", RULES_FILE).strip()
    if not base:
        base, commits = commits[0]["sha"], commits[1:]
    # One report per day, as the daily Action would have produced.
    last_per_day: OrderedDict[str, str] = OrderedDict()
    for c in commits:
        last_per_day[c["date"][:10]] = c["sha"]
    prev, made = base, 0
    for day, sha in last_per_day.items():
        try:
            rep = make_report(repo, prev, sha)
        except json.JSONDecodeError:
            print(f"{day}: upstream file did not parse at {sha[:7]}, skipping")
            continue
        if rep:
            write_report(rep)
            made += 1
            print(f"{day}: {rep['summary']['headline']}")
        prev = sha
    write_state(prev, load_at(repo, prev)["info"]["version"])
    build_site()
    print(f"{made} reports written; state set to {prev[:7]}")
    return 0


def cmd_diff(args) -> int:
    repo = Path(args.upstream)
    rep = make_report(repo, git(repo, "rev-parse", args.old).strip(), git(repo, "rev-parse", args.new).strip())
    print(render_md(rep) if rep else "No changes.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("--upstream", required=True); c.add_argument("--issue-file", default="issue.md")
    b = sub.add_parser("backfill"); b.add_argument("--upstream", required=True); b.add_argument("--since", default="2026-06-24")
    d = sub.add_parser("diff"); d.add_argument("--upstream", required=True); d.add_argument("old"); d.add_argument("new")
    sub.add_parser("site")
    m = sub.add_parser("send-email", help="email a report (latest by default); add --preview FILE to render without sending")
    m.add_argument("--slug"); m.add_argument("--preview")
    args = p.parse_args()
    if args.cmd == "site":
        build_site()
        return 0
    return {"check": cmd_check, "send-email": cmd_send_email, "backfill": cmd_backfill, "diff": cmd_diff}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
