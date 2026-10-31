# FedRAMP Rules Watch

A GitHub Action that checks [FedRAMP/rules](https://github.com/FedRAMP/rules) every morning, compares the
machine-readable FedRAMP Consolidated Rules (`fedramp-consolidated-rules.json`) with the last version it saw,
and publishes a plain-English report of what changed: rules, definitions, Key Security Indicators (KSIs) and
control parameters/guidance that were **added, removed or changed**, with the rule ID and the before and after
statement.

**Read the archive:** https://pscybergeek.github.io/fedramp-rules-watch/ · **Subscribe:** email newsletter (ask to be added), [Atom feed](https://pscybergeek.github.io/fedramp-rules-watch/feed.xml), or *Watch → Custom → Issues* on this repo.

The archive was backfilled from FedRAMP's real commit history, so it starts with every update since the
2026 Consolidated Rules launched on June 24, 2026.

## What a report tells you

Each report opens with an **At a glance** list a busy reader can stop after, then the detail:

| Section | What's in it |
|---|---|
| At a glance | Counts, plus every obligation change (MUST/SHOULD/MAY), deadline change, effective-date change, and new or removed entry |
| Effective dates and ruleset settings | Changes to each ruleset's `info` block: effective, obtain/maintain and grace dates, current status, applicability |
| Added / Removed | Full statement of each entry, its location and obligation level |
| New IDs | Entries that disappeared and reappeared under a new ID with ≥90% identical text |
| Changed | Plain-English sentences, FedRAMP's own changelog note, and the before and after statement with word-level highlighting |
| Mapping-only updates | Compact table for entries where only NIST control mappings or term links moved |

Every change is graded so the important ones float to the top:

- **substantive**: obligation level or normative keyword changed (e.g. Class B `MUST` → `SHOULD`), a deadline changed, the statement was meaningfully reworded, or an entry moved
- **minor**: small rewording, renames, notes, schema links, a machine-readable deadline added to existing text
- **editorial**: punctuation, capitalization or formatting only
- **mapping**: only cross-references (NIST controls, defined terms, related rules) changed

FedRAMP's own `updated` changelog entries are never diffed as noise; they are quoted as "FedRAMP's changelog"
on the entry they belong to.

## How it works

```
cron (daily) ─► clone FedRAMP/rules ─► compare last-processed commit with HEAD
                                         │ no change → exit
                                         ▼
               docs/reports/<date>.{md,html,json} + docs/index.html + docs/feed.xml
                                         ▼
               commit to this repo (GitHub Pages serves docs/) ─► open an issue ─► email the newsletter
```

- `scripts/fedwatch.py` does everything; Python standard library only, no dependencies.
- Every record with an ID such as `VDR-CSO-DET`, `FRD-ACV`, `KSI-CNA-EIS` or `AC-06-01` is indexed wherever it
  sits in the file, so new rulesets and new scopes (`all`, `20x`, `rev5`) are picked up without code changes.
- `state/last.json` stores the last upstream commit processed. Multiple upstream commits in a day roll up
  into one report, with each commit linked.
- If FedRAMP goes quiet for 45 days the job refreshes that state file so GitHub doesn't disable the schedule
  (GitHub turns off scheduled workflows after 60 days with no repository activity; FedRAMP once went 61 days
  between updates).
- The JSON beside each report is the full structured diff, for anyone who wants to build on it.

## Email newsletter

When a change is found, the Action emails the report: an At a glance list, the top 12 changes with the
changed words highlighted, and a link to the full report. Nothing is sent on days with no change.

It sends through Gmail by default. Add three repository secrets under **Settings → Secrets and variables →
Actions**:

| Secret | Value |
|---|---|
| `MAILBOX` | The Gmail address that sends the newsletter |
| `SMTP` | A Gmail [app password](https://myaccount.google.com/apppasswords) for that address (requires 2-Step Verification), not your normal password |
| `MAILTO` | Recipients, comma-separated. With more than one, everyone is Bcc'd so club members don't see each other's addresses |

To use another provider, set repository *variables* `SMTP_HOST` and `SMTP_PORT` (SSL). To confirm the setup,
run the workflow manually with **Email the latest report now** checked.

## Set it up in your own account

1. Create a public repo named `fedramp-rules-watch` and push these files to `main`.
2. **Settings → Actions → General → Workflow permissions:** Read and write permissions.
3. **Settings → Pages:** Deploy from a branch, `main`, folder `/docs`.
4. **Actions → FedRAMP rules watch → Run workflow** once to confirm it runs. With the included state it
   reports "No new commits" until FedRAMP pushes an update.

To start fresh instead of keeping the included archive, delete `docs/` and `state/`, then rebuild locally:

```bash
git clone https://github.com/FedRAMP/rules.git /tmp/fedramp-rules && python3 scripts/fedwatch.py backfill --upstream /tmp/fedramp-rules
```

Other commands: `check` (what the Action runs), `send-email [--slug DATE] [--preview FILE]` (send or preview a newsletter), `diff <old-ref> <new-ref>` (print Markdown for any two
upstream commits), `site` (rebuild the index and feed). Tests: `python -m unittest discover -s tests`.

## Limits

- Unofficial. Summaries are generated mechanically from the JSON; FedRAMP's published rules are authoritative.
- It reports what the data file says, not what FedRAMP means. A "substantive" grade is a signal to read the
  before and after text, not a legal interpretation.
- Changes to prose outside the JSON (fedramp.gov pages, guidance PDFs) are out of scope.
