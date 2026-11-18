# CLAUDE.md — did:webvh Threat Model

Working notes for Claude Code sessions on this repo. Keep this file current: update
**Status** and **Next steps** at the end of each session.

## What this repo is

A Spec-Up document: the threat model for did:webvh v1.0, published to GitHub Pages
from `main` by `.github/workflows/render-specs.yml`.

- Source: `spec/*.md`, assembled in the order of `markdown_paths` in `specs.json`.
- Diagrams: `spec/assets/dfd-layer{2,3,4}-*.svg`, hand-written SVG (no build step).
- The rest (`src/`, `scripts/`, `test/`, `vite.config.mjs`, `references.js`) is the
  Spec-Up tool, vendored by the template. Don't edit it for content changes.
- `npm run build` writes `next/index.html` and `next/assets/` (all of `next/` is gitignored).
  The root `index.html` is a tracked, hand-written redirect to `next/` (user request,
  2026-11-17) so frozen versions (e.g. `v1.0/` from a `spec-v1.0/` folder) can sit
  alongside later. Diagrams are referenced as `../spec/assets/...` from the page.
  The workflow publishes `index.html`, `next/` and `spec/assets/`.
- `npm test` runs Spec-Up's own tests. 3 CSS tests fail on the untouched template
  too (heading counters, copy-button position, issues drawer); not ours.

Do not commit or push; the user does that (global instruction).

## Structure and decisions

The model is layered (user's design, 2026-11-17):

| File | Layer | Content |
|---|---|---|
| `header.md` | – | Title, status, abstract |
| `introduction.md` | – | Purpose, method, ID conventions, dispositions, entry format, legend |
| `layer1-did-threat-model.md` | 1 | Short: what we take from the W3C DID Threat Model (no repetition) |
| `layer2-did-web.md` | 2 | did:web DFD, dictionary, stakeholders, `WEB-TH1..14` |
| `layer3-didwebvh.md` | 3 | did:webvh with no witnesses/watchers/DNS-linking; dispositions of all WEB threats; `WVH-TH1..13` |
| `layer4-didwebvh-extended.md` | 4 | + witnesses, watchers, DNS-linking; dispositions of affected WEB/WVH threats; `WVX-TH1..10` |
| `scope-and-findings.md` | – | Out of scope, assumptions, open items (Editor's Draft diffs), findings for the spec |
| `references.md` | – | Manual reference table with `#ref-*` anchors, plus `[[spec]]` list |

Conventions (also stated in `introduction.md`):

- Element IDs: DID Threat Model IDs kept (`E1–E6, C1–C5, P1–P5, D1–D10, F1–F7, T1–T3`).
  New elements are numbered in the order each layer introduces them, and keep that
  ID in later layers:
  - L2: `E7` DNS/CA providers, `C6` DNS & Web PKI, `P6` DNS+CA, `D11` did.json, `F8` DNS & TLS, `T4` DNS/PKI boundary.
  - L3: `D12` did.jsonl, `D13` DID URL path resources, `F9` did:web fallback, `F10` dereference.
  - L4: `E8` Witness Operator, `C7` Witness, `P7` Witness Service, `D14` witness store,
    `D15` did-witness.json, `F11` witness exchange, `F12` witness log fetch, `T5` witness boundary;
    watcher reuses `E6/C5/P5/D7†`, `F3a/F3b†`, `F13` watcher read, `T6` watcher boundary;
    DNS-linking `D16` `_did` record, `F14` publish, `F15` lookup.
  - `*` new, `†` changed, teal in diagrams = new/changed in that layer.
- Threat IDs `WEB-TH#`, `WVH-TH#`, `WVX-TH#`; responses `WEB-R#`, `WVH-R#`, `WVX-R#`.
  Reused responses keep first ID, marked *(reused)*. Strategies: Eliminate/Reduce/Transfer/Accept.
- Dispositions: Applies / Changed / Mitigated / Superseded. Threats are never repeated
  in a later layer; later layers link back.
- Anchors: each threat is preceded by `<a id="web-th1"></a>` etc.; responses carry
  `<span id="wvh-r3"></span>`. Use these for cross-links, not heading slugs.
- Multiple-compromise framing (user request, 2026-11-17): where a response forces an
  attacker to succeed at more than one independent compromise, say so in a
  **Compromises required** paragraph, and say when the compromises are not
  independent (shared operator/account, keys stored with deploy credentials, DNS takeover).
  Keep the summary table "What an Attacker Must Compromise" at the end of Layer 4 in
  sync when threats or responses change.
- ASSUMPTION (user decision, 2026-11-17): the model assumes pre-rotation is used from
  the first entry and never turned off (recommended; likely required in future
  versions). Stated in a note at the top of Layer 3. Write all threats for the
  pre-rotation case; the no-pre-rotation case lives only in WVH-TH13.
- Pre-rotation facts (v1.0): each entry is signed by a key from its *own*
  `updateKeys`, each of which must hash to the previous entry's `nextKeyHashes`.
  So: a stolen committed next key = takeover (with host); a stolen *used* key that
  wasn't destroyed can sign an alternative to the entry it signed = fork from that
  point (can be made longer than the real log); keys that are neither = nothing.
  Crypto break: tip can't be extended (next keys are hashes) but forks from any
  earlier entry are possible.
- SCOPE (user decision, 2026-11-18): how the DID is *used* is out of scope, including
  the integrity of DID URL path resources (`D13`). The former WVH-TH8 (tampering with
  DID URL path resources) was removed and WVH-TH9..14 renumbered to TH8..13.
- Spec-Up drops `::: note Title` titles (shows only "NOTE"); put a bold lead-in in
  the body instead.
- No backticks in headings (they show raw in the Spec-Up TOC).
- Spec version modeled: did:webvh **v1.0** (`https://identity.foundation/didwebvh/v1.0/#...`).
  Editor's Draft differences go in `scope-and-findings.md` → Open Items.
- "DNS-linking" = the proposed `_did` record from IETF
  draft-carter-high-assurance-dids-with-dns (expired, -08). Not in v1.0; flagged as proposed.
  Modeled as a TXT record, not the draft's URI record (user decision, 2026-11-18:
  URI records proved impractical).
- Old IDs from the earlier attempt (`/d2/repos/didwebvh`, branch `threat-model`,
  untracked `spec-threat-model-v1.0/` and `BRIEF.md`) were renumbered; its TH1–TH3
  content became WVH-TH1/TH2 and WVX dispositions; its findings carried over.

## Checks to run after edits

```bash
npm run build
python3 -I - <<'EOF'
import re
h=open('next/index.html').read(); ids=set(re.findall(r'\sid="([^"]+)"',h))
print([x for x in set(re.findall(r'href="#([^"]+)"',h)) if x not in ids and not x.startswith('term:')])
v=open('/d2/repos/didwebvh/v1.0/index.html').read(); vids=set(re.findall(r'id="([^"]+)"',v))
print([e for e in set(re.findall(r'identity\.foundation/didwebvh/v1\.0/#([^"]+)"',h)) if e not in vids])
EOF
```

Both lists should be empty. To view a diagram, serve `spec/assets` over HTTP and screenshot
with headless Chromium (snap Chromium can't read `/tmp`).

## Status (2026-11-17)

- [x] Template examples removed; `specs.json` points at `spec/`; workflow publishes from `main`.
- [x] Three DFDs drawn and checked visually.
- [x] Full first draft of all layers: 14 + 13 + 10 threats, dispositions, findings.
- [x] All internal links and v1.0 anchors verified.
- [ ] did:web anchors (`w3c-ccg.github.io/did-method-web/#...`) are ReSpec-generated and
      not yet verified in a browser.
- [ ] User review of the threat lists (curation, ordering, kinds).

## Next steps / open questions for the user

1. Review threat selection per layer; cut or merge (Guide prefers curated over exhaustive).
2. DECIDED (2026-11-17): Layer 4 stays a single layer with all three features together.
   No per-feature sub-layers (too complicated). Each threat/disposition keeps its
   "Feature" tag so the features remain independently usable.
3. DNS-linking: the user's intent was the High Assurance DIDs with DNS draft (expired).
   The Work Item will likely drop that reference and define the did:webvh practice
   itself. When it does, rewrite the Layer 4 warning note, WVX-R9 and WVX-TH9/TH10 to
   describe the did:webvh-defined practice, and remove `#ref-ha-dids-dns` if no longer cited.
   When DNS-linking lands in the did:webvh spec (vNext), review the whole Layer 4 DNS-linking
   section (D16, F14/F15, WVX-TH9/TH10, WVX-R9, warning note, Assumptions) against it. The user's
   design notes (TXT record format, size limits, options for path-based DIDs, leaning toward
   domains/subdomains only) are in the Claude Doc "did:webvh DNS-Linking with TXT Records — Design
   Notes": https://claude.ai/artifact/FKAY9zacBTMzNmiJjCLRXg
4. Stakeholders: add ecosystem governance as a formal entity (`E9`)? Currently prose only in L4.
5. Track the Editor's Draft (A-label IDNs etc.) or stay on v1.0?
6. Later: propose a short "Threat Model" pointer in the did:webvh spec's Security
   Considerations (ask before editing the spec repo).
7. Cosmetic: long IDs (`WEB-TH10`) wrap at the hyphen in index tables.
