# The did:webvh Threat Model

A threat model for the [`did:webvh` DID Method v1.0](https://identity.foundation/didwebvh/v1.0/),
following the [W3C Threat Modeling Guide](https://w3c.github.io/threat-modeling-guide/)
and building on the [DID Threat Model](https://w3c.github.io/did-threat-model/).

The model is built in layers, each with its own data flow diagram and threats:

1. the DID Threat Model (referenced, not repeated);
2. `did:web`;
3. `did:webvh` without witnesses, watchers or DNS-linking;
4. `did:webvh` with witnesses, watchers and DNS-linking.

Each later layer adds only its new threats and records whether each earlier
threat still applies, is changed, is mitigated or is superseded.

## Repository Layout

| Path | Contents |
|---|---|
| `spec/` | The Markdown source, one file per section, in the order listed in `specs.json`. |
| `spec/assets/` | The data flow diagrams (hand-written SVG), referenced from the page as `../spec/assets/`. |
| `index.html` | Redirect from the site root to `next/`. |
| `specs.json` | Spec-Up configuration. |
| `src/`, `scripts/`, `test/` | The Spec-Up tool itself, from the template this repo was created from. |

## Building

Requires Node.js 18 or later.

```bash
npm ci
npm run build   # renders next/index.html once
npm run edit    # rebuilds on every change
npm run dev     # local dev server at http://127.0.0.1:5173
```

`npm run build` renders the current draft to `next/index.html` (not committed).
The root `index.html` is a hand-written redirect to `next/`, so the site can later
hold frozen versions (for example `v1.0/`) alongside the draft. The
`spec-up-render` GitHub Action builds the site on every push to `main` and
publishes the redirect, `next/` and `spec/assets/` to GitHub Pages.

## Contributing

Issues and pull requests are welcome. To propose a new threat, open an issue
giving its name, the layer it belongs to, a description, the affected elements
(by ID, from that layer's dictionary), its STRIDE or LINDDUN class, and any
responses with links to the specification sections that provide them.
