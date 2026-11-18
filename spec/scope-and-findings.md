## Scope, Open Items and Findings

### Out of Scope

- **Governance of witnesses and watchers.** What it means for a witness to
  approve a DID version, who may be a witness or watcher, and how deletion
  requests are judged are outside the `did:webvh` specification. They appear in
  this model only as the operator entities `E6` and `E8`. Threats that depend on
  them are recorded as transferred to governance.
- **DNS, registrars and certificate authorities** (`C6`) are a black-box
  dependency, following the W3C minimalist Web threat model. Only their effect
  on `did:web` and `did:webvh` is modeled.
- **Deployment mechanisms.** How the controller deploys files (`F2`) and how
  keys are protected in `D2` are implementation and deployment choices.
- **Use of the DID.** How DID URL path resources (`D13`), such as files reached
  through DID URL paths and the `whois.vp` presentation, are protected and
  relied on is a matter of how the DID is used, not of the DID itself or its
  resolution. `D13` and `F10` appear in the model to show where they sit, but
  threats to their content are not modeled.
- **Threats common to all DID methods** belong in the
  [DID Threat Model](#ref-did-threat-model) ([Layer 1](#layer-1-the-did-threat-model)).
- **Attackers** are not drawn in the diagrams.

### Assumptions

- The model describes `did:webvh` v1.0. Behavior that exists only in the
  Editor's Draft is not modeled; see [Open Items](#open-items).
- DNS-linking is modeled as proposed in the `did:webvh` Work Item, based on the
  [High Assurance DIDs with DNS](#ref-ha-dids-dns) draft, which has expired as an
  individual Internet-Draft. The model assumes a TXT record at `_did.<domain>`
  in place of the draft's URI record, which has proved impractical.

### Open Items

Points where the Editor's Draft differs from v1.0 in a way that affects a threat
or a response:

1. **Internationalized domain names** ([WEB-TH10](#web-th10)). The Editor's
   Draft requires IDNs to appear in the DID as A-labels, forbids resolvers from
   applying any Unicode or IDNA processing, and says software displaying a DID
   with U-labels **SHOULD** apply confusable and mixed-script detection. This
   strengthens the response to look-alike domains, and would change WEB-TH10's
   disposition in Layer 3.

### Findings for the Specification

Writing this model turned up points where the v1.0 text is unclear or silent.
They are candidates for issues against the specification.

1. **Witnesses and truncation** ([WVH-TH1](#wvh-th1)). Threats and Attacks lists
   witness verification as a mitigation for truncation. It detects truncation
   only when the controller prunes `did-witness.json` and the attacker serves the
   current witness file with a stale log. Witnesses hold the latest log, but no
   operation lets a resolver ask them for it.
2. **Threshold and fork resistance** ([WVX-TH2](#wvx-th2)). Witnesses prevent
   forks only when `threshold > n/2`. The specification allows any threshold from
   1 to `n` and does not discuss the trade-off with availability
   ([WVX-TH3](#wvx-th3)).
3. **Divergence handling** ([WVH-TH2](#wvh-th2), [WVX-TH6](#wvx-th6)). The
   specification does not say which result a resolver uses when sources differ,
   what it returns when it detects a fork, or how a watcher reports divergence.
   The Watcher HTTP API has no operation for it.
4. **Backdated entries** ([WVH-TH5](#wvh-th5)). Witnesses are not asked to
   reject entries whose `versionTime` is well before the time they sign, and
   witness proofs carry no required timestamp.
5. **Witness key compromise** ([WVX-TH4](#wvx-th4)). There is no way to signal
   that a witness's `did:key` is compromised, and replacing a witness needs the
   approval of the current witnesses.
6. **Watcher notification endpoints** ([WVX-TH7](#wvx-th7)). The specification
   gives no guidance on abuse of the unauthenticated notification endpoints, and
   does not say that the resolver transport safeguards apply to watchers.
7. **Watcher deletion requests** ([WVX-TH8](#wvx-th8)). Delete requests carry a
   Data Integrity proof "from the requester", but the specification does not say
   whose proof is sufficient.
8. **Deactivation by deletion** ([WVH-TH10](#wvh-th10)). Deleting the log is a
   permitted way to deactivate, but cannot be told apart from withholding.
9. **Witness file name.** Threats and Attacks and the Watcher HTTP API call the
   witness file `witness.json`. Everywhere else it is `did-witness.json`.
10. **DNS-linking** ([WVX-TH9](#wvx-th9), [WVX-TH10](#wvx-th10)). If adopted,
    the specification should say what a `_did` record means for `did:webvh`, how
    it interacts with portability and path-based DIDs, how it is kept current,
    and that its absence is not a verification failure.
11. **Pre-rotation** ([WVH-TH13](#wvh-th13)). Pre-rotation is optional, and DID
    resolution metadata does not report whether it is active, so a verifier must
    inspect the log to know. Consider requiring it in a future version, or at
    least reporting it in resolution metadata.
