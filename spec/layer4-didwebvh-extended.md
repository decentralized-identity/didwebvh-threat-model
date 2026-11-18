## Layer 4: did:webvh with Witnesses, Watchers and DNS-Linking

This layer adds the three optional features that address what
[Layer 3](#layer-3-didwebvh) leaves open:

- **Witnesses** approve each new version of the DID before it is published.
  A threshold of witness proofs is then required for every entry.
- **Watchers** keep copies of DID Logs, indexed by SCID, independently of the
  host, and can serve them after the host stops.
- **DNS-linking** publishes a `_did` DNS record at the DID's domain naming the
  DID, so a verifier can check that the domain holder asserts it.

Each feature is optional and independent. Each threat and disposition below
names the feature it depends on.

::: warning
**DNS-linking is a proposal.** It is not part of `did:webvh` v1.0. It is modeled here as proposed in
the `did:webvh` Work Item, following the IETF
[High Assurance DIDs with DNS](#ref-ha-dids-dns) draft: a record at
`_did.<domain>` naming the DID, validated with DNSSEC. The draft uses a URI
record. URI records have proved impractical, so this model assumes a TXT record
instead. Its threats and responses
will change if the practice is adopted in a different form.
:::

### System Model

[![Data flow diagram for did:webvh with witnesses, watchers and DNS-linking. The DID controller collects witness proofs for each candidate log entry, publishes the DID Log, witness proofs, an optional parallel did:web document and DID URL path resources to a web server, notifies watchers, and publishes a _did DNS record that links the domain to the DID. Watchers cache logs by SCID. Resolvers fetch the log and witness proofs over HTTPS, may cross-check a watcher and the _did record, verify everything, and return the DID document to a DID-enabled application. Six trust boundaries, T1 to T6, are marked.](../spec/assets/dfd-layer4-didwebvh-extended.svg)](../spec/assets/dfd-layer4-didwebvh-extended.svg)

**Figure 3** (select to enlarge). `did:webvh` with witnesses, watchers and DNS-linking. Witnesses
(`C7`) and watchers (`C5`) are the method's checks against rewritten, forked or
withheld history. The `_did` record (`D16`) lets the domain holder vouch for the
DID.

#### Description

**Witnesses.** When the DID's parameters list witnesses, the Controller App
(`P1`) sends each candidate entry to each Witness Service (`P7`) and collects
their proofs (`F11`). Each witness:

- holds its own copy of the published log (`D14`), fetched from the host
  (`F12`);
- confirms the candidate verifies as the next entry to that log, using every
  Read step;
- applies its governance to decide whether to approve;
- signs the entry's `versionId` with its `did:key`, and must not sign two
  children of the same parent.

`P1` publishes the proofs in `did-witness.json` (`D15`) before it publishes the
entry. A resolver fetches both files (`F7`) and requires a threshold of proofs
from distinct witnesses for each witnessed entry. A proof for an entry also
approves every earlier entry. Each witness is operated by a Witness Operator
(`E8`), identified only by its `did:key`.

**Watchers.** The controller can list watchers in the DID's parameters, and
notifies them of updates (`F3a`). Any party can run a watcher, listed or not. A
watcher (`P5`) retrieves the log, witness file and resources from the host
(`F3b`) into a cache indexed by SCID (`D7`), and keeps the last state it has seen
even after the host stops serving it. A resolver can read from a watcher (`F13`)
instead of, or to cross-check, the host. Watchers are operated by Watcher
Operators (`E6`) under their own governance.

**DNS-linking.** The domain holder publishes (`F14`) a TXT record at
`_did.<domain>` naming the `did:webvh` DID (`D16`), signed with DNSSEC. A
resolver or verifier looks it up (`F15`) and checks that it names the DID being
resolved. The domain holder may not be the DID controller, for example when a
DID is hosted on a platform.

Six trust boundaries apply: `T1` to `T4` as in [Layer 3](#layer-3-didwebvh), plus
`T5` between the controller and each witness, and `T6` between the watcher and
both the controller and resolver.

#### Dictionary

Elements as in [Layer 3](#layer-3-didwebvh), plus:

In the ID and Status columns, **\*** marks an element new in this layer and **†** an element whose meaning changes in this layer (see [Element IDs](#element-ids)).

| ID | Name | Status | Description |
|---|---|---|---|
| `E6†` | Watcher Operator | † | Replaces the Resolver VDR Service Provider. Any party may run a watcher. Its governance, including how it handles deletion requests, is out of scope of the specification. |
| `E8*` | Witness Operator | \* | Decides whether to approve each DID version under ecosystem governance. Identified only by a `did:key`. |
| `C5†` | Watcher | † | Replaces the Resolver VDR Device. An HTTP service caching DID state by SCID. |
| `C7*` | Witness | \* | One per entry in the `witness` parameter. |
| `P5†` | Watcher Service | † | `GET /log`, `/witness` and `/resource` by SCID; accepts update notifications and signed delete requests. |
| `P7*` | Witness Service | \* | Verifies a candidate entry against its own copy of the log, applies governance, and signs the `versionId`. |
| `D7†` | Watcher cache | † | Logs, witness files and resources, indexed by SCID. |
| `D14*` | Witness store | \* | The witness's copy of the published log, and its `did:key` private key. |
| `D15*` | Witness proofs (`did-witness.json`) | \* | Data Integrity proofs over `versionId` values. Published before the entry they approve. |
| `D16*` | `_did` DNS record | \* | TXT record at `_did.<domain>` naming the DID, signed with DNSSEC. Proposed. |
| `F3a†` | Notify watcher | † | `POST /log?did=` and `POST /resource`, plus signed delete requests. |
| `F3b†` | Watcher retrieval | † | The watcher fetches or polls the log, witness file and resources from the host. |
| `F7†` | Read DID Log | † | Now also fetches `did-witness.json`. |
| `F11*` | Witness exchange | \* | Candidate entry to each witness; proof back. Transport is not specified. |
| `F12*` | Witness log fetch | \* | The witness obtains its copy of the published log. |
| `F13*` | Watcher read | \* | `GET /log?scid=` and `/witness?scid=`. |
| `F14*` | Publish `_did` record | \* | The domain holder publishes the record through its DNS operator. |
| `F15*` | `_did` lookup | \* | DNSSEC-validated lookup of the record by the resolver or verifier. |
| `T5*` | Witness boundary | \* | Crossed by `F11` and `F12`. Approval is each witness's governance decision. |
| `T6*` | Watcher boundary | \* | Crossed by `F3a`, `F3b` and `F13`. |

### Stakeholders

Changes from [Layer 3](#layer-3-didwebvh):

- **DID Controller (`E1`).** Gains protection against rewritten or forked
  history, and persistence beyond its host. Depends on witnesses to publish any
  update, including an emergency key rotation. Loses control over whether its
  history can be erased.
- **DID URL User (`E2`).** Can detect forks and stale logs that Layer 3 could
  not. Usually does not know which witnesses or watchers are involved, or what
  governs them.
- **Watcher Operator (`E6`).** Provides persistence and divergence detection.
  Bears legal pressure to delete, and load and abuse through unauthenticated
  notification endpoints.
- **Witness Operator (`E8`).** Lends its approval to updates. Bears expectations
  of availability, responsibility for what it approves, and custody of a key it
  cannot rotate.
- **Domain holder (part of `E7`).** With DNS-linking, vouches for the DIDs at
  its domain, and must keep the record current.
- **Ecosystem governance authority** (new). Chooses or approves witnesses and
  watchers, sets thresholds and resource limits, and judges deletion requests.
  Most of what this layer transfers, it transfers here.

<a id="wvx-dispositions"></a>

### Dispositions of Earlier Threats

Threats not listed here have the same disposition as in
[Layer 3](#layer-3-didwebvh).

| Threat | Feature | Disposition | Notes |
|---|---|---|---|
| [WVH-TH1](#wvh-th1) Truncated or withheld DID Log | Watchers, witnesses | **Changed** | Reduced by reading from watchers ([WVX-R6](#wvx-r6)). Witness proofs catch truncation only in narrow cases ([WVX-R4](#wvx-r4)): when the controller prunes the witness file to the latest proofs and the attacker serves the current witness file with an old log. They do not catch an older snapshot of both files. Witnesses hold the latest log but no API lets resolvers ask them for it. With watchers, an undetected stale view needs the host *and* every watcher the verifier's resolver consults. That is a real second compromise only if the watchers are run independently of the host. Watchers fetch from the host, so they protect against truncation *after* they have seen the newer entries, not against a host that withholds an entry from the moment it is published. Still undetected: a stale log served consistently by the host, to a resolver with no prior state that does not consult a watcher. |
| [WVH-TH2](#wvh-th2) Forked DID Log and split view | Witnesses, watchers | **Changed** | Reduced by witnesses refusing a second child ([WVX-R2](#wvx-r2)), consolidation failing on conflict ([WVX-R3](#wvx-r3)) and watchers detecting divergence ([WVX-R6](#wvx-r6)). An undetected fork now needs, in addition to an update key and the host: a threshold of witness approvals on *each* branch, and every consulted watcher to see only one branch. Witnesses prevent forks only when the threshold is more than half the witnesses ([WVX-TH2](#wvx-th2)). |
| [WVH-TH3](#wvh-th3) Update key compromise | Witnesses | **Changed** | Adds a third requirement. Besides a committed next key and a way to publish at the DID's location, the attacker needs a threshold of witnesses to approve the entry. To rewrite history they need to compromise the witnesses as well as the keys and the host ([DID Witnesses](https://identity.foundation/didwebvh/v1.0/#did-witnesses)). The requirements are independent only if the witnesses are run separately from the controller, from the host and from each other, and would refuse an attacker's update: see [WVX-TH1](#wvx-th1). |
| [WVH-TH5](#wvh-th5) Controller-asserted version time | Witnesses, watchers | **Changed** | A witness verifies that `versionTime` is not in the future when it signs, which bounds forward-dating. The specification does not require witnesses to reject backdated entries, and does not require a timestamp in the witness proof. A watcher's first-seen time would be evidence, but the Watcher API does not expose it. |
| [WVH-TH10](#wvh-th10) Ambiguous deactivation | Watchers | **Changed** | Watchers **SHOULD** keep the last valid state of a deleted DID indefinitely ([Deactivate (Revoke)](https://identity.foundation/didwebvh/v1.0/#deactivate-revoke)), so a verifier can still resolve it and see whether it was deactivated. |
| [WVH-TH11](#wvh-th11) Cryptographic break, including quantum | Witnesses, watchers | **Changed** | Watcher copies and witness proofs are external evidence of which history came first. Witness proofs use the same kinds of algorithm and `did:key` keys, so a break may affect them too. |
| [WVH-TH12](#wvh-th12) Permanent public history | Watchers | **Changed** | Worse: watchers are **RECOMMENDED** to keep state indefinitely, so erasure depends on every watcher. See [WVX-TH8](#wvx-th8). |
| [WVH-TH8](#wvh-th8) Misleading prior-domain association | DNS-linking | **Changed** | Reduced: the current domain's `_did` record names the DID, and a domain the DID only claimed to use will not. |
| [WVH-TH9](#wvh-th9) Verification mistaken for trust | DNS-linking | **Changed** | A `_did` record shows that the domain holder asserts the DID. It does not show that the domain holder is trustworthy. See [WVX-TH10](#wvx-th10). Passing off a *new* DID as the domain holder's now needs control of both the web host and the domain's DNS, not the host alone. The two are independent only when hosting and DNS are run by different providers or accounts. A takeover of the domain's DNS gives both ([WVX-TH9](#wvx-th9)). |
| [WEB-TH2](#web-th2) Domain takeover | DNS-linking | **Changed** | Whoever controls the domain also controls its `_did` record. See [WVX-TH9](#wvx-th9). |
| [WEB-TH8](#web-th8) Host unavailability, censorship or exclusion | Watchers | **Changed** | Reduced: resolvers can read the log from a watcher by SCID ([WVX-R6](#wvx-r6), [WVX-R7](#wvx-r7)). |
| [WEB-TH9](#web-th9) Path-based DID misattributed to the domain operator | DNS-linking | **Changed** | Reduced: only DIDs the domain holder names in a `_did` record are vouched for by the domain. |
| [WEB-TH12](#web-th12) SSRF through DID strings | Watchers | **Changed** | Watchers also fetch logs for DIDs supplied by others. See [WVX-TH7](#wvx-th7). |
| [WEB-TH13](#web-th13) Resource exhaustion during resolution | Witnesses, watchers | **Changed** | Witness proofs add verification work. Watchers face the same exposure as resolvers. |
| [WEB-TH14](#web-th14) Resolution tracking | Watchers | **Changed** | A watcher can act as a privacy intermediary, so the host does not see who resolves ([No Phone Home Mitigations](https://identity.foundation/didwebvh/v1.0/#no-phone-home-mitigations)). The watcher itself then sees which SCIDs are queried, and when. |

### New Threats

| ID | Threat | Feature | Kind | Elements |
|---|---|---|---|---|
| [WVX-TH1](#wvx-th1) | Witness collusion or compromise | Witnesses | target | `C7`, `P7`, `E8`, `T5` |
| [WVX-TH2](#wvx-th2) | Fork-tolerant witness configuration | Witnesses | deployment | `D12`, `D15`, `P7`, `F12` |
| [WVX-TH3](#wvx-th3) | Witness unavailability blocks updates | Witnesses | deployment | `P7`, `F11`, `E8` |
| [WVX-TH4](#wvx-th4) | Witness key compromise | Witnesses | target | `D14`, `P7`, `D15` |
| [WVX-TH5](#wvx-th5) | Witness proof misattribution | Witnesses | implementation | `D15`, `P4` |
| [WVX-TH6](#wvx-th6) | Stale, malicious or censoring watcher | Watchers | target | `P5`, `D7`, `F13`, `T6` |
| [WVX-TH7](#wvx-th7) | Abuse of watcher notification endpoints | Watchers | implementation | `F3a`, `P5`, `C5` |
| [WVX-TH8](#wvx-th8) | Watcher retention and deletion conflicts | Watchers | privacy | `D7`, `F3a`, `E6` |
| [WVX-TH9](#wvx-th9) | Spoofed or stale `_did` record | DNS-linking | dependency | `D16`, `F14`, `F15`, `T4` |
| [WVX-TH10](#wvx-th10) | DNS-linking misread or required | DNS-linking | socio-technical | `D16`, `E2`, `P3` |

<a id="wvx-th1"></a>

#### WVX-TH1. Witness Collusion or Compromise

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Spoofing ·
**Elements:** `C7`, `P7`, `E8`, `T5`

Witnesses guard against an attacker holding the controller's keys, or a controller
rewriting history, only if they would refuse to approve such an update. A
threshold of witnesses that collude with an attacker or a malicious controller,
are compromised, or approve whatever they are sent, provides no protection.
Several witness keys run by one operator count as several witnesses.

**Responses**

- <span id="wvx-r1"></span>**WVX-R1. Witness threshold** (Reduce). A threshold
  of distinct witnesses must approve each entry. →
  [Witness Threshold Algorithm](https://identity.foundation/didwebvh/v1.0/#witness-threshold-algorithm),
  [Witness Lists](https://identity.foundation/didwebvh/v1.0/#witness-lists)
- **Witness governance** (Transfer, to ecosystem governance). What "approve"
  means, who may be a witness and how witnesses are identified are outside the
  specification. A trust registry is suggested for identifying them. →
  [Witnessing a DID Version Update](https://identity.foundation/didwebvh/v1.0/#witnessing-a-did-version-update),
  [Witness DIDs and Reputation](https://identity.foundation/didwebvh/v1.0/#witness-dids-and-reputation)

**Remaining threat:** Witness protection is only as strong as witness
governance, which the specification does not define.

**Responsible party:** ecosystem governance; controllers choosing witnesses.

<a id="wvx-th2"></a>

#### WVX-TH2. Fork-Tolerant Witness Configuration

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Tampering,
Repudiation · **Elements:** `D12`, `D15`, `P7`, `F12`

Each witness refuses to sign two children of the same parent. But with `n`
witnesses and a threshold of `t`, if `t ≤ n/2`, a controller can show each
branch of a fork to a different group of `t` witnesses. Both branches are fully
witnessed and no witness has broken the rule. Similarly, a host can serve
different logs to different witnesses when they fetch it (`F12`).

**Responses**

- <span id="wvx-r2"></span>**WVX-R2. Witnesses refuse a second child**
  (Reduce). Each witness **MUST** hold its own copy of the published log,
  **MUST** confirm the candidate is the next entry to it, and **MUST NOT** sign
  more than one child of the same parent. →
  [Witnessing a DID Version Update](https://identity.foundation/didwebvh/v1.0/#witnessing-a-did-version-update),
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)
- <span id="wvx-r3"></span>**WVX-R3. Consolidation fails on conflict** (Reduce,
  for accidental forks). Consolidating the witness file **MUST** fail on
  conflicting branches. →
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)

**Remaining threat:** Fork resistance needs `t > n/2`, so that any two branches
share at least `2t − n` witnesses. The specification allows any threshold from 1
to `n` and does not discuss this ([finding](#findings-for-the-specification)).

**Responsible party:** controllers and ecosystem governance, for witness
configuration.

<a id="wvx-th3"></a>

#### WVX-TH3. Witness Unavailability Blocks Updates

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Denial of Service ·
**Elements:** `P7`, `F11`, `E8`

No entry can be published without a threshold of witness proofs. That includes
an entry that changes the witnesses: a new witness list takes effect only after
the entry introducing it has been approved by the current witnesses. If more
than `n − t` witnesses are unavailable, refuse, or go out of business, the DID
is frozen. It cannot rotate keys after a compromise, change witnesses, or be
deactivated. An attacker racing the controller after a key compromise can try to
make witnesses unavailable to the controller.

**Responses**

- **WVX-R1. Witness threshold** *(reused)* (Reduce). A threshold below `n`
  tolerates some faulty witnesses, which the specification gives as the reason
  for having a threshold. →
  [Witness Threshold Algorithm](https://identity.foundation/didwebvh/v1.0/#witness-threshold-algorithm)

**Remaining threat:** Accepted. Choosing `t` trades fork resistance
([WVX-TH2](#wvx-th2)) against availability.

**Responsible party:** controllers; ecosystem governance; witness operators.

<a id="wvx-th4"></a>

#### WVX-TH4. Witness Key Compromise

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D14`, `P7`, `D15`

A witness is identified by a `did:key`, which cannot be rotated. If its private
key is stolen, the attacker can produce that witness's approval for any entry of
any DID that lists it, until every such DID has replaced the witness. Replacing
it requires an entry approved by the current witnesses.

**Responses**

- **Replace the witness** (Reduce). Controllers can publish a new `witness`
  parameter, which takes effect after that entry is published. →
  [Witness Lists](https://identity.foundation/didwebvh/v1.0/#witness-lists)
- **WVH-R9. Secure key storage** *(reused)* (Transfer, to witness operators).
  Witness private keys **MUST** be kept in secure storage. →
  [Cryptographic Protection](https://identity.foundation/didwebvh/v1.0/#cryptographic-protection)

**Remaining threat:** There is no way to announce that a witness key is
compromised; each controller must learn of it and act.

**Responsible party:** witness operators; ecosystem governance.

<a id="wvx-th5"></a>

#### WVX-TH5. Witness Proof Misattribution

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D15`, `P4`

A resolver that miscounts witness proofs accepts entries that were not properly
witnessed. Errors include:

- counting raw proofs rather than distinct witnesses;
- accepting a `did:key` reference whose fragment names a different key than its
  body;
- counting proofs for entries that are not in the log being verified, such as
  proofs for unpublished or future entries;
- using witness verification in place of entry-hash or signature checks.

**Responses**

- <span id="wvx-r4"></span>**WVX-R4. Verify proofs against the log being
  verified** (Eliminate, when implemented). Resolvers **MUST** discard proofs
  whose `versionId` is not in this log, **MUST** complete all non-witness checks
  first, and require a threshold of proofs for each witnessed entry or a later
  one. →
  [Verifying Witness Proofs During Resolution](https://identity.foundation/didwebvh/v1.0/#verifying-witness-proofs-during-resolution)
- <span id="wvx-r5"></span>**WVX-R5. Distinct, well-formed witness IDs**
  (Eliminate, when implemented). Witness IDs **MUST** be distinct `did:key` DIDs;
  each contributes at most one approval; body and fragment **MUST** be
  byte-equal. →
  [The `witness` Parameter](https://identity.foundation/didwebvh/v1.0/#the-witness-parameter),
  [Witness DIDs and Reputation](https://identity.foundation/didwebvh/v1.0/#witness-dids-and-reputation)

**Remaining threat:** Implementation errors.

**Responsible party:** resolver implementers.

<a id="wvx-th6"></a>

#### WVX-TH6. Stale, Malicious or Censoring Watcher

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Denial of
Service · **Elements:** `P5`, `D7`, `F13`, `T6`

A watcher is just another source of the log. It cannot forge entries, but it can
serve an old log, refuse to serve a DID, or claim to have seen no divergence.
Watchers learn of updates by notification or polling, so even an honest watcher
can lag. A resolver that reads only from a watcher has swapped trust in the host
for trust in the watcher.

**Responses**

- **WVH-R2. Full verification of every entry** *(reused)* (Eliminate, for
  forgery). The log verifies the same way from any source. →
  [Integrity Protection and Update Authentication](https://identity.foundation/didwebvh/v1.0/#integrity-protection-and-update-authentication)
- <span id="wvx-r6"></span>**WVX-R6. Multi-source resolution** (Reduce).
  Resolvers **MAY** read from several watchers and the host, and detect divergence
  in the latest entries. Watchers **SHOULD** detect and report divergence across
  sources. Each watcher consulted adds a source an attacker must also control,
  but only if it is operated independently of the host and of the other
  watchers. A watcher run by the hosting provider adds nothing. →
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks),
  [DID Watchers](https://identity.foundation/didwebvh/v1.0/#did-watchers)

**Remaining threat:** The specification does not say which result a resolver
uses when sources differ, and the Watcher API has no operation for reporting
divergence ([finding](#findings-for-the-specification)).

**Responsible party:** resolver operators; ecosystem governance.

<a id="wvx-th7"></a>

#### WVX-TH7. Abuse of Watcher Notification Endpoints

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Denial of Service,
Elevation of Privilege · **Elements:** `F3a`, `P5`, `C5`

`POST /log?did=` and `POST /resource` are unauthenticated: anyone can tell a
watcher to fetch any DID. An attacker can use them to make a watcher fetch large
or slow logs, track many junk DIDs, or, without transport safeguards, send
requests to internal addresses.

**Responses**

- **WVH-R12. Resolver transport hardening** *(reused)* (Reduce, if applied).
  Stated for resolvers; a watcher fetching a log is acting as one. →
  [Resolver Transport Hardening](https://identity.foundation/didwebvh/v1.0/#resolver-transport-hardening-ssrf-and-network-boundary)
- No watcher-specific response in the specification
  ([finding](#findings-for-the-specification)).

**Remaining threat:** Transferred to watcher operators.

**Responsible party:** watcher implementers and operators.

<a id="wvx-th8"></a>

#### WVX-TH8. Watcher Retention and Deletion Conflicts

**Kind:** privacy · **Taxonomy:** LINDDUN · **Class:** Non-compliance,
Identifiability · **Elements:** `D7`, `F3a`, `E6`

Watchers are recommended to keep a DID's last state indefinitely, which serves
persistence but conflicts with a controller's wish, or legal right, to erase
it. In the other direction, a delete request that a watcher wrongly honors, such
as a forged one or one from a party other than the controller, removes a DID
that verifiers depend on. The delete endpoints take a Data Integrity proof "from
the requester", but the specification does not say whose proof is sufficient.

**Responses**

- <span id="wvx-r7"></span>**WVX-R7. Persistence by watchers** (Reduce, for
  availability). Watchers **SHOULD** keep the last valid state of a deleted DID. →
  [Deactivate (Revoke)](https://identity.foundation/didwebvh/v1.0/#deactivate-revoke),
  [Right to Erasure](https://identity.foundation/didwebvh/v1.0/#right-to-erasure-gdpr-art-17)
- <span id="wvx-r8"></span>**WVX-R8. Signed deletion requests under governance**
  (Transfer, to watcher governance). Requests carry a Data Integrity proof; the
  watcher acts according to its governance. →
  [Watcher HTTP API Operations](https://identity.foundation/didwebvh/v1.0/#watcher-http-api-operations)

**Remaining threat:** Accepted. Erasure across independent watchers cannot be
guaranteed.

**Responsible party:** watcher operators; ecosystem governance.

<a id="wvx-th9"></a>

#### WVX-TH9. Spoofed or Stale _did Record

**Kind:** dependency · **Taxonomy:** STRIDE · **Class:** Spoofing, Tampering ·
**Elements:** `D16`, `F14`, `F15`, `T4`

A `_did` record is only as trustworthy as DNS. Without DNSSEC, an on-path
attacker can spoof it. Whoever controls the domain controls the record, so a
domain takeover ([WEB-TH2](#web-th2)) lets the attacker name their own DID, or
remove the controller's. The record can also become stale: still naming a DID
after it has moved away under portability or been deactivated, or after the
domain has changed hands.

**Compromises required.** The value of DNS-linking is that it puts a second,
separately administered system in the path. An attacker who breaches only the
web host can publish a new DID at the domain ([WVH-TH9](#wvh-th9)), but the
`_did` record still names the real one. To pass off their DID undetected, they
must also change the DNS record. That protection holds only when the two are
independent:

- **Domain takeover collapses it.** Whoever controls the domain's DNS can point
  the domain at their own server *and* rewrite the `_did` record. DNSSEC does not
  help, because the attacker signs as the zone owner.
- **Shared administration collapses it.** When one provider, account or set of
  credentials manages both the DNS zone and the web hosting, one breach yields
  both.

**Responses**

- <span id="wvx-r9"></span>**WVX-R9. DNSSEC validation** (Reduce). The draft
  recommends DNSSEC and says it **SHOULD** be validated on each lookup. The
  `did:webvh` specification calls DNSSEC "essential" in general. →
  [High Assurance DIDs with DNS](#ref-ha-dids-dns) §4, §6;
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)
- **SCID verification** *(see [WVH-R1](#wvh-r1))* (Reduce). A spoofed record can
  only name a different DID; it cannot make a forged log verify.

**Remaining threat:** A `_did` record shows what the current domain holder
asserts. It adds a second compromise only where DNS and hosting are
administered separately. Keeping it in step with moves and deactivation is not
specified.

**Responsible party:** domain holders (keeping DNS and hosting administration
separate); specification (if adopted).

<a id="wvx-th10"></a>

#### WVX-TH10. DNS-Linking Misread or Required

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing, Denial
of Service · **Elements:** `D16`, `E2`, `P3`

A verifier may read a `_did` record as proof that the DID's controller is the
domain's owner, or that the DID is trustworthy. It shows only that the domain
holder names the DID. In the other direction, an ecosystem that *requires*
DNS-linking excludes controllers who publish on a platform they do not control,
which `did:webvh` explicitly allows ([Exclusion](https://identity.foundation/didwebvh/v1.0/#exclusion)),
and path-based DIDs, whose domain holder may not want to vouch for each one.

**Responses**

- No response in the specification, since DNS-linking is not yet part of it.

**Remaining threat:** To be addressed if DNS-linking is adopted: define what a
`_did` record means for `did:webvh`, how it interacts with portability and
paths, and that its absence is not a verification failure.

**Responsible party:** specification; ecosystem governance.

### What an Attacker Must Compromise

Several `did:webvh` features work by making an attacker succeed at more than one
independent compromise before an attack goes undetected. This table brings those
requirements together across the layers. **and** means every item is needed;
**or** means any one is enough. As in the rest of this model, the DID is assumed
to use pre-rotation; without it, any key in the active `updateKeys` replaces
"committed next key" ([WVH-TH13](#wvh-th13)). "Host" means write access to the web host, or
anything that lets an attacker control what resolvers receive from it: control
of the domain's DNS, or a network position combined with a fraudulent
certificate.

| Attacker goal | `did:web` (Layer 2) | `did:webvh` (Layer 3) | With witnesses, watchers and DNS-linking (Layer 4) |
|---|---|---|---|
| Take over the DID: resolvers accept the attacker's keys as current | Host | A committed next key **and** host | Layer 3 **and** a threshold of witnesses |
| Rewrite or fork the DID's history without detection | Not applicable: there is no history | A committed next key, or a used key that was not destroyed, **and** host. Detectable by resolvers that saw the real history. | Layer 3 **and** a threshold of witnesses for each branch (unless the threshold is at most half the witnesses: [WVX-TH2](#wvx-th2)) **and** every consulted watcher that holds the real history |
| Serve a stale DID, or withhold it | Host, or a cache | Host, or a cache. Detectable by resolvers that saw newer versions. | Layer 3 **and** every consulted watcher that has seen the newer versions |
| Pass off another DID as the domain holder's | Host | Host | Host **and** the domain's DNS |
| Tamper with `did.json` | Host | Host | Host |

These requirements add up only when the systems are administered independently.
They collapse into one compromise when:

- **Keys and deploy credentials are kept together.** If next keys and web host
  credentials share a machine, vault or CI pipeline, one breach yields both.
- **DNS and hosting share an operator or account.** A takeover of the domain's
  DNS always yields both, since the attacker can redirect the domain *and*
  rewrite its `_did` record ([WVX-TH9](#wvx-th9)).
- **Witnesses are not independent.** Witness keys run by the controller, by the
  hosting provider, or by a single operator count once, however many there are
  ([WVX-TH1](#wvx-th1)).
- **Watchers are not independent.** A watcher run by the hosting provider adds
  nothing. Any watcher fetches from the host, so it cannot see an entry the host
  has withheld from the start ([WVX-TH6](#wvx-th6)).
- **Verifiers don't consult them.** Watchers and DNS-linking protect only the
  verifiers whose resolvers actually check them.
