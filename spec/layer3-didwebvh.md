## Layer 3: did:webvh

This layer models `did:webvh` as most controllers first deploy it: a DID Log
on a web server, with no witnesses, no watchers and no DNS-linking. It is a
complete, conformant deployment, and the baseline against which
[Layer 4](#layer-4-didwebvh-with-witnesses-watchers-and-dns-linking) adds
options.

::: note
**Assumption: pre-rotation is in use.** This threat model assumes the DID Controller uses
[pre-rotation](https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification)
from the DID's first entry, and never turns it off. Each entry commits, in
`nextKeyHashes`, to the hashes of the keys that will authorize the next entry.
Pre-rotation is optional in v1.0, but it is recommended, and future versions of
`did:webvh` will likely require it. The threats in Layers 3 and 4 are written for
DIDs that use it. The threat of not using it is
[WVH-TH13](#wvh-th13).
:::

### System Model

[![Data flow diagram for did:webvh without witnesses, watchers or DNS-linking. The DID controller publishes a self-certifying DID Log, an optional parallel did:web document and optional DID URL path resources to a web server. A resolver fetches the DID Log over HTTPS, verifies every entry, and returns the DID document to a DID-enabled application. Resolvers that only understand did:web read did.json instead. Four trust boundaries, T1 to T4, are marked.](../spec/assets/dfd-layer3-didwebvh.svg)](../spec/assets/dfd-layer3-didwebvh.svg)

**Figure 2** (select to enlarge). `did:webvh` without witnesses, watchers or DNS-linking. The diagram
is the same shape as `did:web`; what changes is what is published, and what the
resolver checks.

#### Description

The DID (`D1`) now contains a self-certifying identifier (SCID), a hash of
the DID's first log entry:
`did:webvh:{SCID}:example.com`. The identifier is still the whole DID. The
SCID binds the DID to its log: no one can create a different log that verifies
against the same SCID, so the SCID is unique across all `did:webvh` DIDs. The
domain and path tell a resolver where to find the log. If the DID is
[portable](https://identity.foundation/didwebvh/v1.0/#did-portability), it can
move to a new domain or path. The result is a new DID with the same SCID, whose
log continues the original one.

As with `did:web`, the DID Controller (`E1`) manages the DID through a
Controller App (`P1`) (`F1`), and decides what the DID document contains: its
verification methods, services and other properties. The keys for the DID
document's verification methods are chosen by the controller and are separate
from the keys that authorize log entries (`updateKeys`). `did:webvh` does not
restrict the DID document's contents. It changes how a version of the document
is published and authorized, not what the document says.

The controller's key store (`D2`) therefore holds three kinds of secret: the
private keys for the DID document's verification methods, the update keys that
sign log entries, and the credentials used to deploy to the host.

To create or update the DID, the Controller App (`P1`) builds a DID log entry
holding the new DID document and the DID's parameters, and chains it to the
previous entry by an entry hash. With pre-rotation, the entry reveals its
`updateKeys`, each of which must match a hash committed in the previous entry's
`nextKeyHashes`. It is signed with one of those keys, and commits to the hashes
of the keys for the next entry. The key store (`D2`) holds the committed next
keys until they are used. Once used, a key is spent and should be destroyed.

`P1` publishes (`F2`) to the web root (`D3`):

- the DID Log, `did.jsonl` (`D12`), holding every entry since creation;
- optionally, a parallel `did:web` DID document, `did.json` (`D11`), for
  resolvers that only support `did:web`;
- optionally, DID URL path resources (`D13`): a `whois.vp` Verifiable
  Presentation, and any files reached through DID URL paths.

The resolver (`P4`) transforms the DID into an HTTPS URL as `did:web` does,
fetches `did.jsonl` (`F7`) and verifies every entry: the SCID, the entry-hash
chain, the version numbers and times, the proofs against the active update keys,
and the pre-rotation commitments. It returns the requested version of the DID
document. It can remember the latest version it has seen for each DID (`D6`),
and the `ttl` parameter tells it how long to cache. For DID URLs with a path or
`/whois`, it fetches the resource from the host (`F10`). A resolver that only
understands `did:web` reads `did.json` instead (`F9`) and gets none of these
checks.

The key change is to the web host boundary, `T1`. Because the log is
self-certifying, the host is no longer trusted for its integrity. The host is
still trusted for its availability, its freshness and its completeness, and for
the integrity of `did.json` and of any resource that is not signed.

The log can be verified the same way wherever it comes from. A DID-enabled
application can verify it itself and so collapse the resolution boundary `T2`.

#### Dictionary

Elements as in [Layer 2](#layer-2-didweb), except:

In the ID and Status columns, **\*** marks an element new in this layer and **†** an element whose meaning changes in this layer (see [Element IDs](#element-ids)).

| ID | Name | Status | Description |
|---|---|---|---|
| `D1†` | DID | † | `did:webvh:{SCID}:<host>[%3A<port>][:<path>]`. The identifier is the whole DID. The SCID binds it to its log and is unique across all `did:webvh` DIDs; host and path tell resolvers where to find the log. |
| `D2†` | Controller key store | † | Private keys for `updateKeys` and for keys committed in `nextKeyHashes`, plus DID document keys and deploy credentials. |
| `D6†` | Resolver local data | † | Verified state; the last-seen `versionId` per DID; `ttl` guidance. |
| `D11†` | Parallel `did:web` document | † | Optional `did.json` derived from the latest `did:webvh` DID document. Carries no history. |
| `D12*` | DID Log (`did.jsonl`) | \* | JSON Lines entries of `versionId`, `versionTime`, `parameters`, `state` and `proof`, hash-chained from the SCID. Verifiable from any source. |
| `D13*` | DID URL path resources | \* | `whois.vp`, a Verifiable Presentation signed by the DID, and files reached through the implicit `#files` service. Their integrity rests on their own signatures, if any. Not to be confused with DID-Linked Resources (DLRs), an extension to DID metadata, or with Attested Resources. |
| `P1†` | DID Controller Process | † | Generates the SCID, entry hashes and proofs, manages pre-rotation, and writes `D11`–`D13`. |
| `P4†` | `did:webvh` Resolver | † | Transforms the DID, fetches with SSRF safeguards, verifies every entry, answers version queries and dereferences DID URL paths. |
| `F2†` | Publish | † | Deploys `D11`–`D13` to the host. |
| `F7†` | Read DID Log | † | HTTPS GET of `did.jsonl`. |
| `F9*` | `did:web` fallback | \* | HTTPS GET of `did.json` by a resolver that treats the DID as `did:web`. |
| `F10*` | Dereference DID URL | \* | HTTPS GET of `whois.vp` or a path file, through the `#whois` or `#files` service. The DID document can override either service. |
| `T1†` | Web host boundary | † | Crossed by `F2`, `F7`, `F9` and `F10`. The host is trusted for availability, freshness and completeness of `D12`, and for the integrity of `D11` and unsigned `D13`. It is not trusted for the integrity of `D12`. |

### Stakeholders

Changes from [Layer 2](#layer-2-didweb):

- **DID Controller (`E1`).** Gains a DID that survives a host compromise and a
  change of host, and keeps its history. Takes on key management: custody of the
  committed next keys, and destruction of each key once used. Gives up the ability to erase the
  DID's history, since every version is public.
- **DID URL User (`E2`).** Can verify the DID's whole history, and resolve the
  version that was current when a signature was made. Still depends on the host
  for currency, and may not know when a `did:web` resolver has been used
  instead.
- **Resolver Service Provider (`E4`).** Must verify a whole log rather than read
  one document. Faces more denial-of-service risk, and has normative SSRF
  safeguards to implement.
- **Web Hosting Provider (`E5`).** Can no longer forge the DID, but can still
  withhold it, serve a stale copy, or tamper with `did.json` and unsigned
  resources.

### Dispositions of did:web Threats

| Threat | Disposition | Notes |
|---|---|---|
| [WEB-TH1](#web-th1) Host compromise serves a forged DID document | **Superseded** for the DID Log; **Applies** to `D11` | [WVH-R1](#wvh-r1) and [WVH-R2](#wvh-r2) make the log unforgeable without an update key. What a host can still do is replaced by [WVH-TH1](#wvh-th1) (truncation and withholding) and [WVH-TH2](#wvh-th2) (split view). For `did.json` see [WVH-TH7](#wvh-th7). The host can also publish a *new* DID, with its own SCID, at the domain and pass it off as the domain holder's ([WVH-TH9](#wvh-th9)). |
| [WEB-TH2](#web-th2) Domain takeover | **Changed** | The new holder of the domain cannot create entries for the DID without an update key, and cannot create another DID with the same SCID ([Unique Assignment of DIDs](https://identity.foundation/didwebvh/v1.0/#unique-assignment-of-dids)). They can withhold or serve an old log ([WVH-TH1](#wvh-th1)), and forge `D11`. A portable DID can be moved to a new domain ([WVH-R16](#wvh-r16)). |
| [WEB-TH3](#web-th3) Network attacker serves a forged DID document | **Changed** | Mitigated for the log by [WVH-R2](#wvh-r2). TLS becomes a **MUST** ([Endpoint Authentication](https://identity.foundation/didwebvh/v1.0/#endpoint-authentication)) and still protects against truncation in transit ([WVH-TH1](#wvh-th1)) and against forgery of `D11`. |
| [WEB-TH4](#web-th4) Fraudulent TLS certificate | **Changed** | As for WEB-TH3: affects availability and freshness of the log, and integrity of `D11`. |
| [WEB-TH5](#web-th5) No verifiable history | **Mitigated** | [WVH-R2](#wvh-r2): every version is in the log, verifiable, and can be resolved by `versionId`, `versionTime` or `versionNumber` ([Read (Resolve)](https://identity.foundation/didwebvh/v1.0/#read-resolve)). What remains is covered by [WVH-TH2](#wvh-th2) (forks) and [WVH-TH5](#wvh-th5) (controller-asserted time). |
| [WEB-TH6](#web-th6) Reassignment of a DID | **Mitigated** | A new controller of the location cannot produce a valid log for an existing SCID ([WVH-R1](#wvh-r1)). Controllers **SHOULD** deactivate a DID before giving up its domain ([Misattribution](https://identity.foundation/didwebvh/v1.0/#misattribution)). The reverse risk, a DID implying a domain it no longer uses, is [WVH-TH8](#wvh-th8). |
| [WEB-TH7](#web-th7) Stale DID document from caches | **Superseded** | By [WVH-TH1](#wvh-th1), which covers stale logs whether caused by caches or by an attacker. |
| [WEB-TH8](#web-th8) Host unavailability, censorship or exclusion | **Changed** | Still applies to a single host. Because the log verifies from any source, it can be mirrored, and a portable DID can be moved ([WVH-R16](#wvh-r16); [Exclusion](https://identity.foundation/didwebvh/v1.0/#exclusion)). Watchers add persistence in [Layer 4](#wvx-dispositions). |
| [WEB-TH9](#web-th9) Path-based DID misattributed to the domain operator | **Applies** | The specification restates that the domain is used only for discovery and does not show who controls the DID ([Unique Assignment of DIDs](https://identity.foundation/didwebvh/v1.0/#unique-assignment-of-dids)). See also [WVH-TH9](#wvh-th9). |
| [WEB-TH10](#web-th10) Look-alike domains | **Applies** | IDNA processing is normative in the [DID-to-HTTPS transformation](https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation) ([International Domain Names](https://identity.foundation/didwebvh/v1.0/#international-domain-names)), so implementations agree on which host a DID names. Visual confusion is unchanged. |
| [WEB-TH11](#web-th11) Resolver accepts a document for another DID | **Superseded** | By [WVH-R1](#wvh-r1), and by [WVH-TH6](#wvh-th6) for the larger set of checks a `did:webvh` resolver must get right. |
| [WEB-TH12](#web-th12) SSRF through DID strings | **Changed** | Resolvers **MUST** apply eight transport safeguards ([WVH-R12](#wvh-r12)). The specification notes that all four implementations reviewed were vulnerable to at least one of the first four. Applies to `F7` and `F10`. |
| [WEB-TH13](#web-th13) Resource exhaustion during resolution | **Changed** | Worse: a resolver fetches and verifies a whole log, and logs grow. Responses added: size cap, timeout, rate and concurrency limits, and rejecting implausibly rapid `versionTime` progression ([WVH-R12](#wvh-r12); [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks), Denial of Service). Limits are left to ecosystem governance. |
| [WEB-TH14](#web-th14) Resolution tracking | **Applies** | Same responses ([Surveillance](https://identity.foundation/didwebvh/v1.0/#surveillance)). The specification adds guidance for issuers hosting credential status resources alongside a DID ([No Phone Home Mitigations](https://identity.foundation/didwebvh/v1.0/#no-phone-home-mitigations)). |

### New Threats

| ID | Threat | Kind | Elements |
|---|---|---|---|
| [WVH-TH1](#wvh-th1) | Truncated or withheld DID Log | target | `P2`, `F7`, `T1`, `D12`, `D6` |
| [WVH-TH2](#wvh-th2) | Forked DID Log and split view | target | `P1`, `P2`, `D12`, `D6`, `F7` |
| [WVH-TH3](#wvh-th3) | Update key compromise | target | `D2`, `P1`, `D12` |
| [WVH-TH4](#wvh-th4) | Loss of committed next keys | target | `D2`, `E1` |
| [WVH-TH5](#wvh-th5) | Controller-asserted version time | target | `D12`, `P4` |
| [WVH-TH6](#wvh-th6) | Resolver verification shortcuts | implementation | `P4`, `D12` |
| [WVH-TH7](#wvh-th7) | Downgrade to the parallel `did:web` document | deployment | `D11`, `F9`, `P4` |
| [WVH-TH8](#wvh-th8) | Misleading prior-domain association | socio-technical | `D1`, `D4`, `T3` |
| [WVH-TH9](#wvh-th9) | Verification mistaken for trust | socio-technical | `D13`, `E2`, `P3` |
| [WVH-TH10](#wvh-th10) | Ambiguous deactivation | socio-technical | `D12`, `D9`, `D10` |
| [WVH-TH11](#wvh-th11) | Cryptographic break, including quantum | dependency | `D12`, `D2` |
| [WVH-TH12](#wvh-th12) | Permanent public history | privacy | `D12`, `D13` |
| [WVH-TH13](#wvh-th13) | DID operated without pre-rotation | deployment | `D2`, `D12`, `P1`, `P4` |

<a id="wvh-th1"></a>

#### WVH-TH1. Truncated or Withheld DID Log

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Denial of
Service · **Elements:** `P2`, `F7`, `T1`, `D12`, `D6`

Every prefix of a valid DID Log is itself a valid DID Log. Anyone who controls
what is served can serve an older prefix of `did.jsonl`, and the resolver will
verify it and return an old DID document as current. That includes the host, a
network attacker, and a CDN or cache by accident. A verifier might then:

- accept a key the controller has already rotated out, for example after a
  compromise;
- miss a deactivation;
- use service endpoints that have been replaced.

There is no signed statement of which entry is the latest, so a stale log
cannot be told from a current one by its content. Withholding the log
completely gives a `notFound` error, which is a denial of service.

**Responses**

- <span id="wvh-r3"></span>**WVH-R3. Resolver cache-and-compare** (Reduce).
  Resolvers **SHOULD** remember the latest `versionId` they have seen for a DID
  (`D6`), and **SHOULD** warn or fail when served a truncated log. This protects
  only DIDs the resolver has resolved before. A resolver shared by many clients
  covers more DIDs than one embedded in each client. →
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)
  (Truncation or withholding of log entries)
- **WEB-R5. TLS** *(reused)* (Reduce). Required by `did:webvh`. Stops a network
  attacker truncating in transit. Has no effect on the host, or on an
  intermediary that terminates TLS, such as a CDN. →
  [Endpoint Authentication](https://identity.foundation/didwebvh/v1.0/#endpoint-authentication)
- <span id="wvh-r4"></span>**WVH-R4. Intermediaries must not serve stale data**
  (Transfer, to the deployer). Implementations relying on CDN caching or load
  balancers **MUST** ensure that these do not serve stale or tampered DID data. →
  [Network Topology](https://identity.foundation/didwebvh/v1.0/#network-topology)
- <span id="wvh-r5"></span>**WVH-R5. `ttl` parameter** (Reduce). The controller
  tells resolvers how long to cache the DID. This limits staleness caused by
  resolver caches, not by the host. →
  [`did:webvh` DID Method Parameters](https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters)

**Remaining threat:** A resolver with no prior state for the DID cannot detect a
consistent older log. Accepted in this layer.
[Layer 4](#wvx-dispositions) adds witnesses and watchers, which reduce it.

**Responsible party:** resolver operators (WVH-R3); deployers (WVH-R4);
controllers (WVH-R5).

<a id="wvh-th2"></a>

#### WVH-TH2. Forked DID Log and Split View

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Repudiation ·
**Elements:** `P1`, `P2`, `D12`, `D6`, `F7`

An entry's children can be signed by any key whose hash that entry committed in
`nextKeyHashes`. Whoever holds such a key can sign two different children of the
same parent, and both branches of the log verify. That includes keys already
used: the key that signed entry *k* can still sign an alternative entry *k′*
from the same parent. Causes include:

- a mistake, such as two instances of a controller app publishing at once;
- a deliberate choice by the controller, to show different DID documents to
  different parties, or later to deny which keys were in effect (repudiation);
- an attacker who holds a committed next key, or a used key that was not
  destroyed ([WVH-TH3](#wvh-th3)).

The host can then serve different branches to different resolvers, by client
address, time or user agent. This is a *split view*: two verifiers each see a
valid but different DID. Unlike truncation, neither branch is a prefix of the
other, and nothing in the logs shows which is authoritative.

The same mechanism lets a controller rewrite history after the fact: publish a
new branch from an old entry, and replace the log with it.

**Responses**

- <span id="wvh-r6"></span>**WVH-R6. Monotonic extension at publication**
  (Reduce, for accidental forks). Publication components **MUST** enforce
  monotonic extension of the current tip. The specification does not say how.
  This does not constrain a controller acting deliberately. →
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)
  (Conflicting parallel updates / split view)
- **WVH-R3. Resolver cache-and-compare** *(reused)* (Reduce). Resolvers
  **SHOULD** cache the highest version and hash they have seen and **SHOULD**
  detect and warn about older branches. A resolver that saw one branch detects
  the other if it is later served it. →
  [Threats and Attacks](https://identity.foundation/didwebvh/v1.0/#threats-and-attacks)

**Remaining threat:** A controller, or anyone holding a committed or undestroyed
used key, can fork or rewrite the log, and a resolver with no prior state cannot detect it. The
specification does not say what a resolver returns when it detects a fork.
Accepted in this layer; witnesses and watchers address it in
[Layer 4](#wvx-dispositions).

**Responsible party:** controllers; resolver operators; implementers of
publishing tools.

<a id="wvh-th3"></a>

#### WVH-TH3. Update Key Compromise

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Spoofing, Elevation of
Privilege · **Elements:** `D2`, `P1`, `D12`

With pre-rotation, the keys an attacker can use are:

- **A committed next key**, not yet used. The attacker can sign the next entry,
  commit to their own next keys, and take over the DID going forward.
- **A used key that was not destroyed.** It cannot extend the current tip, whose
  committed next keys are different. But it can sign an alternative to the entry
  it originally signed. From there the attacker builds a branch with their own
  keys, which can be made longer than the real log ([WVH-TH2](#wvh-th2)). A
  resolver with no prior state that is served that branch accepts it.

A stolen key that is neither does not authorize anything. If the DID is
portable, an attacker who succeeds can also move it to a domain they control.

**Compromises required.** A key alone is not enough. Resolvers fetch the log from
the DID's location, so the attacker must also get the new entry served there:
through write access to the web host, or control of the domain's DNS, which also
lets them obtain a certificate. That holds for a portable DID too, since the
entry that moves it must first be published at the current location. Taking
over a `did:webvh` DID therefore takes two compromises, the key and the host,
where `did:web` needs only the host ([WEB-TH1](#web-th1)). The two are not
independent when the controller keeps next keys and deploy credentials
together (both in `D2`), or when one publishing pipeline holds both.

**Responses**

- <span id="wvh-r7"></span>**WVH-R7. Key pre-rotation** (Reduce). When
  `nextKeyHashes` is set, each new entry must be signed by a key from its *own*
  `updateKeys`, and every one of those keys **MUST** hash to a value committed in
  the previous entry. Compromise of the keys published in the log does not let an
  attacker extend it. The attacker needs a committed next key, which the
  controller can keep offline until it is needed, or a used key (WVH-R8). →
  [Pre-Rotation Key Hash Generation and Verification](https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification),
  [Authorized Keys](https://identity.foundation/didwebvh/v1.0/#authorized-keys)
- <span id="wvh-r8"></span>**WVH-R8. Treat used keys as spent** (Reduce). After
  rotating from a pre-rotation key, the controller **SHOULD** treat its private
  key as spent and securely destroy it, and **SHOULD NOT** commit to it again.
  Destroying it removes the fork route above. Resolvers **MAY** warn on reuse. →
  [Pre-Rotation Key Hash Generation and Verification](https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification),
  [Residual Risks](https://identity.foundation/didwebvh/v1.0/#residual-risks)
- <span id="wvh-r9"></span>**WVH-R9. Secure key storage** (Transfer, to the
  controller). Secret keys **MUST** be kept in secure storage; HSMs, secure
  enclaves, access controls and backups **SHOULD** be used. →
  [Cryptographic Protection](https://identity.foundation/didwebvh/v1.0/#cryptographic-protection),
  [Residual Risks](https://identity.foundation/didwebvh/v1.0/#residual-risks),
  [Implementation Hygiene](https://identity.foundation/didwebvh/v1.0/#implementation-hygiene-informative)

**Remaining threat:**

- A stolen committed next key, plus a way to publish, is a takeover. If the
  controller publishes with another committed key at about the same time, the
  result is a fork ([WVH-TH2](#wvh-th2)).
- A stolen used key that was not destroyed, plus a way to publish, is a forked
  history that deceives resolvers with no prior state.
- Witnesses add a third requirement in [Layer 4](#wvx-dispositions).
- For DIDs that do not use pre-rotation, see [WVH-TH13](#wvh-th13).

**Responsible party:** controller.

<a id="wvh-th4"></a>

#### WVH-TH4. Loss of Committed Next Keys

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Denial of Service ·
**Elements:** `D2`, `E1`

Only keys committed in the latest entry's `nextKeyHashes` can authorize the next
entry. If the controller loses the private keys for all of them, no further
entry can be made. The DID can no longer be updated, rotated, moved or
deactivated. There is no recovery mechanism in the method: the controller must
create a new DID. Because next keys are meant to be kept offline and separate
from day-to-day systems, they are also easier to lose.

**Responses**

- **WVH-R9. Secure key storage** *(reused)* (Transfer, to the controller),
  including secure backups of critical keys. →
  [Residual Risks](https://identity.foundation/didwebvh/v1.0/#residual-risks)
- **Commit to spare keys** (Reduce). A controller **MAY** commit to more hashes in
  `nextKeyHashes` than it will use, for example one key held online and one in
  cold storage. Any one of them can authorize the next entry. The specification
  allows this but does not describe it as a recovery practice. →
  [Pre-Rotation Key Hash Generation and Verification](https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification)

**Remaining threat:** Accepted.

**Responsible party:** controller.

<a id="wvh-th5"></a>

#### WVH-TH5. Controller-Asserted Version Time

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Repudiation, Tampering ·
**Elements:** `D12`, `P4`

Each entry's `versionTime` is set by the controller. Resolvers check that times
strictly increase and are not in the future, but nothing ties a time to when the
entry was actually created. A controller can backdate an entry into the gap
after the previous one, so that `versionTime` queries return a document that was
not in fact published at that time. That matters when a verifier asks which key
was valid when a signature was made. Combined with a fork
([WVH-TH2](#wvh-th2)), a controller can construct a whole alternative history.

**Responses**

- <span id="wvh-r10"></span>**WVH-R10. Time ordering checks** (Reduce).
  `versionTime` **MUST** be strictly greater than the previous entry's and
  **MUST NOT** be more than a small skew in the future. →
  [Read (Resolve)](https://identity.foundation/didwebvh/v1.0/#read-resolve)

**Remaining threat:** Accepted in this layer. Verifiers needing trustworthy time
need evidence from outside the log, such as witnesses
([Layer 4](#wvx-dispositions)) or a timestamped copy held by a watcher.

**Responsible party:** verifiers.

<a id="wvh-th6"></a>

#### WVH-TH6. Resolver Verification Shortcuts

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Tampering,
Spoofing · **Elements:** `P4`, `D12`

`did:webvh`'s guarantees hold only if the resolver performs every check. A
resolver that, for example, verifies only the last entry, accepts an unexpected
cryptosuite, silently downgrades or ignores an unknown `method` value, mishandles
`null` parameters, skips the pre-rotation check, or accepts a `state.id` with a
different SCID, accepts a forged or substituted log.

**Responses**

- <span id="wvh-r1"></span>**WVH-R1. Self-certifying identifier** (Eliminate,
  for substituted logs). The SCID in the DID is the hash of the first entry.
  Resolvers **MUST** verify it, and **MUST** check that the SCID in every entry's
  `state.id` equals both the DID's SCID and the first entry's `parameters.scid`. →
  [SCID Generation and Verification](https://identity.foundation/didwebvh/v1.0/#scid-generation-and-verification),
  [Read (Resolve)](https://identity.foundation/didwebvh/v1.0/#read-resolve)
- <span id="wvh-r2"></span>**WVH-R2. Full verification of every entry**
  (Eliminate, for altered or inserted entries). Resolvers **MUST** verify the
  entry hash chain and the proof of every entry, not only the latest, with
  version numbers increasing by one. Because the log is self-certifying, it
  verifies the same way from any source. →
  [Read (Resolve)](https://identity.foundation/didwebvh/v1.0/#read-resolve),
  [Entry Hash Generation and Verification](https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification),
  [Authorized Keys](https://identity.foundation/didwebvh/v1.0/#authorized-keys),
  [Integrity Protection and Update Authentication](https://identity.foundation/didwebvh/v1.0/#integrity-protection-and-update-authentication)
- <span id="wvh-r11"></span>**WVH-R11. Fail closed and validation checklist**
  (Reduce). Unknown parameter values, hash algorithm mismatch and cryptosuite
  mismatch **MUST** fail resolution. An informative checklist maps each
  normative check to a test point. →
  [Resolver Validation Checklist](https://identity.foundation/didwebvh/v1.0/#resolver-validation-checklist-informative)
- <span id="wvh-r12"></span>**WVH-R12. Resolver transport hardening** (Reduce).
  No automatic redirects; reject IP literals before and after decoding and after
  DNS resolution; normalize percent-encoding; HTTPS only; size cap; timeout; no
  `localhost` in production. →
  [Resolver Transport Hardening](https://identity.foundation/didwebvh/v1.0/#resolver-transport-hardening-ssrf-and-network-boundary)

**Remaining threat:** Implementation errors. A shared conformance test suite
would reduce them; the specification does not reference one.

**Responsible party:** resolver implementers.

<a id="wvh-th7"></a>

#### WVH-TH7. Downgrade to the Parallel did:web Document

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Tampering, Spoofing ·
**Elements:** `D11`, `F9`, `P4`

A controller who publishes a parallel `did:web` DID (`did.json`) lets
`did:web`-only resolvers use the DID. Those resolvers, and any verifier who
accepts the `did:web` form, get none of `did:webvh`'s protections: every
[Layer 2](#layer-2-didweb) threat applies to them. A compromised host can alter
only `did.json`, leaving the log intact, and `did:web` users will not notice.

**Responses**

- <span id="wvh-r13"></span>**WVH-R13. Evaluate before publishing** (Transfer,
  to the controller). Controllers considering a parallel `did:web` **SHOULD**
  evaluate the loss of `did:webvh`'s security properties. →
  [Publishing parallel `did:web`](https://identity.foundation/didwebvh/v1.0/#publishing-parallel-didweb),
  [Publishing a Parallel `did:web` DID](https://identity.foundation/didwebvh/v1.0/#publishing-a-parallel-didweb-did)
- **Upgrade through `alsoKnownAs`** (Reduce). The `did:web` document lists the
  `did:webvh` DID in `alsoKnownAs`, so a resolver aware of `did:webvh` can
  resolve the log instead. →
  [Publishing a Parallel `did:web` DID](https://identity.foundation/didwebvh/v1.0/#publishing-a-parallel-didweb-did)

**Remaining threat:** Verifiers using the `did:web` form are exposed to all
`did:web` threats.

**Responsible party:** controller (whether to publish); verifiers (which form
to accept).

<a id="wvh-th8"></a>

#### WVH-TH8. Misleading Prior-Domain Association

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D1`, `D4`, `T3`

A portable DID's log records every domain it has used, and its DID document
lists earlier DIDs in `alsoKnownAs`. A controller can create a DID that names a
domain it never controlled, such as `did:webvh:{SCID}:bigbank.example`, without
ever publishing there, then immediately move it to its own domain. The history
now appears to show an association with the first domain.

**Responses**

- <span id="wvh-r14"></span>**WVH-R14. Ignore prior domains** (Reduce).
  Resolvers and their clients **MUST** ignore prior domain components when
  evaluating a DID's history or trustworthiness. →
  [Unique Assignment of DIDs](https://identity.foundation/didwebvh/v1.0/#unique-assignment-of-dids),
  [DID Portability](https://identity.foundation/didwebvh/v1.0/#did-portability)
- <span id="wvh-r15"></span>**WVH-R15. Attestations through `whois`**
  (Transfer, to relying parties). Use credentials from relevant authorities to
  decide whom a DID belongs to. →
  [DID URL whois LinkedVP Service](https://identity.foundation/didwebvh/v1.0/#did-url-whois-linkedvp-service)

**Remaining threat:** Users who look at the history rather than rely on software
can still be misled.

**Responsible party:** DID-enabled application developers; users.

<a id="wvh-th9"></a>

#### WVH-TH9. Verification Mistaken for Trust

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D13`, `E2`, `P3`

A DID that verifies proves only that its history is internally consistent and
signed by its own keys. It says nothing about who controls it. A user who sees a
valid DID on a familiar domain, or a `/whois` presentation full of credentials,
may assume the DID is trustworthy. But the controller chooses what goes in
`whois.vp`, and the domain need not be controlled by the DID's controller.

This also gives a host compromise a way around `did:webvh`'s integrity. An
attacker who can write to an organization's web host cannot alter the
organization's DID, but can create and publish a *new* DID at the same domain.
A verifier who judges a DID by its domain will accept it. Without DNS-linking,
host access alone is enough for this.

**Responses**

- **Specification warnings** (Accept, documented). The DID-to-HTTPS
  transformation warns that a DID is not inherently controlled by the entity
  associated with its domain, and the domain is used only for discovery. →
  [The DID to HTTPS Transformation](https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation),
  [Unique Assignment of DIDs](https://identity.foundation/didwebvh/v1.0/#unique-assignment-of-dids)
- **WVH-R15. Attestations through `whois`** *(reused)* (Transfer, to relying
  parties), with the relying party deciding which issuers matter. →
  [DID URL whois LinkedVP Service](https://identity.foundation/didwebvh/v1.0/#did-url-whois-linkedvp-service)

**Remaining threat:** Accepted. A DNS-linking record ([Layer 4](#wvx-dispositions))
lets a domain holder assert a DID, which helps for that one question.

**Responsible party:** relying parties; ecosystem governance.

<a id="wvh-th10"></a>

#### WVH-TH10. Ambiguous Deactivation

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Repudiation,
Denial of Service · **Elements:** `D12`, `D9`, `D10`

A controller can retire a DID in three ways, and each looks different to a
verifier:

- set `deactivated: true`: the resolver returns no DID document and reports the
  DID as deactivated;
- set `updateKeys` to `[]`: the last DID document is still returned, and the
  metadata shows it can no longer be updated. With pre-rotation this takes two
  entries: one that turns pre-rotation off, then one that empties `updateKeys`;
- delete the log: the resolver returns `notFound`.

The third cannot be told apart from an outage or from a host withholding the log
([WVH-TH1](#wvh-th1)). A verifier may treat a deleted DID as temporarily
unavailable, or an unavailable DID as deactivated.

**Responses**

- <span id="wvh-r16"></span>**WVH-R16. Explicit deactivation and portability**
  (Reduce). Deactivation in the log is reported in resolution metadata, including
  when earlier versions are resolved. Controllers **SHOULD** deactivate a DID
  before giving up its domain, and **SHOULD** move a DID with portability rather
  than abandon it. →
  [Deactivate (Revoke)](https://identity.foundation/didwebvh/v1.0/#deactivate-revoke),
  [Misattribution](https://identity.foundation/didwebvh/v1.0/#misattribution)

**Remaining threat:** Deleting the log is still a permitted way to deactivate,
and is indistinguishable from withholding.

**Responsible party:** controllers; verifiers.

<a id="wvh-th11"></a>

#### WVH-TH11. Cryptographic Break, Including Quantum

**Kind:** dependency · **Taxonomy:** STRIDE · **Class:** Spoofing, Tampering ·
**Elements:** `D12`, `D2`

Every entry, and every update key ever used, is public and permanent. If the
signature algorithm is broken, for example by a quantum computer, an attacker
can derive the private key for any published update key. Pre-rotation stops them
extending the current tip, since the next keys are published only as hashes. But
each published key can still sign an alternative to the entry it signed. The
attacker can therefore fork the log from any earlier entry, including the one
before the tip, and build a longer branch with their own keys
([WVH-TH2](#wvh-th2)). The branch verifies, and a resolver with no prior state
cannot tell it from the real log.

**Responses**

- <span id="wvh-r17"></span>**WVH-R17. Cryptographic agility** (Reduce). The
  `method` parameter fixes the cryptosuites and hash algorithms in effect, and
  can be updated to a new version of the specification. →
  [Cryptographic Agility](https://identity.foundation/didwebvh/v1.0/#cryptographic-agility)
- **WVH-R7. Key pre-rotation** *(reused)* (Reduce). Next keys are published only
  as hashes, so they are not exposed to a break of the signature algorithm until
  they are used, and the tip cannot be extended with derived keys. Forks from
  earlier entries remain possible. →
  [Post Quantum Attacks](https://identity.foundation/didwebvh/v1.0/#post-quantum-attacks)

**Remaining threat:** History signed with a broken algorithm can be forked from
the point of the break. Only external evidence, such as witnesses or watcher
copies, can show which history came first.

**Responsible party:** controllers (timely migration); specification
maintainers.

<a id="wvh-th12"></a>

#### WVH-TH12. Permanent Public History

**Kind:** privacy · **Taxonomy:** LINDDUN · **Class:** Identifiability,
Linkability, Non-compliance · **Elements:** `D12`, `D13`

The log keeps every version of the DID document: every key, service endpoint and
other value the controller has ever published, with times. Information removed
from the current document stays in the log. Anyone can copy it, so deleting the
log does not erase it. Patterns of updates may reveal operational activity.

**Responses**

- <span id="wvh-r18"></span>**WVH-R18. Data minimization** (Reduce).
  Sensitive data **MUST NOT** be included; controllers **SHOULD** avoid personal
  identifiers and unnecessary service endpoints. →
  [Disclosure](https://identity.foundation/didwebvh/v1.0/#disclosure),
  [Correlation](https://identity.foundation/didwebvh/v1.0/#correlation),
  [Secondary Use](https://identity.foundation/didwebvh/v1.0/#secondary-use)

**Remaining threat:** Accepted. Watchers make retention more likely
([Layer 4](#wvx-dispositions)).

**Responsible party:** controllers.

<a id="wvh-th13"></a>

#### WVH-TH13. DID Operated without Pre-Rotation

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Spoofing, Elevation of
Privilege · **Elements:** `D2`, `D12`, `P1`, `P4`

This model assumes pre-rotation is used (see the note at the start of
[Layer 3](#layer-3-didwebvh)). In v1.0 it is optional. A controller can create a
DID without it, and any holder of a committed key can turn it off by setting
`nextKeyHashes` to `[]`. Without pre-rotation, each entry is signed by a key from
the *previous* entry's `updateKeys`, which are published in the log. As a result:

- any key in the active `updateKeys` is enough to take over the DID. Those keys
  are typically held online for routine updates, so they are easier to steal than
  offline next keys ([WVH-TH3](#wvh-th3));
- after a cryptographic break, the active keys can be derived from the log, so
  the tip itself can be extended, not only forked ([WVH-TH11](#wvh-th11));
- an attacker who obtains a key can install their own keys in one entry, leaving
  the controller no committed key to recover with.

A verifier cannot easily tell whether a DID uses pre-rotation: the DID resolution
metadata does not report it, so the verifier must inspect the log.

**Responses**

- **WVH-R7. Key pre-rotation** *(reused)* (Reduce). Available in v1.0 and
  recommended by this model. →
  [Pre-Rotation Key Hash Generation and Verification](https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification)
- **Ecosystem policy** (Transfer, to ecosystem governance). An ecosystem can
  require its participants' DIDs to use pre-rotation, and verifiers can check the
  log for it. Not in the specification.

**Remaining threat:** Accepted in v1.0. It would be eliminated if a future version
of `did:webvh` made pre-rotation mandatory
([finding](#findings-for-the-specification)).

**Responsible party:** controllers; ecosystem governance; specification
maintainers.
