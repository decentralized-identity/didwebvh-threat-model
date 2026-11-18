## Layer 2: did:web

This layer models the [`did:web` method](#ref-did-web). `did:webvh` keeps
`did:web`'s DID-to-HTTPS transformation, its use of an ordinary web server, and
its dependence on DNS and TLS, so every later layer starts here.

No threat model for `did:web` has been published. This layer is written so that
it could stand alone as one.

### System Model

[![Data flow diagram for did:web. The DID controller publishes a did.json DID document to a web server. A resolver finds the server through DNS and Web PKI, fetches did.json over HTTPS, and returns the DID document to a DID-enabled application. Four trust boundaries, T1 to T4, are marked.](../spec/assets/dfd-layer2-did-web.svg)](../spec/assets/dfd-layer2-did-web.svg)

**Figure 1** (select to enlarge). `did:web`. The DID Threat Model's VDR collapses into a web server,
and DNS and Web PKI are added as a dependency.

#### Description

The DID Controller (`E1`) manages the DID (`D1`) through a Controller App (`P1`)
(`F1`). For `did:web`, managing the DID means editing a DID document and
deploying it as `did.json` (`D11`) to the web root (`D3`) of a Web Server
(`P2`) (`F2`). The location is fixed by the DID: `did:web:example.com` maps to
`https://example.com/.well-known/did.json`, and `did:web:example.com:u:bob` to
`https://example.com/u/bob/did.json`.

The `did:web` specification defines no API and no authentication for this step.
Whoever can write to the web root controls the DID. The controller's data store
(`D2`) therefore holds two kinds of secret: the private keys for the DID
document's verification methods, and the credentials used to deploy to the host.

The server is run by a Web Hosting Provider (`E5`), which may be the controller
or a platform such as GitHub Pages. There is no separate resolver-side VDR node:
resolvers read from the controller's own host. The DID Threat Model's `P5`, `C5`,
`D7`, `E6` and `F3` are not used in this layer.

Resolution follows the DID Threat Model up to the resolver. The DID-enabled App
(`P3`) asks a Resolver (`P4`) to resolve the DID (`F6`). `P4`:

1. transforms the DID into an HTTPS URL;
2. resolves the host name and validates the server's certificate through DNS and
   Web PKI (`P6`, `F8`);
3. fetches `did.json` (`F7`);
4. checks that the document's `id` matches the DID;
5. returns the DID document and metadata (`D8`–`D10`).

Nothing in the document itself shows that it is authentic, current or complete.
The resolver relies entirely on the host, DNS and TLS.

#### Dictionary

In the ID and Status columns, **\*** marks an element new in this layer and **†** an element whose meaning changes in this layer (see [Element IDs](#element-ids)).

| ID | Name | Status | Description |
|---|---|---|---|
| `D1†` | DID | † | `did:web:<host>[%3A<port>][:<path>]`. The domain and path both identify the DID and locate its document. |
| `D2†` | Controller data store | † | Private keys for the DID document's verification methods, and credentials to deploy to the host. |
| `D3†` | Web root | † | Directory at `/.well-known/` or at the DID's path. Replaces the Controller VDR Data Store. |
| `D11*` | `did.json` | \* | The DID document, served as JSON. Carries no proof of its own integrity or currency. |
| `C2†` | Web Server (DID host) | † | The HTTPS origin named by the DID. Replaces the Controller VDR Device. |
| `C6*` | DNS and Web PKI | \* | Registrars, DNS and certificate authorities. A black-box dependency, as in the W3C minimalist Web threat model. |
| `P2†` | Web Server | † | Serves files. Replaces the Controller VDR Node. Has full control over what is served. |
| `P4†` | `did:web` Resolver | † | Performs the transformation, fetches `did.json` and checks its `id`. |
| `P6*` | DNS resolution and certificate validation | \* | Turns the host name into an address and authenticates the server. |
| `E5†` | Web Hosting Provider | † | Operates `C2`, including any CDN or load balancer. Replaces the Controller VDR Service Provider. |
| `E7*` | Domain, DNS and CA providers | \* | Registrars, DNS operators and certificate authorities on which discovery and TLS depend. |
| `F2†` | Publish | † | Deploys `did.json` to the host. The mechanism is not specified. |
| `F7†` | Read DID document | † | HTTPS GET of `did.json`. Replaces Read VDR State. |
| `F8*` | DNS and TLS | \* | Name resolution and certificate validation behind every HTTPS flow. Drawn to `P4` and `P2`; it applies to `F2` as well. |
| `T1†` | Web host boundary | † | Crossed by `F2` and `F7`. The host is trusted for the integrity, freshness and availability of the DID document. |
| `T4*` | DNS and Web PKI boundary | \* | Crossed by `F8`. |

All other elements are as in the DID Threat Model.

### Stakeholders

The DID Threat Model's stakeholders apply. This layer changes or adds:

- **Web Hosting Provider (`E5`).** Replaces the Controller VDR Service Provider.
  Often a general-purpose host that does not know it is hosting DIDs. Has full
  control over the DID documents it serves, and its caching layers can serve
  stale documents by accident.
- **Domain, DNS and CA providers (`E7`).** Registrars, DNS operators and
  certificate authorities. Their failures, or attacks on them, can redirect a
  DID to an attacker.
- **DID Controller (`E1`).** For `did:web`, control of the DID *is* control of
  the domain and of write access to the web root. Losing either loses the DID.
- **DID URL User (`E2`).** Depends on the host for the integrity and currency of
  every DID document, and cannot check either.

### Threats

| ID | Threat | Kind | Elements |
|---|---|---|---|
| [WEB-TH1](#web-th1) | Host compromise serves a forged DID document | target | `C2`, `P2`, `D3`, `D11`, `E5`, `T1` |
| [WEB-TH2](#web-th2) | Domain takeover | dependency | `D1`, `C6`, `E7`, `T4` |
| [WEB-TH3](#web-th3) | Network attacker serves a forged DID document | target | `F7`, `F8`, `P6`, `T4` |
| [WEB-TH4](#web-th4) | Fraudulent TLS certificate | dependency | `C6`, `E7`, `F8` |
| [WEB-TH5](#web-th5) | No verifiable history | target | `D11`, `F2`, `D8`–`D10` |
| [WEB-TH6](#web-th6) | Reassignment of a DID to a new controller | socio-technical | `D1`, `D3`, `E5`, `E7` |
| [WEB-TH7](#web-th7) | Stale DID document from caches | deployment | `P2`, `F7`, `D6` |
| [WEB-TH8](#web-th8) | Host unavailability, censorship or exclusion | deployment | `C2`, `E5`, `F7` |
| [WEB-TH9](#web-th9) | Path-based DID misattributed to the domain operator | socio-technical | `D1`, `D4`, `T3` |
| [WEB-TH10](#web-th10) | Look-alike domains | socio-technical | `D1`, `D4`, `T3` |
| [WEB-TH11](#web-th11) | Resolver accepts a document for another DID | implementation | `P4`, `D11` |
| [WEB-TH12](#web-th12) | Server-side request forgery through DID strings | implementation | `P4`, `C4`, `F7` |
| [WEB-TH13](#web-th13) | Resource exhaustion during resolution | implementation | `P4`, `C4`, `F7` |
| [WEB-TH14](#web-th14) | Resolution tracking | privacy | `F7`, `F8`, `E5`, `E7` |

<a id="web-th1"></a>

#### WEB-TH1. Host Compromise Serves a Forged DID Document

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Spoofing,
Elevation of Privilege · **Elements:** `C2`, `P2`, `D3`, `D11`, `E5`, `T1`

Anyone who can write to the web root can replace `did.json` with a document
listing their own keys and services. Resolvers will accept it. That includes an
attacker who has compromised the server or the controller's deploy credentials,
a malicious insider at the hosting provider, and a platform that hosts many
users' DIDs. The attacker then holds the DID: they can sign as its subject and
receive messages sent to its services. Nothing in the document reveals the
change.

**Responses**

- <span id="web-r1"></span>**WEB-R1. Web environment access control**
  (Transfer, to the deployer). `did:web` specifies no authentication or
  authorization for writing the DID document, leaving it to implementations to
  protect it "as with any other web resource". →
  [Authentication and Authorization](https://w3c-ccg.github.io/did-method-web/#authentication-and-authorization)
- <span id="web-r2"></span>**WEB-R2. Hashlink integrity verification** (Reduce,
  optional). A hash of the DID document **MAY** be recorded in a trusted or
  distributed store and checked by the retriever. The specification does not say
  where the hash is stored or how resolvers find it, so in practice this is not
  used. →
  [DID Document Integrity Verification](https://w3c-ccg.github.io/did-method-web/#did-document-integrity-verification)

**Remaining threat:** Complete. Integrity of the DID rests on the security of the
host and its deploy pipeline.

**Responsible party:** deployer and hosting provider.

<a id="web-th2"></a>

#### WEB-TH2. Domain Takeover

**Kind:** dependency · **Taxonomy:** STRIDE · **Class:** Spoofing, Tampering ·
**Elements:** `D1`, `C6`, `E7`, `T4`

The domain *is* the identifier. Whoever controls the domain's DNS can point it
at their own server, obtain a domain-validated certificate for it, and serve any
DID document. Routes to control include:

- compromise of the registrar account or DNS provider;
- a dangling DNS record pointing at a resource the attacker can claim;
- the domain expiring and being registered by someone else.

TLS does not help: the attacker's certificate is valid for the domain.

**Responses**

- <span id="web-r3"></span>**WEB-R3. DNSSEC** (Reduce). The specification
  recommends DNSSEC to prevent spoofed DNS records. DNSSEC protects records in
  transit; it does not help when the registrar or DNS account itself is
  compromised. →
  [DNS Security Considerations](https://w3c-ccg.github.io/did-method-web/#dns-security-considerations)
- <span id="web-r4"></span>**WEB-R4. Domain and registrar hygiene** (Transfer,
  to the deployer). Registrar locks, account multi-factor authentication,
  renewal monitoring and removal of dangling records. Not in the specification.

**Remaining threat:** A party that gains control of the domain, by attack or by
lawful re-registration, gains every DID under it. See also
[WEB-TH6](#web-th6).

**Responsible party:** deployer (domain holder).

<a id="web-th3"></a>

#### WEB-TH3. Network Attacker Serves a Forged DID Document

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Tampering, Spoofing ·
**Elements:** `F7`, `F8`, `P6`, `T4`

An attacker on the network path between resolver and host spoofs DNS responses
or intercepts the HTTPS connection and returns a forged `did.json`.

**Responses**

- <span id="web-r5"></span>**WEB-R5. TLS with strong configuration**
  (Reduce). The identifier **MUST** match the certificate's name, and delivery
  **MUST** follow NIST SP 800-52 Rev. 2. The specification adds cipher-suite
  guidance. →
  [Method-Specific Identifier](https://w3c-ccg.github.io/did-method-web/#method-specific-identifier),
  [In-transit Security](https://w3c-ccg.github.io/did-method-web/#in-transit-security)
- **WEB-R3. DNSSEC** *(reused)* (Reduce). →
  [DNS Security Considerations](https://w3c-ccg.github.io/did-method-web/#dns-security-considerations)
- <span id="web-r6"></span>**WEB-R6. DNS over HTTPS** (Reduce). Resolvers
  **SHOULD** use DNS over HTTPS [[spec:rfc8484]], which protects the DNS lookup
  from on-path tampering as well as observation. →
  [Read (Resolve)](https://w3c-ccg.github.io/did-method-web/#read-resolve),
  [DNS Security Considerations](https://w3c-ccg.github.io/did-method-web/#dns-security-considerations)

**Remaining threat:** Low where TLS is correctly validated. Rests on
[WEB-TH4](#web-th4).

**Responsible party:** resolver implementers (validation), deployers (TLS
configuration).

<a id="web-th4"></a>

#### WEB-TH4. Fraudulent TLS Certificate

**Kind:** dependency · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `C6`, `E7`, `F8`

A certificate authority issues a certificate for the DID's domain to an
attacker, by error, compromise or coercion. Combined with a network position
([WEB-TH3](#web-th3)), the attacker can serve a forged DID document that passes
TLS validation.

**Responses**

- <span id="web-r7"></span>**WEB-R7. Certificate issuance controls** (Transfer,
  to the deployer). CAA records [[spec:rfc8659]], Certificate Transparency
  monitoring [[spec:rfc6962]] and DANE [[spec:rfc6698]]. Not in the
  specification.

**Remaining threat:** Accepted, as for all Web PKI.

**Responsible party:** deployer; the Web PKI.

<a id="web-th5"></a>

#### WEB-TH5. No Verifiable History

**Kind:** target · **Taxonomy:** STRIDE · **Class:** Repudiation, Tampering ·
**Elements:** `D11`, `F2`, `D8`–`D10`

`did:web` publishes only the current DID document. Updating the DID means
overwriting `did.json`. As a result:

- a verifier cannot see what keys a DID had at an earlier time, so cannot verify
  a signature made with a key that has since been rotated out;
- a controller can deny that a key was ever theirs, or claim it was, and no one
  can prove otherwise from the DID alone;
- a malicious change to the document ([WEB-TH1](#web-th1)) leaves no trace once
  it is reverted;
- DID document metadata such as `created`, `updated` and `versionId` cannot be
  checked.

**Responses**

- <span id="web-r8"></span>**WEB-R8. Version control and CI** (Reduce, for the
  controller only). The specification suggests managing updates with a version
  control system and a CI pipeline "for authentication and audit history". That
  history is private to the controller and cannot be checked by resolvers. →
  [Update](https://w3c-ccg.github.io/did-method-web/#update)

**Remaining threat:** Complete for verifiers. This is the threat `did:webvh` was
created to address ([Layer 3](#layer-3-didwebvh)).

**Responsible party:** accepted by the method.

<a id="web-th6"></a>

#### WEB-TH6. Reassignment of a DID to a New Controller

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D1`, `D3`, `E5`, `E7`

A `did:web` DID is just a location. When the controller stops using it, anyone
who later controls that location can publish a new document under the same DID.
This happens when:

- a domain expires and is re-registered;
- a hosting platform recycles a user name or repository path;
- an organization reorganizes its web site and another team takes over a path.

Credentials and signatures made by the old controller now appear to come from
the new one, and vice versa. Deleting `did.json`, the only form of
deactivation, makes this worse: there is no record that the DID was ever
deactivated.

**Responses**

- **WEB-R4. Domain and registrar hygiene** *(reused)* (Transfer, to the
  deployer). Keeping the domain registered avoids the domain case, but not path
  recycling by a platform.
- No response in the specification. `did:web`
  [Deactivate (Revoke)](https://w3c-ccg.github.io/did-method-web/#deactivate-revoke)
  is deletion of the document.

**Remaining threat:** Accepted.

**Responsible party:** deployer; hosting platforms; verifiers, who cannot detect
it.

<a id="web-th7"></a>

#### WEB-TH7. Stale DID Document from Caches

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Tampering
(freshness) · **Elements:** `P2`, `F7`, `D6`

A CDN, reverse proxy, browser cache or resolver cache serves an old `did.json`
after the controller has updated it. A verifier then trusts a key the
controller has rotated out, possibly because it was compromised. The same
effect can be caused deliberately by anyone in control of the host or a cache.
The document carries nothing that would show it is out of date.

**Responses**

- No response in the specification.

**Remaining threat:** Accepted. Controllers can limit it through HTTP cache
headers.

**Responsible party:** deployer (cache configuration); resolver operators
(cache policy).

<a id="web-th8"></a>

#### WEB-TH8. Host Unavailability, Censorship or Exclusion

**Kind:** deployment · **Taxonomy:** STRIDE · **Class:** Denial of Service ·
**Elements:** `C2`, `E5`, `F7`

The DID can be resolved only while its host serves it. A host outage, a
denial-of-service attack, a hosting provider suspending the account or blocking
some regions, or a government ordering removal all make the DID unresolvable.
Because the domain is the identifier, the controller cannot move the DID to
another host without changing the DID, unless they control the domain's DNS.

**Responses**

- No response in the specification.

**Remaining threat:** Accepted.

**Responsible party:** deployer.

<a id="web-th9"></a>

#### WEB-TH9. Path-Based DID Misattributed to the Domain Operator

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D1`, `D4`, `T3`

`did:web:example.com:u:bob` is controlled by whoever controls the path
`/u/bob/`, not by the operator of `example.com`. A verifier who sees the domain
may assume that the domain's owner stands behind the DID. On a shared platform,
any user can create a DID that appears to belong to the platform. The reverse
also holds: the domain operator can change any user's DID ([WEB-TH1](#web-th1)).

**Responses**

- <span id="web-r9"></span>**WEB-R9. Path considerations** (Accept, documented).
  The specification notes that proofs for a path-based DID show control of the
  file at that path, not of the domain. →
  [Optional Path Considerations](https://w3c-ccg.github.io/did-method-web/#optional-path-considerations)

**Remaining threat:** Accepted. Verifiers must not infer endorsement by the
domain operator.

**Responsible party:** verifiers; DID-enabled application developers.

<a id="web-th10"></a>

#### WEB-TH10. Look-Alike Domains

**Kind:** socio-technical · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `D1`, `D4`, `T3`

An attacker registers a domain that looks like a trusted one, such as
`examp1e.com`, or an internationalized domain using characters that resemble
ASCII, and creates a DID there. A user or verifier who checks the DID by eye
accepts it as the trusted party's DID.

**Responses**

- <span id="web-r10"></span>**WEB-R10. Caution with internationalized domain
  names** (Transfer, to implementers). DID Core does not allow Unicode in the
  method-specific identifier, and implementers are told to be cautious with DID
  URLs that rely on Unicode domain names. →
  [International Domain Names](https://w3c-ccg.github.io/did-method-web/#international-domain-names)

**Remaining threat:** Accepted, as for all web URLs. Trust in a DID should come
from how it was received ([`T3`](#ref-did-threat-model)) or from credentials about
it, not from how its domain looks.

**Responsible party:** users; DID-enabled application developers.

<a id="web-th11"></a>

#### WEB-TH11. Resolver Accepts a Document for Another DID

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Spoofing ·
**Elements:** `P4`, `D11`

A resolver that does not check the document's `id`, or that resolves relative
DID URLs inside the document against the wrong base, can be made to return keys
belonging to a different DID. For example, a host serves at one DID's location a
copy of another DID's document.

**Responses**

- <span id="web-r11"></span>**WEB-R11. Check the document `id`** (Eliminate).
  Resolvers **MUST** verify that the `id` of the retrieved document matches the
  DID being resolved. →
  [Read (Resolve)](https://w3c-ccg.github.io/did-method-web/#read-resolve)
- <span id="web-r12"></span>**WEB-R12. Absolute DID URLs** (Eliminate). DID URLs
  in a `did:web` document must be absolute, to prevent key confusion attacks. →
  [Key Material and Document Handling](https://w3c-ccg.github.io/did-method-web/#key-material-and-document-handling)

**Remaining threat:** Implementation errors.

**Responsible party:** resolver implementers.

<a id="web-th12"></a>

#### WEB-TH12. Server-Side Request Forgery through DID Strings

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Elevation of
Privilege, Information Disclosure · **Elements:** `P4`, `C4`, `F7`

A resolver makes an HTTPS request to wherever a DID string points. A service
that resolves DIDs supplied by its users can be made to send requests to
internal hosts, cloud metadata endpoints or `localhost`, through IP literals,
redirects, percent-encoded characters, or host names that resolve to private
addresses.

**Responses**

- <span id="web-r13"></span>**WEB-R13. No IP addresses in the identifier**
  (Reduce). The method-specific identifier **MUST NOT** include IP addresses. This
  does not cover redirects, or host names that resolve to private addresses. →
  [Method-Specific Identifier](https://w3c-ccg.github.io/did-method-web/#method-specific-identifier)

**Remaining threat:** Most SSRF vectors are unaddressed by the specification.

**Responsible party:** resolver implementers and operators.

<a id="web-th13"></a>

#### WEB-TH13. Resource Exhaustion during Resolution

**Kind:** implementation · **Taxonomy:** STRIDE · **Class:** Denial of
Service · **Elements:** `P4`, `C4`, `F7`

A malicious host serves a very large document, or holds the connection open and
sends data slowly. Resolvers that resolve previously unseen DIDs on behalf of
others, such as open verification services, are most exposed.

**Responses**

- No response in the specification. Standard HTTP client limits apply.

**Remaining threat:** Transferred to resolver operators.

**Responsible party:** resolver implementers and operators.

<a id="web-th14"></a>

#### WEB-TH14. Resolution Tracking

**Kind:** privacy · **Taxonomy:** LINDDUN · **Class:** Linkability,
Detectability · **Elements:** `F7`, `F8`, `E5`, `E7`

Every resolution contacts the DID's DNS provider and web host. Both learn which
DIDs are being resolved, when, and from which network address. For an issuer
DID, the issuer's host can learn when and where its credentials are verified.

**Responses**

- **WEB-R6. DNS over HTTPS** *(reused)* (Reduce). Hides the lookup from network
  observers, but not from the DNS resolver operator or the web host. →
  [Read (Resolve)](https://w3c-ccg.github.io/did-method-web/#read-resolve)
- <span id="web-r14"></span>**WEB-R14. Privacy-preserving resolution**
  (Reduce). Use a trusted universal resolver for herd privacy, a VPN, Tor, or
  Oblivious DNS over HTTPS. →
  [DNS Privacy Considerations](https://w3c-ccg.github.io/did-method-web/#dns-privacy-considerations)

**Remaining threat:** The web host always sees requests from whoever fetches the
document.

**Responsible party:** resolver operators; verifiers.
