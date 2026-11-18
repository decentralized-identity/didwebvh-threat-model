## Introduction

### Purpose

`did:webvh` ("did:web + Verifiable History") keeps the simple deployment of a
DID published on a web server and adds:

- a self-certifying identifier (SCID);
- a hash-chained, signed log of every version of the DID;
- pre-rotation of the keys that authorize updates;
- optional witnesses, who approve each version before it is published;
- optional watchers, who keep copies of the log independently of the host.

This threat model explains what each of those features protects against, what
they do not protect against, and who is responsible for what remains. For each
threat, it links to the section of the specification that provides each
response. Where no section does, it says so and records whether the threat is
transferred to another party or accepted.

The intended readers are:

- implementers of `did:webvh` controllers, resolvers, witnesses and watchers;
- DID controllers and ecosystem governance authorities choosing how to deploy
  `did:webvh`;
- reviewers of the `did:webvh` specification.

### Method

This model follows the [W3C Threat Modeling Guide](#ref-threat-modeling-guide)
and uses the conventions of the [DID Threat Model](#ref-did-threat-model). For
each layer it gives:

- a **system model**: a data flow diagram, a short description, and a dictionary
  of the elements the layer adds or changes;
- **stakeholder** notes, for stakeholders the layer adds or affects;
- the **dispositions** of threats from the layers below;
- the **new threats** the layer introduces, each with responses.

The threat lists are curated, not exhaustive. As the Guide recommends, they aim
for a well-told set of the most significant threats rather than a complete
catalogue.

### The Layers

| Layer | Models | Adds |
|---|---|---|
| [1](#layer-1-the-did-threat-model) | Any DID method | Reference only: generic DID architecture, stakeholders and trust boundaries `T1`–`T3`. |
| [2](#layer-2-didweb) | `did:web` | A web server as the registry; DNS and Web PKI as a dependency. |
| [3](#layer-3-didwebvh) | `did:webvh` without witnesses, watchers or DNS-linking | SCID, DID Log, pre-rotation, DID URL path resources, parallel `did:web`. |
| [4](#layer-4-didwebvh-with-witnesses-watchers-and-dns-linking) | `did:webvh` with witnesses, watchers and DNS-linking | Witnesses, watchers, and a `_did` DNS record linking the domain to the DID. |

Layer 3 is a complete, conformant `did:webvh` deployment. Witnesses, watchers and
DNS-linking are each optional, and each can be added on its own. Layer 4 shows
them together, but each of its threats and dispositions names the feature it
depends on.

### Element IDs

- Element IDs carried over from the [DID Threat Model](#ref-did-threat-model)
  keep their IDs: `E1`–`E6`, `C1`–`C5`, `P1`–`P5`, `D1`–`D10`, `F1`–`F7` and
  trust boundaries `T1`–`T3`.
- Each layer numbers the elements it adds by continuing the series, so an
  element's ID is the same in every layer in which it appears. One `D` series
  covers both data stores and data objects.
- In each layer's dictionary and diagram:
  - **\*** marks an element new in that layer;
  - **†** marks an element whose meaning changes in that layer;
  - elements in teal are new or changed in that layer.
- Trust boundaries use `T#`, as in the DID Threat Model. Threats and responses
  carry a layer prefix so they cannot be confused with boundaries.

### Threat and Response IDs

| Layer | Threats | Responses |
|---|---|---|
| 2: `did:web` | `WEB-TH1`, `WEB-TH2`, … | `WEB-R1`, `WEB-R2`, … |
| 3: `did:webvh` | `WVH-TH1`, … | `WVH-R1`, … |
| 4: `did:webvh` with witnesses, watchers and DNS-linking | `WVX-TH1`, … | `WVX-R1`, … |

A response used by more than one threat keeps the ID of its first use and is
marked *(reused)*, as in the DID Threat Model.

### Threat Entry Format

Each threat uses the fields of the [DID Threat Model](#ref-did-threat-model),
plus a strategy for each response and a statement of what remains:

- **Name and ID.**
- **Kind:** target, implementation, deployment, dependency, socio-technical or
  privacy, following the groupings of the
  [W3C Threat Modeling Guide](#ref-threat-modeling-guide).
- **Taxonomy and class:** STRIDE for security threats, LINDDUN for privacy
  threats.
- **Elements:** IDs of the affected elements.
- **Description.**
- **Responses:** each with an ID, a strategy and a link to the specification
  section that provides it. The strategies are:
  - **Eliminate:** the threat cannot occur when the response is implemented;
  - **Reduce:** the threat is less likely or less harmful;
  - **Transfer:** responsibility rests with another party, such as the deployer,
    the user or ecosystem governance;
  - **Accept:** the threat remains, and is documented.
- **Compromises required.** Where a response means an attacker must succeed at
  more than one independent compromise to succeed undetected, such as stealing
  a key *and* gaining write access to the web host, the entry says so. It also
  says when those compromises are not in fact independent, for example when one
  provider or account runs both. The combined effect across layers is summarized
  in [What an Attacker Must Compromise](#what-an-attacker-must-compromise).
- **Remaining threat** and the **responsible party**: implementer, deployer,
  governance or user.

### Dispositions

Each layer records what happens to every threat from the layers below it, using
one of:

| Disposition | Meaning |
|---|---|
| **Applies** | The threat applies unchanged. Its responses still apply. |
| **Changed** | The threat still applies, but its scope or its responses change. The change is described. |
| **Mitigated** | The layer's responses eliminate the threat or reduce it to something minor. The responses are named. |
| **Superseded** | The threat no longer applies as written. It is replaced by one or more new threats in this layer. |

A threat is never repeated in a later layer. Its entry stays in the layer that
introduced it, and the later layer links to it.

### Diagram Legend

All three diagrams use the notation of the
[W3C Threat Modeling Guide](#ref-threat-modeling-guide):

- rectangle: external entity;
- circle or ellipse: process;
- two parallel lines: data store;
- dog-eared page: data object;
- solid arrow: data flow;
- dotted arrow: dependency flow;
- dashed rounded box: container;
- small boxed label: trust boundary crossing;
- teal, with `*` or `†`: element new or changed in that layer.

Attackers are not drawn.
