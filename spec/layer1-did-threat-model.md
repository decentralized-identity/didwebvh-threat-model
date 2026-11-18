## Layer 1: The DID Threat Model

The W3C Decentralized Identifier Working Group's
[DID Threat Model](#ref-did-threat-model) is the foundation of this document. It
models DIDs and DID resolution in general, as defined by DID Core and DID
Resolution, without reference to any one DID method. This document does not
repeat it.

From the DID Threat Model, this document takes:

- **The system model.** Its data flow diagram of a DID controller, a
  DID-enabled application, a resolver and Verifiable Data Registry (VDR) nodes,
  and the element IDs (`E1`–`E6`, `C1`–`C5`, `P1`–`P5`, `D1`–`D10`, `F1`–`F7`)
  used throughout this document.
- **The trust boundaries:**
  - `T1` **VDR trust boundary**: trust in the VDR and the services used to update
    and read it.
  - `T2` **Resolution trust boundary**: trust in the resolver chosen by the DID URL
    User.
  - `T3` **DID URL trust boundary**: trust that a DID URL came from an authentic
    source.
- **The stakeholders:** the DID Controller (`E1`), DID URL User (`E2`), DID URL
  Author (`E3`), Resolver Service Provider (`E4`) and VDR service providers
  (`E5`, `E6`). Later layers describe only what changes for each.
- **The threat entry format** and the convention for reused responses.

The DID Threat Model deliberately leaves three flows to each method: how the DID
is managed (`F1`), how VDR state is updated (`F2`) and how VDR nodes stay
synchronized (`F3`). Layers 2 to 4 supply those flows for `did:web` and
`did:webvh`, and with them the method-specific threats.

### What a Method Threat Model Should Do

The DID Threat Model invites method-specific threat models. Following it and the
[W3C Threat Modeling Guide](#ref-threat-modeling-guide), this document aims to:

- start from the DID Threat Model's diagram and make the method-specific flows
  concrete, keeping its element IDs;
- show where the method changes a trust boundary, especially `T1`, since the
  VDR is where DID methods differ most;
- describe threats in terms of the stakeholders who are harmed, not only the
  components attacked;
- tie every response to the specification text that provides it, and say
  plainly when there is none;
- state what threat remains after the responses, and who owns it.

### Generic Threats

At the time of writing, the DID Threat Model defines its system model and
stakeholders, and its list of threats is still being developed. Threats that
apply to every DID method, rather than to `did:web` or `did:webvh` in particular,
belong there and are not modeled here. Examples include:

- an untrustworthy remote resolver (`T2`);
- a malicious or mistaken DID URL (`T3`);
- disclosure and correlation through public DID documents.

Where `did:webvh` changes one of these, the relevant layer says so. For example,
because a `did:webvh` DID Log can be verified by any client, a DID-enabled
application can collapse `T2` by verifying the log itself.

::: note
When the DID Threat Model publishes threat IDs, generic threats referenced in
this document will link to them.
:::
