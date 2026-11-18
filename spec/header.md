The did:webvh Threat Model
==================

**Status:** Editor's Draft. This document is a work in progress and is not yet
endorsed by the `did:webvh` Work Item.

**Specification Modeled:**
[The `did:webvh` DID Method v1.0](https://identity.foundation/didwebvh/v1.0/).
The [Editor's Draft](https://identity.foundation/didwebvh/next/) of the
specification has diverged from v1.0. Where a difference matters to a threat, it
is recorded as an [open item](#open-items) rather than modeled.

**Latest Draft:**
  [https://github.com/decentralized-identity/didwebvh-threat-model](https://github.com/decentralized-identity/didwebvh-threat-model)

**Information Site:**
  [https://didwebvh.info/](https://didwebvh.info/)

**Editors:**
~ [Stephen Curran](https://github.com/swcurran)

**Participate:**
~ [GitHub repo](https://github.com/decentralized-identity/didwebvh-threat-model)
~ [File a bug](https://github.com/decentralized-identity/didwebvh-threat-model/issues)
~ [Commit history](https://github.com/decentralized-identity/didwebvh-threat-model/commits/main)

------------------------------------

## Abstract

This document is a threat model for the `did:webvh` DID Method v1.0. It follows
the [W3C Threat Modeling Guide](#ref-threat-modeling-guide) and is built as a
stack of layers:

1. the [DID Threat Model](#ref-did-threat-model), which describes threats common
   to all DID methods and which this document references rather than repeats;
2. a model of [`did:web`](#ref-did-web), the method `did:webvh` extends;
3. a model of `did:webvh` as most controllers first deploy it, without
   witnesses, watchers or DNS-linking;
4. a model of `did:webvh` with witnesses, watchers and DNS-linking added.

Each layer has its own data flow diagram and its own threats. Each later layer
lists only the threats it adds, and records for every threat of the layers below
whether it still applies, is changed, is mitigated or is superseded.

No threat model for `did:web` has been published, so Layer 2 is written to
stand alone as one. If a formal `did:web` threat model is published, Layer 2
will be replaced with a reference to it, and the later layers will link to that
model's threats instead.

The layering shows where each of `did:webvh`'s security properties comes from.
The self-certifying identifier, hash-chained log and pre-rotation (Layer 3) move
the integrity of the DID out of the web host's hands. Witnesses and watchers
(Layer 4) address what remains: forked, withheld or rewritten history.
