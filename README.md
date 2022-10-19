# ark-ec-blind-signatures [![Test](https://github.com/aragonzkresearch/ark-ec-blind-signatures/workflows/Test/badge.svg)](https://github.com/aragonzkresearch/ark-ec-blind-signatures/actions?query=workflow%3ATest) [![Clippy](https://github.com/aragonzkresearch/ark-ec-blind-signatures/workflows/Clippy/badge.svg)](https://github.com/aragonzkresearch/ark-ec-blind-signatures/actions?query=workflow%3AClippy)

Blind signatures over elliptic curve implementation (native & r1cs constraints) using arkworks.

[Blind signature](https://en.wikipedia.org/wiki/Blind_signature) over elliptic curves, based on *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* paper by Hamid Mala & Nafiseh Nezhadansari.


> Warning: experimental code, do not use in production.

Target: Groth16 over Bn254 (for Ethereum), ed-on-bn254 ([BabyJubJub](https://github.com/barryWhiteHat/baby_jubjub)) for the signatures.
