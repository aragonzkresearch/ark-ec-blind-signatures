# ark-ec-blind-signatures [![Test](https://github.com/aragonzkresearch/ark-ec-blind-signatures/workflows/Test/badge.svg)](https://github.com/aragonzkresearch/ark-ec-blind-signatures/actions?query=workflow%3ATest) [![Clippy](https://github.com/aragonzkresearch/ark-ec-blind-signatures/workflows/Clippy/badge.svg)](https://github.com/aragonzkresearch/ark-ec-blind-signatures/actions?query=workflow%3AClippy)

> Warning: experimental code, do not use in production.

[Blind signature](https://en.wikipedia.org/wiki/Blind_signature) over elliptic curve implementation (native & r1cs constraints) using [arkworks](https://github.com/arkworks-rs).

Schemes implemented:
- mala_nezhadansari: *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* paper by Hamid Mala, Nafiseh Nezhadansari. Note that in this scheme signatures are malleable. Number of constraints for the verification: 9785.
- shcnorr_blind: *"[Blind Schnorr Signatures and Signed ElGamal Encryption in the Algebraic Group Model](https://eprint.iacr.org/2019/877)"* paper by Georg Fuchsbauer, Antoine Plouviez, and Yannick Seurin. Number of constraints for the verification: 6052.


Target: Groth16 over Bn254 (for Ethereum), ed-on-bn254 ([BabyJubJub](https://github.com/barryWhiteHat/baby_jubjub)) for the signatures.
