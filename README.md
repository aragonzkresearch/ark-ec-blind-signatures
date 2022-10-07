# ark-ec-blind-signatures
Blind signatures over elliptic curve implementation (native & r1cs gadgets) using arkworks.

Blind signature over elliptic curves, based on *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* paper by Hamid Mala & Nafiseh Nezhadansari.


> Warning: experimental code, do not use in production.

Target: Groth16 over Bn254 (for Ethereum), so the curve used for the blind signatures is ed-on-bn254 ([BabyJubJub](https://github.com/barryWhiteHat/baby_jubjub)).
