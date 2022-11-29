use ark_std::rand::Rng;

pub mod mala_nezhadansari;
pub mod schnorr_blind;

use ark_ff::PrimeField;
use arkworks_native_gadgets::poseidon;

pub trait BlindSignatureScheme {
    type Parameters;
    type Fq;
    type Fr;
    type ConstraintF: PrimeField;
    type PointAffine;
    type SecretKey;
    type PublicKey;
    type BlindedSignature;
    type Signature;
    type UserSecretData;

    fn setup(hash: &poseidon::Poseidon<Self::ConstraintF>) -> Self::Parameters;

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey);

    fn new_request_params<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> (Self::Fr, Self::PointAffine);

    fn blind_sign(sk: Self::SecretKey, r: Self::Fr, m_blinded: Self::Fr) -> Self::BlindedSignature;

    fn unblind(s_blinded: Self::Fr, u: &Self::UserSecretData) -> Self::Signature;

    fn non_blind_sign<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
        sk: Self::SecretKey,
        m: &[Self::ConstraintF],
    ) -> Result<Self::Signature, ark_crypto_primitives::Error>;

    fn blind<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
        m: &[Self::ConstraintF],
        signer_pk: Self::PublicKey,
        signer_r: Self::PointAffine,
    ) -> Result<(Self::Fr, Self::UserSecretData), ark_crypto_primitives::Error>;

    fn verify(
        parameters: &Self::Parameters,
        m: &[Self::ConstraintF],
        s: Self::Signature,
        q: Self::PublicKey,
    ) -> bool;
}
