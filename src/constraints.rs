use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::BlindSignatureScheme;
use ark_ff::PrimeField;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;

pub trait BlindSigVerifyGadget<S: BlindSignatureScheme, ConstraintF: PrimeField> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<S::PublicKey, ConstraintF> + Clone;
    type SignatureVar: AllocVar<S::Signature, ConstraintF> + Clone;
    type Msg;
    type MsgVar: AllocVar<Self::Msg, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        poseidon_hash: &PoseidonGadget<ConstraintF>,
        m: &Self::MsgVar,
        s: &Self::SignatureVar,
        q: &Self::PublicKeyVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}
