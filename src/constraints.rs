use crate::{Parameters, PublicKey, Signature};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsParameters, FqParameters};
use ark_ff::{
    fields::{Field, Fp256},
    to_bytes, PrimeField, ToConstraintField,
};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::uint8::UInt8,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::{curves::twisted_edwards::AffineVar, GroupOpsBounds},
    prelude::CurveVar,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::ops::{Add, Mul};

use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

// hash
use arkworks_native_gadgets::poseidon as poseidon_native;
use arkworks_r1cs_gadgets::poseidon;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar};

use crate::ConstraintF;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    s: Vec<UInt8<ConstraintF<C>>>,
    r: GC,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // let s = val.borrow().s;
            let mut s = Vec::<UInt8<ConstraintF<C>>>::new();
            let s_bytes = to_bytes![val.borrow().s].unwrap();
            for i in 0..s_bytes.len() {
                s.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(s_bytes[i].clone()),
                    mode,
                )?);
            }

            let r = GC::new_variable(cs.clone(), || Ok(val.borrow().r), mode)?;

            Ok(Self {
                s,
                r,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            Ok(Self {
                generator,
                _curve: PhantomData,
            })
        })
    }
}

pub struct BlindSigVerifyGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    _params: Parameters<C>, // TODO review if needed, maybe delete
    _gc: PhantomData<GC>,
}

impl<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>> BlindSigVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
    ark_r1cs_std::groups::curves::twisted_edwards::AffineVar<
        EdwardsParameters,
        FpVar<Fp256<FqParameters>>,
    >: From<GC>,
    <C as ProjectiveCurve>::BaseField: PrimeField,
    FpVar<<C as ProjectiveCurve>::BaseField>: Mul<FpVar<Fp256<FqParameters>>>,
    FpVar<<C as ProjectiveCurve>::BaseField>: From<FpVar<Fp256<FqParameters>>>,
{
    fn verify(
        parameters: &ParametersVar<C, GC>,
        poseidon_hash: &PoseidonGadget<ConstraintF<C>>,
        m: FpVar<ConstraintF<C>>,
        s: &SignatureVar<C, GC>,
        q: &PublicKeyVar<C, GC>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let s_s = s.s.clone();

        let sG = parameters
            .generator
            .scalar_mul_le(s_s.to_bits_le()?.iter())?;

        // Note: in a circuit that aggregates multiple verifications, the hashing step could be
        // done outside the signature verification, once for all 1 votes and once for all 0 votes,
        // saving lots of constraints
        let hm = poseidon_hash.hash(&[m])?;
        let r = EdwardsVar::from(s.r.clone()); // WIP
        let rx_fpvar: FpVar<ConstraintF<C>> = r.x.into();

        // G * s == R + Q * (R.x * H(m))
        let Q_rx_hm_0 = q.pub_key.scalar_mul_le(rx_fpvar.to_bits_le()?.iter())?;
        let Q_rx_hm = Q_rx_hm_0.scalar_mul_le(hm.to_bits_le()?.iter())?;
        let RHS = s.r.clone() + Q_rx_hm;

        sG.is_eq(&RHS)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{poseidon_setup_params, BlindSigScheme};
    use ark_ed_on_bn254::constraints::EdwardsVar as BabyJubJubVar;
    use ark_ed_on_bn254::EdwardsProjective as BabyJubJub;

    use arkworks_native_gadgets::poseidon;
    use arkworks_utils::Curve;

    use ark_relations::r1cs::ConstraintSystem;

    type Fq = <BabyJubJub as ProjectiveCurve>::BaseField;
    // type Fr = <BabyJubJub as ProjectiveCurve>::ScalarField;
    type S = BlindSigScheme<BabyJubJub>;

    #[test]
    fn test_verify() {
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 3);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);
        let mut rng = ark_std::test_rng();

        // create signature using native-rust lib
        let params = S::setup();
        let (pk, sk) = S::keygen(&params, &mut rng);
        let (k, signer_r) = S::new_request_params(&params, &mut rng);
        let m = Fq::from(1234);
        let (m_blinded, u) = S::blind(&params, &mut rng, &poseidon_hash, m, signer_r).unwrap();
        let s_blinded = S::blind_sign(sk, k, m_blinded);
        let s = S::unblind(s_blinded, u);
        let verified = S::verify(&params, &poseidon_hash, m, s.clone(), pk);
        assert!(verified);

        // use the constraint system to verify the signature
        type SG = BlindSigVerifyGadget<BabyJubJub, BabyJubJubVar>;
        let cs = ConstraintSystem::<Fq>::new_ref();

        let params_var =
            ParametersVar::<BabyJubJub, BabyJubJubVar>::new_constant(cs.clone(), params).unwrap();
        let signature_var =
            SignatureVar::<BabyJubJub, BabyJubJubVar>::new_witness(cs.clone(), || Ok(&s)).unwrap();
        let pk_var =
            PublicKeyVar::<BabyJubJub, BabyJubJubVar>::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let m_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&m)).unwrap();
        let poseidon_hash_var =
            PoseidonGadget::<Fq>::from_native(&mut cs.clone(), poseidon_hash).unwrap();

        let valid_sig = SG::verify(
            &params_var,
            &poseidon_hash_var,
            m_var,
            &signature_var,
            &pk_var,
        )
        .unwrap();
        valid_sig.enforce_equal(&Boolean::<Fq>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
