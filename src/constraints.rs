use crate::{Parameters, Signature};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsParameters, FqParameters};
use ark_ff::{
    fields::{Field, Fp256},
    to_bytes, ToConstraintField,
};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::uint8::UInt8,
    boolean::Boolean,
    fields::fp::FpVar,
    groups::{curves::twisted_edwards::AffineVar, GroupOpsBounds},
    prelude::CurveVar,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::ops::Mul;

use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

// hash
use arkworks_r1cs_gadgets::poseidon;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

// type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
type ConstraintF<C> = <C as ProjectiveCurve>::ScalarField; // Fr

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

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    // s: FpVar<ConstraintF>,
    // s: C::ScalarField,
    s: Vec<UInt8<ConstraintF<C>>>,
    r: GC,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: ProjectiveCurve,
    // TODO not sure on '+ AllocVarar'
    GC: CurveVar<C, ConstraintF<C>> + AllocVar<GC, ConstraintF<C>>,
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
                s: s, // TODO not sure of FpVar::Constant
                r: r,
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
    params: Parameters<C>,
    // sig: Signature<C>,
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
    FpVar<<C as ProjectiveCurve>::ScalarField>: Mul<FpVar<Fp256<FqParameters>>>,
    FpVar<<C as ProjectiveCurve>::ScalarField>: From<<C as ProjectiveCurve>::ScalarField>,
{
    fn verify(
        parameters: &ParametersVar<C, GC>,
        poseidon_hash: &PoseidonGadget<ConstraintF<C>>,
        m: FpVar<ConstraintF<C>>,
        s: &SignatureVar<C, GC>,
        q: &PublicKeyVar<C, GC>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError>
    where
        <C as ProjectiveCurve>::ScalarField: Iterator, // WIP
        <C as ProjectiveCurve>::ScalarField: From<
            <FpVar<<C as ProjectiveCurve>::ScalarField> as Mul<FpVar<Fp256<FqParameters>>>>::Output,
        >,
    {
        let s_s = s.s.clone();

        let sG = parameters
            .generator
            .scalar_mul_le(s_s.to_bits_le()?.iter())?;

        // G * s == R + Q * (R.x * H(m))
        // Note: in a circuit that aggregates multiple verifications, the hashing step could be
        // done outside the signature verification, once for all 1 votes and once for all 0 votes,
        // saving lots of constraints
        let hm = poseidon_hash.hash(&[m])?;
        let r = EdwardsVar::from(s.r.clone()); // WIP

        let rx_hm: ConstraintF<C> = ConstraintF::<C>::from(hm * r.x);
        let rx_hm_fp: FpVar<ConstraintF<C>> = FpVar::<ConstraintF<C>>::from(rx_hm);

        let Q_rx_hm = q.pub_key.scalar_mul_le(rx_hm_fp.to_bits_le()?.iter())?;
        let RHS = s.r.clone() + Q_rx_hm;

        sG.is_eq(&RHS)
    }
}
