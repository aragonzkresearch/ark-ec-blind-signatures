use crate::schnorr_blind::{ConstraintF, Msg, Parameters, PublicKey, Signature};
use crate::{constraints::BlindSigVerifyGadget, BlindSignatureScheme};

use ark_ec::ProjectiveCurve;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsParameters, FqParameters};
use ark_ff::{fields::Fp256, to_bytes, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::uint8::UInt8,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::GroupOpsBounds,
    prelude::CurveVar,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::ops::Mul;

use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

// hash
use arkworks_native_gadgets::poseidon as poseidon_native;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub pub_key: GC,
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
pub struct MsgVar<const MSG_LEN: usize, C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    m: [FpVar<ConstraintF<C>>; MSG_LEN],
    _gc: PhantomData<GC>,
}
impl<const MSG_LEN: usize, C, GC> MsgVar<MSG_LEN, C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub fn new(m: [FpVar<ConstraintF<C>>; MSG_LEN]) -> Self {
        Self {
            m,
            _gc: PhantomData,
        }
    }
}

impl<const MSG_LEN: usize, C, GC> AllocVar<Msg<MSG_LEN, C>, ConstraintF<C>>
    for MsgVar<MSG_LEN, C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Msg<MSG_LEN, C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|m| {
            let m = m.borrow();
            let cs = cs.into();
            let msg_vec: Vec<FpVar<ConstraintF<C>>> =
                Vec::new_variable(cs, || Ok(m.clone().0), mode)?;
            let m: [FpVar<ConstraintF<C>>; MSG_LEN] =
                msg_vec
                    .try_into()
                    .unwrap_or_else(|v: Vec<FpVar<ConstraintF<C>>>| {
                        // WIP
                        panic!(
                            "Expected Vec of length: {}, actual length: {}",
                            MSG_LEN,
                            v.len()
                        )
                    });
            Ok(Self {
                m,
                _gc: PhantomData,
            })
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
            #[allow(clippy::needless_range_loop)]
            for i in 0..s_bytes.len() {
                s.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(s_bytes[i]),
                    mode,
                )?);
            }

            let r = GC::new_variable(cs, || Ok(val.borrow().r), mode)?;

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
            let generator = GC::new_variable(cs, || Ok(val.borrow().generator), mode)?;
            Ok(Self {
                generator,
                _curve: PhantomData,
            })
        })
    }
}

pub struct BlindSchnorrVerifyGadget<
    const MSG_LEN: usize,
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
> where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    _params: Parameters<C>, // TODO review if needed, maybe delete
    _gc: PhantomData<GC>,
}

impl<
        S: BlindSignatureScheme,
        const MSG_LEN: usize,
        C: ProjectiveCurve,
        GC: CurveVar<C, ConstraintF<C>>,
    > BlindSigVerifyGadget<S, ConstraintF<C>> for BlindSchnorrVerifyGadget<MSG_LEN, C, GC>
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

    ParametersVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::Parameters, <C as ProjectiveCurve>::BaseField>,
    PublicKeyVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::PublicKey, <C as ProjectiveCurve>::BaseField>,
    SignatureVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::Signature, <C as ProjectiveCurve>::BaseField>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;
    type Msg = Msg<MSG_LEN, C>;
    type MsgVar = MsgVar<MSG_LEN, C, GC>;

    fn verify(
        parameters: &ParametersVar<C, GC>,
        poseidon_hash: &PoseidonGadget<ConstraintF<C>>,
        m: &MsgVar<MSG_LEN, C, GC>,
        s: &SignatureVar<C, GC>,
        q: &PublicKeyVar<C, GC>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let sG = parameters
            .generator
            .scalar_mul_le(s.s.to_bits_le()?.iter())?;

        // Note: in a circuit that aggregates multiple verifications, the hashing step could be
        // done outside the signature verification, once for all 1 votes and once for all 0 votes,
        // saving lots of constraints
        let r = EdwardsVar::from(s.r.clone()); // WIP
        let hm = poseidon_hash.hash(&m.m)?;
        let to_hash = [r.x.into(), r.y.into(), hm];
        let h = poseidon_hash.hash(&to_hash)?;

        // G * s == R + H(R, m) * Q
        let RHS = s.r.clone() + q.pub_key.scalar_mul_le(h.to_bits_le()?.iter())?;

        sG.is_eq(&RHS)
    }
}

// example of circuit using BlindSigVerifyGadget to verify a single blind signature
#[derive(Clone)]
pub struct BlindSigVerifyCircuit<
    S: BlindSignatureScheme,
    const MSG_LEN: usize,
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
> where
    <C as ProjectiveCurve>::BaseField: PrimeField,
{
    _s: PhantomData<S>,
    _group: PhantomData<*const GC>,
    pub params: Parameters<C>,
    pub poseidon_hash_native: poseidon_native::Poseidon<ConstraintF<C>>,
    pub signature: Option<Signature<C>>,
    pub pub_key: Option<PublicKey<C>>,
    pub message: Option<Msg<MSG_LEN, C>>,
}

impl<
        S: BlindSignatureScheme,
        const MSG_LEN: usize,
        C: ProjectiveCurve,
        GC: CurveVar<C, ConstraintF<C>>,
    > ConstraintSynthesizer<ConstraintF<C>> for BlindSigVerifyCircuit<S, MSG_LEN, C, GC>
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

    ParametersVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::Parameters, <C as ProjectiveCurve>::BaseField>,
    PublicKeyVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::PublicKey, <C as ProjectiveCurve>::BaseField>,
    SignatureVar<C, GC>:
        AllocVar<<S as BlindSignatureScheme>::Signature, <C as ProjectiveCurve>::BaseField>,

    Parameters<C>: Borrow<<S as BlindSignatureScheme>::Parameters>,
    PublicKey<C>: Borrow<<S as BlindSignatureScheme>::PublicKey>,
    Signature<C>: Borrow<<S as BlindSignatureScheme>::Signature>,
{
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let parameters =
            ParametersVar::new_constant(ark_relations::ns!(cs, "parameters"), self.params)?;

        let pub_key =
            PublicKeyVar::<C, GC>::new_input(ark_relations::ns!(cs, "public key"), || {
                self.pub_key.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let m = MsgVar::<MSG_LEN, C, GC>::new_input(ark_relations::ns!(cs, "message"), || {
            self.message.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let signature =
            SignatureVar::<C, GC>::new_witness(ark_relations::ns!(cs, "signature"), || {
                self.signature.ok_or(SynthesisError::AssignmentMissing)
            })?;
        #[allow(clippy::redundant_clone)]
        let poseidon_hash = PoseidonGadget::<ConstraintF<C>>::from_native(
            &mut cs.clone(),
            self.poseidon_hash_native,
        )
        .unwrap();

        let v = <BlindSchnorrVerifyGadget<MSG_LEN, C, GC> as BlindSigVerifyGadget<
            S,
            ConstraintF<C>,
        >>::verify(&parameters, &poseidon_hash, &m, &signature, &pub_key)?;
        v.enforce_equal(&Boolean::TRUE)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::schnorr_blind::{poseidon_setup_params, SchnorrBlindSig};
    use crate::BlindSignatureScheme;
    use ark_ed_on_bn254::constraints::EdwardsVar as BabyJubJubVar;
    use ark_ed_on_bn254::EdwardsProjective as BabyJubJub;

    use arkworks_native_gadgets::poseidon;
    use arkworks_utils::Curve;

    use ark_relations::r1cs::ConstraintSystem;

    type Fq = <BabyJubJub as ProjectiveCurve>::BaseField;
    // type Fr = <BabyJubJub as ProjectiveCurve>::ScalarField;
    type S = SchnorrBlindSig<BabyJubJub>;

    fn generate_single_sig_native_data(
        poseidon_hash: &poseidon::Poseidon<Fq>,
    ) -> (
        Parameters<BabyJubJub>,
        PublicKey<BabyJubJub>,
        Msg<3, BabyJubJub>,
        Signature<BabyJubJub>,
    ) {
        let mut rng = ark_std::test_rng();
        let params = S::setup(poseidon_hash);
        let (pk, sk) = S::keygen(&params, &mut rng);
        let (k, signer_r) = S::new_request_params(&params, &mut rng);
        let m = [Fq::from(1234), Fq::from(5689), Fq::from(3456)];
        let (m_blinded, u) = S::blind(&params, &mut rng, &m, pk, signer_r).unwrap();
        let s_blinded = S::blind_sign(sk, k, m_blinded);
        let s = S::unblind(s_blinded, &u);
        let verified = S::verify(&params, &m, s.clone(), pk);
        assert!(verified);
        (params, pk, Msg(m), s)
    }

    #[test]
    fn test_single_verify() {
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);
        const MSG_LEN: usize = 3;

        // create signature using native-rust lib
        let (params, pk, m, s) = generate_single_sig_native_data(&poseidon_hash);

        // use the constraint system to verify the signature
        let cs = ConstraintSystem::<Fq>::new_ref();

        let params_var =
            ParametersVar::<BabyJubJub, BabyJubJubVar>::new_constant(cs.clone(), params).unwrap();
        let signature_var =
            SignatureVar::<BabyJubJub, BabyJubJubVar>::new_witness(cs.clone(), || Ok(&s)).unwrap();
        let pk_var =
            PublicKeyVar::<BabyJubJub, BabyJubJubVar>::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let m_var = MsgVar::<MSG_LEN, BabyJubJub, BabyJubJubVar>::new_witness(cs.clone(), || Ok(m))
            .unwrap();
        let poseidon_hash_var =
            PoseidonGadget::<Fq>::from_native(&mut cs.clone(), poseidon_hash).unwrap();

        let valid_sig =
            <BlindSchnorrVerifyGadget<MSG_LEN, BabyJubJub, BabyJubJubVar> as BlindSigVerifyGadget<
                S,
                ConstraintF<BabyJubJub>,
            >>::verify(
                &params_var,
                &poseidon_hash_var,
                &m_var,
                &signature_var,
                &pk_var,
            )
            .unwrap();
        valid_sig.enforce_equal(&Boolean::<Fq>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_single_verify_constraint_system() {
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);
        const MSG_LEN: usize = 3;

        // create signature using native-rust lib
        let (params, pk, m, s) = generate_single_sig_native_data(&poseidon_hash);

        // use the constraint system to verify the signature
        let circuit = BlindSigVerifyCircuit::<S, MSG_LEN, BabyJubJub, BabyJubJubVar> {
            params,
            poseidon_hash_native: poseidon_hash.clone(),
            signature: Some(s),
            pub_key: Some(pk),
            message: Some(m),
            _group: PhantomData,
            _s: PhantomData,
        };
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        println!("num_constraints={:?}", cs.num_constraints());
    }
}
