#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]

// #[cfg(feature="r1cs")]
pub mod constraints;

use ark_ec::{models::twisted_edwards_extended::GroupAffine, AffineCurve, ProjectiveCurve};

use ark_ff::{to_bytes, BigInteger256, Field, Fp256, FpParameters, PrimeField};

use ark_std::marker::PhantomData;
use ark_std::{rand::Rng, UniformRand};
use derivative::Derivative;

// hash
use arkworks_native_gadgets::poseidon;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};

// WIP
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters, FqParameters};

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
pub type SecretKey<C> = <C as ProjectiveCurve>::ScalarField;
pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;
pub type BlindedSignature<C> = <C as ProjectiveCurve>::ScalarField;

// #[derive(Derivative)]
#[derive(Clone, Default, Debug)]
pub struct Signature<C: ProjectiveCurve> {
    s: C::ScalarField, // ScalarField == Fr
    r: <C as ProjectiveCurve>::Affine,
}

#[derive(Clone, Default, Debug)]
pub struct UserSecretData<C: ProjectiveCurve> {
    alpha: C::ScalarField,
    beta: C::ScalarField,
    R: C::Affine,
}
impl<C: ProjectiveCurve> UserSecretData<C> {
    fn new_empty(parameters: &Parameters<C>) -> Self {
        UserSecretData {
            alpha: C::ScalarField::from(0_u32),
            beta: C::ScalarField::from(0_u32),
            R: parameters.generator, // WIP
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve"), Debug)]
pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

pub struct BlindSigScheme<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

impl<C: ProjectiveCurve> BlindSigScheme<C>
where
    C::ScalarField: PrimeField,
    GroupAffine<EdwardsParameters>: From<<C as ProjectiveCurve>::Affine>, // WIP
{
    pub fn setup() -> Parameters<C> {
        let generator = C::prime_subgroup_generator().into();
        Parameters { generator }
    }

    // signer
    pub fn keygen<R: Rng>(parameters: &Parameters<C>, rng: &mut R) -> (PublicKey<C>, SecretKey<C>) {
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();
        (public_key, secret_key)
    }

    pub fn new_request_params<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
    ) -> (C::ScalarField, C::Affine) {
        let r = C::ScalarField::rand(rng);
        let R_ = parameters.generator.mul(r).into();
        (r, R_)
    }

    pub fn blind_sign(
        sk: SecretKey<C>,
        r: C::ScalarField,
        m_blinded: C::ScalarField,
    ) -> BlindedSignature<C> {
        r + m_blinded * sk
    }

    // new_k_and_R returns a new k \in Fr, and R=k * G, such that R.x \in Fr
    fn new_k_and_R<R: Rng>(parameters: &Parameters<C>, rng: &mut R) -> (C::ScalarField, C::Affine)
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
    {
        // TODO, for schorr, the H(R, m) needs to be \in Fr, not R.x
        let k = C::ScalarField::rand(rng);

        let R: C::Affine = parameters.generator.mul(k.into_repr()).into();
        let r = EdwardsAffine::from(R); // WIP

        let one = BigInteger256::from(1u64);
        let x_repr = r.x.into_repr();
        let modulus = <<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS;
        let modulus_repr = BigInteger256::try_from(modulus.into()).unwrap();

        if !(x_repr >= one && x_repr < modulus_repr) {
            // TODO maybe add a counter of attempts with a limit
            return Self::new_k_and_R(parameters, rng);
        }

        (k, R)
    }

    // non_blind_sign performs a non-blind signature, which can be verified with the same check
    // than a blind-signature
    pub fn non_blind_sign<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
        poseidon_hash: &poseidon::Poseidon<ConstraintF<C>>,
        sk: SecretKey<C>,
        m: &[ConstraintF<C>],
    ) -> Result<Signature<C>, ark_crypto_primitives::Error>
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
        <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField: From<Fp256<FqParameters>>,
    {
        let (r, R) = Self::new_k_and_R(parameters, rng);
        let R_ed = EdwardsAffine::from(R); // WIP

        let hm = poseidon_hash.hash(m)?;
        let to_hash: [ConstraintF<C>; 3] = [R_ed.x.into(), R_ed.y.into(), hm];
        let h = poseidon_hash.hash(&to_hash)?;
        let h_fr = C::ScalarField::from_le_bytes_mod_order(&to_bytes!(h)?); // WIP TMP

        let s = r + h_fr * sk;
        Ok(Signature { s, r: R })
    }

    // requester
    pub fn new_blind_params<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
        signer_pk: PublicKey<C>,
        signer_r: C::Affine,
    ) -> UserSecretData<C>
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
    {
        let mut u: UserSecretData<C> = UserSecretData::new_empty(parameters);
        u.alpha = C::ScalarField::rand(rng);
        u.beta = C::ScalarField::rand(rng);

        // R = R' + alpha * G + beta * X
        let alphaG = parameters.generator.mul(u.alpha.into_repr());
        let betaPk = signer_pk.mul(u.beta.into_repr());
        u.R = signer_r + alphaG.into_affine() + betaPk.into_affine();

        let R = EdwardsAffine::from(u.R); // WIP
        let one = BigInteger256::from(1u64);
        let x_repr = R.x.into_repr();
        let modulus = <<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS;
        let modulus_repr = BigInteger256::try_from(modulus.into()).unwrap();

        if !(x_repr >= one && x_repr < modulus_repr) {
            // TODO maybe add a counter of attempts with a limit
            return Self::new_blind_params(parameters, rng, signer_pk, signer_r);
        }
        u
    }

    pub fn blind<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
        poseidon_hash: &poseidon::Poseidon<ConstraintF<C>>,
        m: &[ConstraintF<C>],
        signer_pk: PublicKey<C>,
        signer_r: C::Affine,
    ) -> Result<(C::ScalarField, UserSecretData<C>), ark_crypto_primitives::Error>
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
        <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField: From<Fp256<FqParameters>>,
    {
        let u = Self::new_blind_params(parameters, rng, signer_pk, signer_r);

        // get X coordinate, as in new_blind_params we already checked that R.x is inside Fr and
        // will not overflow (giving None)
        let r = EdwardsAffine::from(u.R); // WIP

        // m' = H(R, m) + beta
        // TODO hash(R, m) must be \in Fr
        let hm_0 = poseidon_hash.hash(m)?;
        let to_hash: [ConstraintF<C>; 3] = [r.x.into(), r.y.into(), hm_0];
        let h = poseidon_hash.hash(&to_hash)?;
        let h_fr = C::ScalarField::from_le_bytes_mod_order(&to_bytes!(h)?); // WIP TMP
        let m_blinded = h_fr + u.beta;

        Ok((m_blinded, u))
    }

    pub fn unblind(s_blinded: C::ScalarField, u: &UserSecretData<C>) -> Signature<C> {
        // s = s' + alpha
        let s = s_blinded + u.alpha;
        Signature { s, r: u.R }
    }

    pub fn verify(
        parameters: &Parameters<C>,
        poseidon_hash: &poseidon::Poseidon<ConstraintF<C>>,
        m: &[ConstraintF<C>],
        s: Signature<C>,
        q: PublicKey<C>,
    ) -> bool
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
        <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField: From<Fp256<FqParameters>>,
    {
        let sG = parameters.generator.mul(s.s.into_repr());

        let r = EdwardsAffine::from(s.r); // WIP

        // TODO the output of hash(R, m) must be \in Fr
        let hm_0 = poseidon_hash.hash(m).unwrap();
        let to_hash: [ConstraintF<C>; 3] = [r.x.into(), r.y.into(), hm_0];
        let h = poseidon_hash.hash(&to_hash).unwrap();
        let h_fr = C::ScalarField::from_le_bytes_mod_order(&to_bytes!(h).unwrap()); // WIP TMP

        // TODO the output of hash(R, m) must be \in Fr
        let one = BigInteger256::from(1u64);
        let x_repr = r.x.into_repr();
        let modulus = <<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS;
        let modulus_repr = BigInteger256::try_from(modulus.into()).unwrap();
        if !(x_repr >= one && x_repr < modulus_repr) {
            return false;
        }
        let right = s.r + q.mul(h_fr.into_repr()).into_affine();

        sG.into_affine() == right
    }
}

// poseidon
pub fn poseidon_setup_params<F: PrimeField>(
    curve: Curve,
    exp: i8,
    width: u8,
) -> poseidon::PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    poseidon::PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: poseidon::sbox::PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::EdwardsProjective;
    pub type Fq = ark_ed_on_bn254::Fq; // base field
                                       // pub type Fr = ark_ed_on_bn254::Fr; // scalar field

    #[test]
    fn test_blind_signature_flow_native() {
        type S = BlindSigScheme<EdwardsProjective>;

        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);

        let mut rng = ark_std::test_rng();

        let params = S::setup();
        let (pk, sk) = S::keygen(&params, &mut rng);

        let (r, signer_r) = S::new_request_params(&params, &mut rng);
        let m = [Fq::from(1234), Fq::from(5689), Fq::from(3456)];

        let (m_blinded, u) = S::blind(&params, &mut rng, &poseidon_hash, &m, pk, signer_r).unwrap();

        let s_blinded = S::blind_sign(sk, r, m_blinded);

        let s = S::unblind(s_blinded, &u);

        let verified = S::verify(&params, &poseidon_hash, &m, s, pk);
        assert!(verified);
    }

    #[test]
    fn test_non_blind_signature() {
        type S = BlindSigScheme<EdwardsProjective>;

        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);

        let mut rng = ark_std::test_rng();

        let params = S::setup();
        let (pk, sk) = S::keygen(&params, &mut rng);

        let m = [Fq::from(1234), Fq::from(5689), Fq::from(3456)];
        let s = S::non_blind_sign(&params, &mut rng, &poseidon_hash, sk, &m).unwrap();

        // verify using the same verification method used for blind-signatures
        let verified = S::verify(&params, &poseidon_hash, &m, s, pk);
        assert!(verified);
    }
}
