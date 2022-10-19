#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]

// #[cfg(feature="r1cs")]
pub mod constraints;

use ark_ec::{models::twisted_edwards_extended::GroupAffine, AffineCurve, ProjectiveCurve};

use ark_ff::{to_bytes, BigInteger256, Field, FpParameters, PrimeField};

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
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters};

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

#[derive(Debug)]
pub struct UserSecretData<C: ProjectiveCurve> {
    a: C::ScalarField,
    b: C::ScalarField,
    r: C::Affine,
}
impl<C: ProjectiveCurve> UserSecretData<C> {
    fn new_empty(parameters: &Parameters<C>) -> Self {
        UserSecretData {
            a: C::ScalarField::from(0_u32),
            b: C::ScalarField::from(0_u32),
            r: parameters.generator, // WIP
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
        let k = C::ScalarField::rand(rng);
        let R = parameters.generator.mul(k).into();
        (k, R)
    }

    pub fn blind_sign(
        sk: SecretKey<C>,
        k: C::ScalarField,
        m_blinded: C::ScalarField,
    ) -> BlindedSignature<C> {
        sk * m_blinded + k
    }

    // requester
    pub fn new_blind_params<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
        signer_r: C::Affine,
    ) -> UserSecretData<C>
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
    {
        let mut u: UserSecretData<C> = UserSecretData::new_empty(parameters);
        u.a = C::ScalarField::rand(rng);
        u.b = C::ScalarField::rand(rng);

        // R = aR' + bG
        let aR = signer_r.mul(u.a.into_repr());
        let bG = parameters.generator.mul(u.b.into_repr());
        u.r = aR.into_affine() + bG.into_affine();

        let r = EdwardsAffine::from(u.r); // WIP
        let one = BigInteger256::from(1u64);
        let x_repr = r.x.into_repr();
        let modulus = <<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS;
        let modulus_repr = BigInteger256::try_from(modulus.into()).unwrap();

        if !(x_repr >= one && x_repr < modulus_repr) {
            // TODO maybe add a counter of attempts with a limit
            return Self::new_blind_params(parameters, rng, signer_r);
        }
        u
    }

    pub fn blind<R: Rng>(
        parameters: &Parameters<C>,
        rng: &mut R,
        poseidon_hash: &poseidon::Poseidon<ConstraintF<C>>,
        m: ConstraintF<C>,
        signer_r: C::Affine,
    ) -> Result<(C::ScalarField, UserSecretData<C>), ark_crypto_primitives::Error>
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
    {
        let u = Self::new_blind_params(parameters, rng, signer_r);
        // get X coordinate, as in new_blind_params we already checked that R.x is inside Fr and
        // will not give None
        let r = EdwardsAffine::from(u.r); // WIP
        let x_fr = C::ScalarField::from(r.x.into_repr());

        // m' = a^-1 rx h(m)
        // TODO hash(m) must be \in Fr
        let hm = poseidon_hash.hash(&[m])?;
        // let hm_fr = C::ScalarField::from_repr(hm.into_repr()).unwrap();
        let hm_fr = C::ScalarField::from_le_bytes_mod_order(&to_bytes!(hm)?); // WIP TMP
        let m_blinded = u.a.inverse().unwrap() * x_fr * hm_fr;
        // let m_blinded = C::ScalarField::from(u.a.inverse().unwrap() * x_fr) * hm_fr;

        Ok((m_blinded, u))
    }

    pub fn unblind(s_blinded: C::ScalarField, u: UserSecretData<C>) -> Signature<C> {
        // s = a s' + b
        let s = u.a * s_blinded + u.b;
        Signature { s, r: u.r }
    }

    pub fn verify(
        parameters: &Parameters<C>,
        poseidon_hash: &poseidon::Poseidon<ConstraintF<C>>,
        m: ConstraintF<C>,
        s: Signature<C>,
        q: PublicKey<C>,
    ) -> bool
    where
        <C as ProjectiveCurve>::ScalarField: From<BigInteger256>,
    {
        let sG = parameters.generator.mul(s.s.into_repr());

        // TODO the output of hash(m) must be \in Fr
        let hm = poseidon_hash.hash(&[m]).unwrap();
        // let hm_fr = C::ScalarField::from_repr(hm.into_repr()).unwrap();
        let hm_fr = C::ScalarField::from_le_bytes_mod_order(&to_bytes!(hm).unwrap()); // WIP TMP

        // check that s.R.x is in Fr
        let r = EdwardsAffine::from(s.r); // WIP
        let one = BigInteger256::from(1u64);
        let x_repr = r.x.into_repr();
        let modulus = <<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS;
        let modulus_repr = BigInteger256::try_from(modulus.into()).unwrap();
        if !(x_repr >= one && x_repr < modulus_repr) {
            return false;
        }
        // get s.R.x
        let x_fr = C::ScalarField::from(r.x.into_repr());
        let right = s.r + q.mul((x_fr * hm_fr).into_repr()).into_affine();

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

        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 3);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);

        let mut rng = ark_std::test_rng();

        let params = S::setup();
        let (pk, sk) = S::keygen(&params, &mut rng);

        let (k, signer_r) = S::new_request_params(&params, &mut rng);
        let m = Fq::from(1234);

        let (m_blinded, u) = S::blind(&params, &mut rng, &poseidon_hash, m, signer_r).unwrap();

        let s_blinded = S::blind_sign(sk, k, m_blinded);

        let s = S::unblind(s_blinded, u);

        let verified = S::verify(&params, &poseidon_hash, m, s, pk);
        assert!(verified);
    }
}
