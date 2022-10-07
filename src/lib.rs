#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]

// pub type ConstraintF = ark_bn254::Fr;
// pub type ConstraintF = ark_ed_on_bn254::Fq; // base field
pub type ConstraintF = ark_ed_on_bn254::Fr; // scalar field

use ark_ec::{AffineCurve, ProjectiveCurve, TEModelParameters};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters, EdwardsProjective, FqParameters, Fr};
use ark_ff::{
    to_bytes, BigInteger, BigInteger256, Field, Fp256, FpParameters, One, PrimeField, Zero,
};

use ark_std::rand::{CryptoRng, RngCore};
use ark_std::UniformRand;

// hash
use arkworks_native_gadgets::poseidon;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, parse_vec, poseidon_params::setup_poseidon_params, Curve,
};

const GX: Fp256<FqParameters> = <EdwardsParameters as TEModelParameters>::AFFINE_GENERATOR_COEFFS.0;
const GY: Fp256<FqParameters> = <EdwardsParameters as TEModelParameters>::AFFINE_GENERATOR_COEFFS.1;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref G_AFFINE: EdwardsAffine = EdwardsAffine::new(GX, GY);
    static ref G: EdwardsProjective = G_AFFINE.into_projective();
}

// Fr modulus (bigendian)
const FR_MODULUS: BigInteger256 = BigInteger256::new([
    0x677297DC392126F1,
    0xAB3EEDB83920EE0A,
    0x370A08B6D0302B0B,
    0x060C89CE5C263405,
]);

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

pub struct PrivateKey(ConstraintF);
pub type PublicKey = EdwardsAffine;
pub type BlindedSignature = ConstraintF;
pub struct Signature {
    s: ConstraintF,
    r: EdwardsAffine,
}

#[derive(Debug)]
pub struct UserSecretData {
    a: ConstraintF,
    b: ConstraintF,
    r: EdwardsAffine,
}
impl UserSecretData {
    fn new_empty() -> Self {
        UserSecretData {
            a: ConstraintF::from(0),
            b: ConstraintF::from(0),
            r: G_AFFINE.clone(), // WIP
        }
    }
}

pub fn new_sk<R: RngCore>(rng: &mut R) -> PrivateKey {
    let sk: PrivateKey = PrivateKey(ConstraintF::rand(rng));
    sk
}

impl PrivateKey {
    pub fn public(&self) -> PublicKey {
        let pk: PublicKey = G.mul(self.0.into_repr()).into_affine();
        pk
    }
    pub fn blind_sign(&self, m_blinded: ConstraintF, k: ConstraintF) -> BlindedSignature {
        self.0 * m_blinded + k
    }
}

pub fn new_request_params<R: RngCore>(rng: &mut R) -> (ConstraintF, EdwardsAffine) {
    let k = ConstraintF::rand(rng);
    let R = G.mul(k.into_repr()).into_affine();
    (k, R)
}

fn new_blind_params<R: RngCore>(rng: &mut R, signer_r: EdwardsAffine) -> UserSecretData {
    let mut u: UserSecretData = UserSecretData::new_empty();
    u.a = ConstraintF::rand(rng);
    u.b = ConstraintF::rand(rng);

    // R = aR' + bG
    let aR = signer_r.mul(u.a.into_repr());
    let bG = G.mul(u.b.into_repr());
    u.r = aR.into_affine() + bG.into_affine();

    // check that u.r.x can be safely converted into Fr, and if not, choose other u.a & u.b values
    let x_repr = u.r.x.into_repr();
    if !(x_repr >= ConstraintF::one().into_repr() && x_repr < FR_MODULUS) {
        return new_blind_params(rng, signer_r);
    }
    return u;
}

pub fn blind<R: RngCore>(
    rng: &mut R,
    poseidon_hash: &poseidon::Poseidon<ConstraintF>,
    m: ConstraintF,
    signer_r: EdwardsAffine,
) -> Result<(ConstraintF, UserSecretData), ark_crypto_primitives::Error> {
    let u = new_blind_params(rng, signer_r);
    // use unwrap, as we already checked that R.x is inside Fr and will not give None
    let x_fr = ConstraintF::from_repr(u.r.x.into_repr()).unwrap();

    // m' = a^-1 rx h(m)
    let h_m = poseidon_hash.hash(&[m])?;
    let m_blinded = u.a.inverse().unwrap() * x_fr * h_m;

    Ok((m_blinded, u))
}

pub fn unblind(s_blinded: ConstraintF, u: UserSecretData) -> Signature {
    // s = a s' + b
    let s = u.a * s_blinded + u.b;
    Signature { s, r: u.r }
}

pub fn verify(
    poseidon_hash: &poseidon::Poseidon<ConstraintF>,
    m: ConstraintF,
    s: Signature,
    q: PublicKey,
) -> bool {
    let sG = G.mul(s.s.into_repr());

    let h_m = poseidon_hash.hash(&[m]).unwrap();

    let x_repr = s.r.x.into_repr();
    if !(x_repr >= ConstraintF::one().into_repr() && x_repr < FR_MODULUS) {
        return false; // error, s.r.x does not fit in Fr
    }
    let x_fr = ConstraintF::from_repr(s.r.x.into_repr()).unwrap();
    let right = s.r + q.mul((x_fr * h_m).into_repr()).into_affine();

    sG.into_affine() == right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind() {
        let poseidon_params = poseidon_setup_params::<ConstraintF>(Curve::Bn254, 5, 3);
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);

        let mut rng = ark_std::test_rng();

        let sk = new_sk(&mut rng);
        let pk = sk.public();

        let (k, signer_r) = new_request_params(&mut rng);
        let m = ConstraintF::from(1234);

        let (m_blinded, u) = blind(&mut rng, &poseidon_hash, m, signer_r).unwrap();

        let s_blinded = sk.blind_sign(m_blinded, k);

        let s = unblind(s_blinded, u);

        let verified = verify(&poseidon_hash, m, s, pk);
        assert!(verified);
    }
}
