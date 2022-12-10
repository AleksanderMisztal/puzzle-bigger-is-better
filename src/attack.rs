use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::SeedableRng, UniformRand, Zero};
use blake2::Digest;

use crate::{
    algorithms::ILV,
    data_structures::{Commitment, CommitmentKey, Proof},
};

pub struct Attack<E: PairingEngine> {
    /// The vector that will be committed.
    pub a: Vec<E::Fr>,
    /// Commitment to `a`.
    pub commitment: Commitment<E>,
    /// The claimed inner product of `a` and `b := Hash(commitment)`, which differs
    /// from the actual inner product.
    pub claimed_inner_product: E::Fr,
    /// An unsound proof that `a` and `b` have inner product `claimed_inner_product`.
    pub proof: Proof<E>,
}

impl<E: PairingEngine> Attack<E> {
    pub fn attack(ck: &CommitmentKey<E>, dim: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let a = vec![E::Fr::rand(&mut rng); dim];
        let commitment = ILV::commit(&ck, &a);
        let b = hash(commitment, dim);
        let claimed_inner_product = E::Fr::rand(&mut rng);
        let proof = Self::fake_open(&ck, &a, &b, claimed_inner_product);
        Self {
            a,
            commitment,
            claimed_inner_product,
            proof,
        }
    }

    fn fake_open(
        ck: &CommitmentKey<E>,
        a: &[E::Fr],
        b: &[E::Fr],
        claimed_inner_product: E::Fr,
    ) -> Proof<E> {
        let mut a_coeffs = Vec::with_capacity(a.len() + 1);
        a_coeffs.push(E::Fr::zero());
        a_coeffs.extend_from_slice(a);
        let a_poly = DensePolynomial::from_coefficients_vec(a_coeffs);

        let mut b_rev = b.to_vec();
        b_rev.push(E::Fr::zero());
        b_rev.reverse();
        let b_poly = DensePolynomial::from_coefficients_vec(b_rev);

        let mut product = &a_poly * &b_poly;

        product.coeffs[a.len() + 1] -= claimed_inner_product;

        let product_coeffs = product
            .coeffs
            .iter()
            .map(|x| x.into_repr())
            .collect::<Vec<_>>();

        let powers_of_beta_g = [
            ck.powers_of_beta_g_first.clone(),
            ck.powers_of_beta_g_second.clone(),
        ]
        .concat();

        let proof = VariableBaseMSM::multi_scalar_mul(&powers_of_beta_g, &product_coeffs);
        Proof(proof.into())
    }

    pub fn assert_attack_works(&self, ck: &CommitmentKey<E>, dim: usize) {
        assert_eq!(self.a.len(), dim);
        assert_eq!(self.commitment, ILV::commit(&ck, &self.a));
        let b = hash(self.commitment, dim);
        let actual_inner_product = self
            .a
            .iter()
            .zip(b.iter())
            .map(|(&a, b)| a * b)
            .sum::<E::Fr>();
        assert!(ILV::verify(
            &ck,
            &self.commitment,
            &b,
            self.claimed_inner_product,
            &self.proof
        ));
        assert_ne!(actual_inner_product, self.claimed_inner_product);
    }
}

pub fn hash<E: PairingEngine>(commitment: Commitment<E>, dim: usize) -> Vec<E::Fr> {
    let mut commitment_bytes = vec![];
    commitment.serialize(&mut commitment_bytes).unwrap();
    let seed: [u8; 32] = blake2::Blake2s::digest(&commitment_bytes)
        .as_slice()
        .try_into()
        .unwrap();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
    let mut b = vec![E::Fr::zero(); dim];
    for i in 0..dim {
        b[i] = E::Fr::rand(&mut rng);
    }
    b
}
