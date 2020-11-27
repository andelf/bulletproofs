// The #-commented lines are hidden in Rustdoc but not in raw
// markdown rendering, and contain boilerplate code so that the
// code in the README.md is actually run as part of the test suite.

use rand::thread_rng;

use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn main() {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 16.
    let bp_gens = BulletproofGens::new(64, 16);

    // Four secret values we want to prove lie in the range [0, 2^32)
    let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];

    // The API takes blinding factors for the commitments.
    let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    // Create a 32-bit rangeproof.
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &secrets,
        &blindings,
        32,
    )
    .expect("A real program could handle errors");

    let raw = proof.to_bytes();
    println!("proof => {:?}", proof);
    println!("proof => {:?}", hex::encode(&raw));
    println!("proof size => {}", raw.len());

    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"doctest example");
    let _ = proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &commitments,
            32,
        )
        .unwrap();
}
