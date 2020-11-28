#![allow(non_snake_case)]

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

fn main() {
    println!("========= case1: 200 + 33 = 233");
    case1();

    println!("========= case2: 200 - 1 = 199");
    case2();
}

fn case1() {
    let gens = PedersenGens::default();

    let mut blinding_rng = rand::thread_rng();

    let v1: u64 = 200;
    let v_binding1 = Scalar::random(&mut blinding_rng);

    // type: RistrettoPoint
    let V1 = gens.commit(v1.into(), v_binding1);
    // println!("V  => {:?}", V);
    println!("V1(200)  => {}", hex::encode(&V1.compress().to_bytes()[..]));

    let v2: u64 = 33;
    let v_binding2 = Scalar::random(&mut blinding_rng);
    let V2 = gens.commit(v2.into(), v_binding2);
    // println!("V2 => {:?}", V2);
    println!("V2(33)   => {}", hex::encode(&V2.compress().to_bytes()[..]));

    let v3: u64 = 200 + 33;
    let v_binding3 = v_binding1 + v_binding2;
    let V3 = gens.commit(v3.into(), v_binding3);
    println!("V3(233)  => {}", hex::encode(&V3.compress().to_bytes()[..]));

    let V3_hat = V1 + V2;
    println!(
        "V3'(hash)=> {}",
        hex::encode(&V3_hat.compress().to_bytes()[..])
    );

    println!(": construct via hash");
    let v1_compressed = &V1.compress().to_bytes()[..];
    let v1 = CompressedRistretto::from_slice(v1_compressed);

    let v2_compressed = &V2.compress().to_bytes()[..];
    let v2 = CompressedRistretto::from_slice(v2_compressed);

    let v3 = v1.decompress().unwrap() + v2.decompress().unwrap();
    println!("V3_decomp=> {}", hex::encode(&v3.compress().to_bytes()[..]));
}

fn case2() {
    let gens = PedersenGens::default();

    let mut blinding_rng = rand::thread_rng();

    let v1: u64 = 200;
    let v_binding1 = Scalar::random(&mut blinding_rng);

    // type: RistrettoPoint
    let V1 = gens.commit(v1.into(), v_binding1);
    // println!("V  => {:?}", V);
    println!("V1(200)  => {}", hex::encode(&V1.compress().to_bytes()[..]));

    let v2: u64 = 1;
    // println!("V2 = {:x}", v2);
    let v_binding2 = Scalar::random(&mut blinding_rng);
    let V2 = gens.commit(v2.into(), v_binding2);
    // println!("V2 => {:?}", V2);
    println!("V2(-1)   => {}", hex::encode(&V2.compress().to_bytes()[..]));

    let v3: u64 = 199;
    let v_binding3 = v_binding1 - v_binding2;
    let V3 = gens.commit(v3.into(), v_binding3);
    println!("V3(199)  => {}", hex::encode(&V3.compress().to_bytes()[..]));

    let V3_hat = V1 - V2;
    println!(
        "V3'(hash)=> {}",
        hex::encode(&V3_hat.compress().to_bytes()[..])
    );
}
