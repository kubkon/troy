use libspartan::{
    math::Math,
    r1csinstance::R1CSInstance,
    scalar::Scalar,
    sparse_mlpoly::{SparseMatEntry, SparseMatPolynomial},
    Instance, SNARKGens, Transcript, SNARK,
};

fn main() {
    // describe R1CS system
    // x^3 = y
    // x * x = z1
    // z1 * x = z2
    // z2 = y
    let num_vars = 2;
    let num_cons = 2;
    let num_inputs = 1;
    let cols = num_vars + 1 + num_inputs;

    // [x^2, x^3, 1, x]
    #[rustfmt::skip]
    // let A: Vec<_> = vec![
    //     0, 0, 0, 0, 0, 1,
    //     1, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 1,
    //     0, 0, 1, 0, 5, 0,
    // ]
    let A: Vec<_> = vec![
        0, 0, 0, 1,
        1, 0, 0, 0,
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, x)| {
        if x == 0 {
            None
        } else {
            let col = i % cols;
            let row = i / cols;
            Some(SparseMatEntry::new(row, col, x.into()))
        }
    })
    .collect();

    #[rustfmt::skip]
    // let B: Vec<_> = vec![
    //     0, 0, 0, 0, 0, 1,
    //     0, 0, 0, 0, 0, 1,
    //     0, 0, 0, 0, 1, 0,
    //     0, 0, 0, 0, 1, 0,
    // ]
    let B: Vec<_> = vec![
        0, 0, 0, 1, 
        0, 0, 0, 1, 
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, x)| {
        if x == 0 {
            None
        } else {
            let col = i % cols;
            let row = i / cols;
            Some(SparseMatEntry::new(row, col, x.into()))
        }
    })
    .collect();

    #[rustfmt::skip]
    // let C: Vec<_> = vec![
    //     1, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0,
    //     0, 0, 1, 0, 0, 0,
    //     0, 0, 0, 1, 0, 0,
    // ]
    let C: Vec<_> = vec![
        1, 0, 0, 0,
        0, 1, 0, 0,
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, x)| {
        if x == 0 {
            None
        } else {
            let col = i % cols;
            let row = i / cols;
            Some(SparseMatEntry::new(row, col, x.into()))
        }
    })
    .collect();

    // let Z: Vec<Scalar> = vec![9, 27, 30, 35, 1, 3]
    let Z: Vec<Scalar> = vec![9, 27, 1, 3]
        .into_iter()
        .map(|x| x.into())
        .collect();

    let vars = Z[0..num_vars].to_vec();
    let inputs = Z[num_vars + 1..].to_vec();

    let num_poly_vars_x = num_cons.log2();
    let num_poly_vars_y = (2 * num_vars).log2();
    let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, A);
    let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, B);
    let poly_C = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, C);

    let r1cs_inst = R1CSInstance::new(num_cons, num_vars, num_inputs, poly_A, poly_B, poly_C);

    assert_eq!(
      r1cs_inst.is_sat(&Z[0..num_vars].to_vec(), &Z[num_vars + 1..].to_vec()),
      true,
    );

    let inst: Instance = r1cs_inst.into();
    
    // produce public generators
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_cons);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::prove(&inst, &decomm, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof
    let mut verifier_transcript = Transcript::new(b"example");

    let res = proof.verify(&comm, &inputs, &mut verifier_transcript, &gens).is_ok();
    println!("Proof verified? {}", res);
}
