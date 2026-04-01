/*
 * Utilities for using Bezout's Identity / Extended Euclidean Algorithm to
 * compute the coefficients f, g such that f * a + g * t = gcd(a, t) = 1 for
 * polynomials a and t over the ZoKrates prime field (BLS12-381 scalar field,
 * modulus 52435875175126190479447740508185965837690552500527637822603658699938581184513).
 *
 * We run the EEA to solve for f, then recover g = (1 - f * a) / t.
 *
 * Uses ark-ff / ark-poly. The FftField bound is required to unlock ark-poly's
 * built-in Add, Sub, Mul, and divide_with_q_and_r — ark_bls12_381::Fr satisfies it.
 */

use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Multiplies every coefficient of `p` by the scalar `s`.
fn scale<F: FftField>(p: &DensePolynomial<F>, s: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(p.coeffs.iter().map(|c| *c * s).collect())
}

/// Polynomial long division: returns (quotient, remainder).
fn divmod<F: FftField>(
    num: &DensePolynomial<F>,
    den: &DensePolynomial<F>,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    let num: DenseOrSparsePolynomial<F> = num.into();
    let den: DenseOrSparsePolynomial<F> = den.into();
    num.divide_with_q_and_r(&den).expect("division by zero polynomial")
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Builds a monic polynomial whose roots are exactly `roots`:
///   result(x) = (x - roots[0]) * (x - roots[1]) * ... * (x - roots[n-1])
pub fn poly_from_roots<F: FftField>(roots: &[F]) -> DensePolynomial<F> {
    roots.iter().fold(
        DensePolynomial::from_coefficients_vec(vec![F::one()]),
        |acc, &root| {
            let factor = DensePolynomial::from_coefficients_vec(vec![-root, F::one()]);
            &acc * &factor
        },
    )
}

/// Computes (f, g) such that f * a + g * t = 1.
///
/// Assumes gcd(a, t) = 1 — asserts if not.
///
/// Algorithm:
///   1. Run the EEA tracking only the Bezout coefficient for `a` to find f.
///   2. Normalize f (the EEA produces the gcd up to a scalar, not necessarily 1).
///   3. Recover g = (1 - f * a) / t.
pub fn bezout<F: FftField>(
    a: &DensePolynomial<F>,
    t: &DensePolynomial<F>,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    // EEA state — invariant: r_prev = f_prev * a + ??? * t
    // Starts with (r, f) = (a, 1) then (t, 0).
    let mut r_prev = a.clone();
    let mut r_curr = t.clone();
    let mut f_prev = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    let mut f_curr = DensePolynomial::zero();

    while !r_curr.is_zero() {
        let (q, r_next) = divmod(&r_prev, &r_curr);
        // f_next = f_prev - q * f_curr
        let f_next = &f_prev - &(&q * &f_curr);
        r_prev = r_curr;
        r_curr = r_next;
        f_prev = f_curr;
        f_curr = f_next;
    }

    // r_prev is the GCD. We assert it is a nonzero constant (degree 0),
    // meaning gcd(a, t) = 1 (up to a field scalar).
    assert_eq!(
        r_prev.degree(),
        0,
        "bezout: gcd(a, t) has degree {}, expected 0 — polynomials are not coprime",
        r_prev.degree()
    );

    // Normalize: the EEA may produce gcd = c ≠ 1; scale f so f * a + g * t = 1.
    let gcd_inv = r_prev.coeffs[0].inverse().expect("gcd must be nonzero");
    let f = scale(&f_prev, gcd_inv);

    // Recover g = (1 - f * a) / t
    let one = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    let one_minus_fa = &one - &(&f * a);
    let (g, remainder) = divmod(&one_minus_fa, t);
    assert!(remainder.is_zero(), "bezout: (1 - f*a) not divisible by t");

    (f, g)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::One;

    #[test]
    fn test_bezout_identity_holds() {
        // a has roots 2 and 5: a(x) = (x-2)(x-5) = x^2 - 7x + 10
        let a = poly_from_roots(&[Fr::from(2u64), Fr::from(5u64)]);

        // t has root 7: t(x) = x - 7
        let t = poly_from_roots(&[Fr::from(7u64)]);

        // Roots of a and t are disjoint, so gcd(a, t) = 1
        let (f, g) = bezout(&a, &t);

        // Verify f * a + g * t = 1
        let lhs = &(&f * &a) + &(&g * &t);
        assert_eq!(lhs.degree(), 0, "f*a + g*t must be a constant");
        assert_eq!(lhs.coeffs[0], Fr::one(), "f*a + g*t must equal 1");
    }

    #[test]
    fn test_a_roots_are_correct() {
        let a = poly_from_roots(&[Fr::from(2u64), Fr::from(5u64)]);
        assert_eq!(a.evaluate(&Fr::from(2u64)), Fr::zero());
        assert_eq!(a.evaluate(&Fr::from(5u64)), Fr::zero());
        assert_ne!(a.evaluate(&Fr::from(7u64)), Fr::zero());
    }

    #[test]
    fn test_t_root_is_correct() {
        let t = poly_from_roots(&[Fr::from(7u64)]);
        assert_eq!(t.evaluate(&Fr::from(7u64)), Fr::zero());
        assert_ne!(t.evaluate(&Fr::from(2u64)), Fr::zero());
    }

    #[test]
    #[should_panic(expected = "not coprime")]
    fn test_bezout_panics_when_not_coprime() {
        // a and t share root 5, so gcd != 1
        let a = poly_from_roots(&[Fr::from(2u64), Fr::from(5u64)]);
        let t = poly_from_roots(&[Fr::from(5u64)]);
        bezout(&a, &t);
    }

    #[test]
    fn test_divmod_exact() {
        // (x-2)(x-5) / (x-5) = (x-2), remainder 0
        let num = poly_from_roots(&[Fr::from(2u64), Fr::from(5u64)]);
        let den = poly_from_roots(&[Fr::from(5u64)]);
        let (q, r) = divmod(&num, &den);
        assert!(r.is_zero());
        assert_eq!(q.evaluate(&Fr::from(2u64)), Fr::zero());
        assert_ne!(q.evaluate(&Fr::from(5u64)), Fr::zero());
    }
}
