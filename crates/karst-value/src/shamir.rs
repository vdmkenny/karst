//! Shamir secret sharing over a prime field, for threshold credential issuance.
//!
//! Threshold issuance is what stops the value layer becoming error 03. A single issuer sees
//! every credential request and can link every one of them to the party that made it. With
//! `t`-of-`n` issuance, fewer than `t` colluding issuers learn nothing, and no single party
//! is worth compromising or compelling.
//!
//! The field is the prime 2^61 - 1, which is large enough for the share arithmetic here and
//! small enough to compute in `u128` without a bignum dependency. A production issuance
//! scheme uses Coconut over a pairing curve; this is the threshold structure only.

/// A Mersenne prime, so reduction is cheap and the field is big enough to be non-trivial.
pub const P: u128 = (1 << 61) - 1;

fn add(a: u128, b: u128) -> u128 {
    (a + b) % P
}

fn sub(a: u128, b: u128) -> u128 {
    (a + P - b % P) % P
}

fn mul(a: u128, b: u128) -> u128 {
    (a % P) * (b % P) % P
}

fn pow(mut base: u128, mut exp: u128) -> u128 {
    let mut acc = 1u128;
    base %= P;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Modular inverse by Fermat's little theorem. `P` is prime, so `a^(P-2) = a^-1`.
fn inv(a: u128) -> u128 {
    pow(a, P - 2)
}

/// One issuer's share of the issuing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    /// Issuer index, one-based. Zero is the secret itself and is never a valid share.
    pub index: u64,
    pub value: u128,
}

/// Split `secret` so that any `threshold` of `count` shares reconstruct it, and any fewer
/// learn nothing.
pub fn split(secret: u128, threshold: usize, count: usize, seed: u64) -> Vec<Share> {
    assert!(threshold >= 1 && threshold <= count, "1 <= t <= n");

    // Deterministic coefficients from the seed. A real deployment draws these from a CSPRNG
    // and destroys them; determinism here is for reproducible tests.
    let mut coeffs = vec![secret % P];
    for i in 1..threshold {
        let mut h = blake3::Hasher::new();
        h.update(b"karst.shamir.coeff");
        h.update(&seed.to_le_bytes());
        h.update(&(i as u64).to_le_bytes());
        let mut b = [0u8; 16];
        h.finalize_xof().fill(&mut b);
        coeffs.push(u128::from_le_bytes(b) % P);
    }

    (1..=count as u64)
        .map(|x| {
            // Horner evaluation of the polynomial at x.
            let mut acc = 0u128;
            for c in coeffs.iter().rev() {
                acc = add(mul(acc, x as u128), *c);
            }
            Share {
                index: x,
                value: acc,
            }
        })
        .collect()
}

/// Reconstruct the secret from any `threshold` shares, by Lagrange interpolation at zero.
///
/// Returns `None` if two shares carry the same index, which would make the interpolation
/// singular.
pub fn combine(shares: &[Share]) -> Option<u128> {
    if shares.is_empty() {
        return None;
    }
    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.index == b.index {
                return None;
            }
        }
    }

    let mut secret = 0u128;
    for (i, si) in shares.iter().enumerate() {
        let mut num = 1u128;
        let mut den = 1u128;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            // Evaluating at x = 0, so the numerator term is (0 - x_j).
            num = mul(num, sub(0, sj.index as u128));
            den = mul(den, sub(si.index as u128, sj.index as u128));
        }
        secret = add(secret, mul(si.value, mul(num, inv(den))));
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_subset_reconstructs() {
        let secret = 0x0123_4567_89ab_cdefu128 % P;
        let shares = split(secret, 3, 5, 42);

        for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let subset: Vec<Share> = combo.iter().map(|i| shares[*i]).collect();
            assert_eq!(combine(&subset), Some(secret), "combo {combo:?} failed");
        }
    }

    #[test]
    fn fewer_than_the_threshold_learns_nothing() {
        let secret = 999_331u128;
        let shares = split(secret, 3, 5, 7);

        // Two shares of a 3-of-5 split interpolate to a value that is not the secret.
        let two: Vec<Share> = shares[..2].to_vec();
        assert_ne!(combine(&two), Some(secret));

        // And a different pair gives a different wrong answer, which is the point: the
        // reconstruction is unconstrained below the threshold.
        let other: Vec<Share> = vec![shares[2], shares[4]];
        assert_ne!(combine(&two), combine(&other));
    }

    #[test]
    fn more_than_the_threshold_still_works() {
        let secret = 4242u128;
        let shares = split(secret, 2, 5, 1);
        assert_eq!(combine(&shares), Some(secret));
    }

    #[test]
    fn duplicate_indices_are_refused_rather_than_producing_nonsense() {
        let shares = split(1234, 2, 3, 1);
        let dup = vec![shares[0], shares[0]];
        assert_eq!(combine(&dup), None);
    }

    #[test]
    fn a_single_issuer_split_is_just_the_secret() {
        let shares = split(77, 1, 3, 1);
        for s in &shares {
            assert_eq!(combine(&[*s]), Some(77));
        }
    }
}
