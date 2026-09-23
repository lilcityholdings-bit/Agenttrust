//! Deterministic hashing and a seeded PRNG, both hand-rolled to keep the zero-dependency rule.
//!
//! Two different hashes live here on purpose, for two different jobs:
//!
//! - [`fnv1a64`] is not cryptographic and is not used where that matters. It seeds the jury draw
//!   so a panel is *reproducible by a stranger* — the point is that anyone replaying the public
//!   feed computes the same panel, not that the seed resists a motivated forger. Nobody profits
//!   from predicting a jury seed in advance of it existing, so a fast non-cryptographic hash is
//!   the right tool.
//! - [`sha256`] is cryptographic, and is what actually matters: it chains the audit log (rewriting
//!   history means finding a preimage, not guessing a 64-bit value) and it is what a claimed
//!   secret is hashed with before it ever touches disk or the audit feed. This used to be FNV-1a
//!   for both jobs; that was an honest, clearly-labeled gap, not an oversight — this is the
//!   "swap two functions" follow-through the original comment promised.

/// FNV-1a, 64-bit. Reproducible, fast, not cryptographic — see module docs for why that's fine
/// for a jury seed and would not be fine for an audit hash.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

pub fn hex64(value: u64) -> String {
    format!("{value:016x}")
}

// ---------------------------------------------------------------------------------------------
// SHA-256 — a plain from-the-spec implementation (FIPS 180-4), no crates. Used for the audit
// chain and for hashing claimed secrets before they touch disk.
// ---------------------------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 over `bytes`, returning the 32-byte digest.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = H0;

    // Padding: a 1 bit, zeros, then the original bit length as a big-endian u64, so the total
    // length is a multiple of 64 bytes.
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// SplitMix64 — a small, well-distributed PRNG that is fully determined by its seed.
///
/// The jury draw uses this rather than anything OS-seeded on purpose: a panel drawn from a
/// published seed can be recomputed by whoever wants to check that the venue drew fairly instead
/// of hand-picking jurors who would rule the way it wanted.
pub struct Seeded(u64);

impl Seeded {
    pub fn new(seed: u64) -> Seeded {
        Seeded(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish index below `n`. Modulo bias is bounded by u64 range over any realistic pool
    /// size and is irrelevant at the scale this picks from.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// Draws `k` distinct items from `pool` by partial Fisher-Yates. Order of the returned panel
    /// is itself part of the reproducible output.
    pub fn draw<T: Clone>(&mut self, pool: &[T], k: usize) -> Vec<T> {
        let mut items: Vec<T> = pool.to_vec();
        let take = k.min(items.len());
        for i in 0..take {
            let j = i + self.below(items.len() - i);
            items.swap(i, j);
        }
        items.truncate(take);
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_always_draws_the_same_panel() {
        let pool: Vec<String> = (0..50).map(|i| format!("agent_{i}")).collect();
        let a = Seeded::new(1234).draw(&pool, 9);
        let b = Seeded::new(1234).draw(&pool, 9);
        assert_eq!(a, b, "a stranger replaying the feed must compute the same jury");
    }

    #[test]
    fn different_seeds_draw_different_panels() {
        let pool: Vec<String> = (0..50).map(|i| format!("agent_{i}")).collect();
        assert_ne!(Seeded::new(1).draw(&pool, 9), Seeded::new(2).draw(&pool, 9));
    }

    #[test]
    fn a_draw_never_repeats_a_juror_and_never_exceeds_the_pool() {
        let pool: Vec<String> = (0..5).map(|i| format!("agent_{i}")).collect();
        let panel = Seeded::new(77).draw(&pool, 9);
        assert_eq!(panel.len(), 5, "cannot seat more jurors than exist");
        let mut sorted = panel.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), panel.len(), "the same juror must not be seated twice");
    }

    // ---- SHA-256 against the standard published test vectors -----------------------------

    #[test]
    fn sha256_of_the_empty_string() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_of_a_two_block_message() {
        // The standard's own 448-bit test vector, long enough to force two 64-byte blocks.
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha256_hex(msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_is_deterministic_and_avalanches() {
        assert_eq!(sha256_hex(b"same input"), sha256_hex(b"same input"));
        assert_ne!(sha256_hex(b"same input"), sha256_hex(b"same inpuT"));
    }
}
