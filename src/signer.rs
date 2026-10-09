//! Signed verdicts. Every payment check carries Keptvow's signature, so an answer can be passed
//! along — shown inside a marketplace, cached by a bot, attached to a payment — and anyone can
//! still prove it came from Keptvow, unaltered, and when it stops being fresh.
//!
//! The signature is an ordinary Ethereum `personal_sign` (EIP-191) by Keptvow's own signing
//! address, published at `/.well-known/keptvow-signer.json`. That means the tools every x402
//! buyer already has check it — viem's `verifyMessage`, ethers, `eth_account` — and so can a
//! contract on-chain, with `ecrecover`. The key only signs verdicts; it never holds money.

use std::path::PathBuf;
use std::sync::OnceLock;

use k256::ecdsa::SigningKey;

use crate::json::Json;
use crate::verify;

/// How long a signed verdict may be reused before asking again. Short: a seller's record can
/// turn the moment buyers start reporting that nothing arrived.
pub const FRESH_S: i64 = 300;

static KEY: OnceLock<SigningKey> = OnceLock::new();

/// The signing key: `VERDICT_SIGNING_KEY` (64 hex characters) if set, else the one saved in the
/// data folder, else a new one saved there — so the address stays the same across restarts.
pub fn load(dir: PathBuf) {
    let from_env = std::env::var("VERDICT_SIGNING_KEY").ok().and_then(|h| key_from_hex(&h));
    let path = dir.join("signer.key");
    let key = from_env
        .or_else(|| std::fs::read_to_string(&path).ok().and_then(|h| key_from_hex(&h)))
        .unwrap_or_else(|| {
            let k = fresh_key();
            let hex = verify::hex(&k.to_bytes());
            if let Err(e) = write_private(&path, &hex) {
                eprintln!("keptvow: could not save the verdict signing key ({e}); it will change on restart");
            }
            k
        });
    let _ = KEY.set(key);
    println!("keptvow: verdicts are signed by {}", address());
}

fn write_private(path: &std::path::Path, hex: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(hex.as_bytes())
}

fn key_from_hex(h: &str) -> Option<SigningKey> {
    let h = h.trim().trim_start_matches("0x");
    if h.len() != 64 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..64).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok()).collect();
    SigningKey::from_slice(&bytes?).ok()
}

fn fresh_key() -> SigningKey {
    use std::io::Read as _;
    loop {
        let mut buf = [0u8; 32];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).expect("no randomness for a signing key");
        if let Ok(k) = SigningKey::from_slice(&buf) {
            return k;
        }
    }
}

fn key() -> &'static SigningKey {
    KEY.get_or_init(fresh_key)
}

/// Keptvow's signing address, lowercase 0x.
pub fn address() -> String {
    let point = key().verifying_key().to_encoded_point(false);
    format!("0x{}", verify::hex(&verify::keccak(&point.as_bytes()[1..])[12..]))
}

/// An EIP-191 `personal_sign` signature over `msg`: 0x, then r ‖ s ‖ v with v = 27 or 28.
pub fn sign(msg: &str) -> String {
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    prefixed.extend_from_slice(msg.as_bytes());
    match key().sign_prehash_recoverable(&verify::keccak(&prefixed)) {
        Ok((sig, rid)) => {
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + rid.to_byte());
            format!("0x{}", verify::hex(&out))
        }
        Err(_) => String::new(),
    }
}

/// The signed form of a payment check: the exact text signed, the signature, who signed, and
/// until when the answer may be reused.
pub fn verdict(pay_to: &str, verdict: &str, amount_usd: Option<f64>, now_ms: i64) -> Json {
    let checked = now_ms / 1000;
    let until = checked + FRESH_S;
    let amount = amount_usd.map_or_else(|| "any".to_string(), |a| format!("{a}"));
    let message = format!("Keptvow verdict\nWallet: {pay_to}\nVerdict: {verdict}\nAmount USD: {amount}\nChecked: {checked}\nValid until: {until}");
    Json::obj(vec![
        ("message", Json::str(message.clone())),
        ("signature", Json::str(sign(&message))),
        ("signer", Json::str(address())),
        ("valid_until_ms", Json::num((until * 1000) as f64)),
    ])
}

/// What `/.well-known/keptvow-signer.json` says: who signs, and how to check a signature.
pub fn info(base: &str) -> Json {
    Json::obj(vec![
        ("signer", Json::str(address())),
        ("scheme", Json::str("EIP-191 personal_sign (secp256k1), like any Ethereum wallet signature")),
        ("signs", Json::str("every payment check: the \"signed\" field of /v1/check, /v1/wallets/{wallet} and the check_payment tool")),
        ("fresh_for_seconds", Json::num(FRESH_S as f64)),
        (
            "how_to_verify",
            Json::str(
                "viem: await verifyMessage({ address: signer, message: signed.message, signature: signed.signature }). \
                 ethers: verifyMessage(signed.message, signed.signature) === signer. \
                 Python: Account.recover_message(encode_defunct(text=signed.message), signature=signed.signature). \
                 Then check that the message names the wallet you're paying and that Valid until is in the future.",
            ),
        ),
        ("more", Json::str(format!("{base}/docs#signed"))),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_verdict_recovers_to_the_published_signer() {
        let j = verdict("0x00000000000000000000000000000000000000aa", "ok", Some(2.5), 1_790_000_000_123);
        let msg = j.get("message").and_then(|v| v.as_str()).unwrap();
        assert!(msg.contains("Verdict: ok") && msg.contains("Amount USD: 2.5") && msg.contains("Valid until: 1790000300"), "{msg}");
        let sig = j.get("signature").and_then(|v| v.as_str()).unwrap();
        let bytes: Vec<u8> = (2..sig.len()).step_by(2).map(|i| u8::from_str_radix(&sig[i..i + 2], 16).unwrap()).collect();
        assert_eq!(verify::recover_eth(msg.as_bytes(), &bytes).unwrap(), address());
        assert_eq!(j.get("signer").and_then(|v| v.as_str()), Some(address().as_str()));
        // Changing a word breaks it.
        let forged = msg.replace("Verdict: ok", "Verdict: stop");
        assert_ne!(verify::recover_eth(forged.as_bytes(), &bytes).unwrap(), address());
    }

    #[test]
    fn a_saved_key_is_read_back_the_same() {
        let k = fresh_key();
        let back = key_from_hex(&format!("0x{}\n", verify::hex(&k.to_bytes()))).unwrap();
        assert_eq!(back.to_bytes(), k.to_bytes());
        assert!(key_from_hex("0x1234").is_none());
    }
}
