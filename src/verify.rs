//! Proving an agent really controls the outside identity it says it has.
//!
//! Before this module, `POST /v1/agents/{id}/identity` took the agent's word for it: any bot
//! could say "I am ICP principal X" or "I am ERC-8004 agent #7" and the service repeated the
//! claim. A trust score that repeats unverified claims is worse than none, so a registration now
//! has two states — *claimed* (the agent said so) and *verified* (the agent signed a challenge
//! with the key that identity belongs to, and we checked it).
//!
//! Every protocol uses the same challenge, which the agent signs with its own key:
//!
//! ```text
//! agenttrust identity proof
//! agent: <agent_id>
//! protocol: <protocol>
//! id: <external id, normalized>
//! timestamp: <unix ms>
//! ```
//!
//! Naming the agent id inside the signed text means a proof can only ever bind the identity to
//! the agent it was made for — replaying it elsewhere is useless. The timestamp must be within
//! ten minutes of the server's clock, and when an identity moves from one agent to another the
//! newer proof wins, so an old proof cannot take an identity back after it was handed on.
//!
//! What each protocol checks:
//!
//! | protocol       | id                                     | proof                                                         |
//! |----------------|----------------------------------------|---------------------------------------------------------------|
//! | `icp`          | Internet Computer principal            | Ed25519 or secp256k1 key whose self-authenticating principal is the id, and its signature |
//! | `eth`          | `0x` wallet address                    | EIP-191 `personal_sign` signature recovering to that address  |
//! | `erc8004`      | `eip155:<chain>:<registry>:<agentId>`  | EIP-191 signature from the NFT's on-chain owner or agent wallet |
//! | `did`          | `did:key:z6Mk…` (Ed25519)              | Ed25519 signature by the key encoded in the DID               |
//! | `web_bot_auth` | the bot's domain                       | Ed25519 signature by a key listed in the domain's `/.well-known/http-message-signatures-directory` |
//!
//! Anything else (UCP, AP2, TAP, did:web, Internet Identity delegations…) can still be
//! *claimed*, and is shown as claimed — never as verified.

use std::io::Read as _;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256Key};
use sha3::{Digest as _, Keccak256};

use crate::hash::{sha224, sha256};
use crate::json::{self, Json};

/// How far a proof's timestamp may sit from the server clock.
pub const PROOF_WINDOW_MS: i64 = 10 * 60 * 1000;

/// The ERC-8004 Identity Registry. Deployed at the same address on Ethereum, Base, Polygon,
/// Arbitrum, Optimism, BNB, Avalanche and the other mainnets the reference deployment covers.
pub const ERC8004_REGISTRY: &str = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";

/// Protocols a proof can actually be checked for.
pub const VERIFIABLE: [&str; 5] = ["icp", "eth", "erc8004", "did", "web_bot_auth"];

pub fn is_verifiable(protocol: &str) -> bool {
    VERIFIABLE.contains(&protocol)
}

/// The exact text an agent signs.
pub fn challenge(agent_id: &str, protocol: &str, external_id: &str, timestamp_ms: i64) -> String {
    format!(
        "agenttrust identity proof\nagent: {agent_id}\nprotocol: {protocol}\nid: {external_id}\ntimestamp: {timestamp_ms}"
    )
}

/// Canonical form of an external id, so `0xABC…` and `0xabc…` are one identity, not two.
pub fn normalize(protocol: &str, id: &str) -> Result<String, String> {
    let id = id.trim();
    if id.is_empty() || id.len() > 256 {
        return Err("id must be 1–256 characters".into());
    }
    match protocol {
        "icp" => {
            let p = id.to_ascii_lowercase();
            decode_principal(&p)?;
            Ok(p)
        }
        "eth" => parse_address(id),
        "erc8004" => {
            let (chain, registry, agent) = parse_erc8004(id)?;
            Ok(format!("eip155:{chain}:{registry}:{agent}"))
        }
        "did" => {
            if !id.starts_with("did:") {
                return Err("a DID starts with did:".into());
            }
            Ok(id.to_string())
        }
        "web_bot_auth" => {
            let d = id.trim_start_matches("https://").trim_end_matches('/').to_ascii_lowercase();
            check_public_domain(&d)?;
            Ok(d)
        }
        _ => {
            if protocol.is_empty()
                || protocol.len() > 32
                || !protocol.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err("protocol must be a short name like icp, eth, erc8004, did, web_bot_auth, ucp".into());
            }
            Ok(id.to_string())
        }
    }
}

/// What the agent submits to prove control.
pub struct Proof<'a> {
    pub agent_id: &'a str,
    pub protocol: &'a str,
    /// Already normalized.
    pub external_id: &'a str,
    pub timestamp_ms: i64,
    pub signature: &'a str,
    pub public_key: Option<&'a str>,
}

/// The outside world, behind a trait so tests can stand in for the chain and the web.
pub trait Net {
    /// `eth_call` against `to` on `chain_id`; returns the raw hex result.
    fn eth_call(&self, chain_id: u64, to: &str, data: &str) -> Result<String, String>;
    /// The body of `https://<domain>/.well-known/http-message-signatures-directory`.
    fn wba_directory(&self, domain: &str) -> Result<String, String>;
}

/// Checks a proof. On success returns a short description of how it was verified, which is
/// stored and shown on the agent's profile.
pub fn verify(p: &Proof, now_ms: i64, net: &dyn Net) -> Result<String, String> {
    if (p.timestamp_ms - now_ms).abs() > PROOF_WINDOW_MS {
        return Err(format!(
            "timestamp is more than 10 minutes from server time ({now_ms}) — fetch a fresh challenge"
        ));
    }
    let msg = challenge(p.agent_id, p.protocol, p.external_id, p.timestamp_ms);
    let sig = decode_bytes(p.signature).ok_or("signature must be hex or base64")?;
    match p.protocol {
        "icp" => {
            let key = decode_bytes(p.public_key.ok_or("public_key is required for icp")?)
                .ok_or("public_key must be hex or base64")?;
            verify_icp(p.external_id, &key, msg.as_bytes(), &sig)
        }
        "eth" => {
            let addr = recover_eth(msg.as_bytes(), &sig)?;
            if addr != p.external_id {
                return Err(format!("signature is from {addr}, not {}", p.external_id));
            }
            Ok("eip191 signature".into())
        }
        "erc8004" => {
            let (chain, registry, agent) = parse_erc8004(p.external_id)?;
            let signer = recover_eth(msg.as_bytes(), &sig)?;
            let owner = erc8004_address(net, chain, &registry, agent, "ownerOf(uint256)")?;
            if owner.as_deref() == Some(signer.as_str()) {
                return Ok(format!("eip191 signature by on-chain owner {signer} (chain {chain})"));
            }
            let wallet = erc8004_address(net, chain, &registry, agent, "getAgentWallet(uint256)").ok().flatten();
            if wallet.as_deref() == Some(signer.as_str()) {
                return Ok(format!("eip191 signature by on-chain agent wallet {signer} (chain {chain})"));
            }
            match owner {
                None => Err(format!("ERC-8004 agent {agent} does not exist on chain {chain}")),
                Some(o) => Err(format!(
                    "signature is from {signer}, but ERC-8004 agent {agent} is owned by {o}{}",
                    wallet.map(|w| format!(" (agent wallet {w})")).unwrap_or_default()
                )),
            }
        }
        "did" => {
            let key = did_key_ed25519(p.external_id)?;
            verify_ed25519(&key, msg.as_bytes(), &sig)?;
            Ok("ed25519 signature by did:key".into())
        }
        "web_bot_auth" => {
            let key = decode_bytes(p.public_key.ok_or("public_key is required for web_bot_auth")?)
                .ok_or("public_key must be hex or base64")?;
            let key: [u8; 32] = key.try_into().map_err(|_| "public_key must be a 32-byte Ed25519 key")?;
            verify_ed25519(&key, msg.as_bytes(), &sig)?;
            let dir = net.wba_directory(p.external_id)?;
            if !directory_lists_key(&dir, &key) {
                return Err(format!(
                    "that key is not in https://{}/.well-known/http-message-signatures-directory",
                    p.external_id
                ));
            }
            Ok("ed25519 key published in the domain's Web Bot Auth directory".into())
        }
        other => Err(format!("{other} identities can be claimed but not verified yet")),
    }
}

// ---- encodings ------------------------------------------------------------------------------

/// Hex (with or without 0x) or base64 (standard or URL alphabet, padded or not).
pub fn decode_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let h = s.strip_prefix("0x").unwrap_or(s);
    if !h.is_empty() && h.len() % 2 == 0 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok()).collect();
    }
    base64_decode(s)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

// ---- Ed25519 --------------------------------------------------------------------------------

fn verify_ed25519(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let key = EdKey::from_bytes(key).map_err(|_| "not a valid Ed25519 public key")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "an Ed25519 signature is 64 bytes")?;
    key.verify_strict(msg, &EdSignature::from_bytes(&sig))
        .map_err(|_| "signature does not verify for that key and challenge".to_string())
}

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend(out);
    Some(full)
}

/// The Ed25519 key inside a `did:key:z6Mk…` (multibase base58btc, multicodec 0xed01).
fn did_key_ed25519(did: &str) -> Result<[u8; 32], String> {
    let enc = did
        .strip_prefix("did:key:z")
        .ok_or("only did:key (Ed25519) DIDs can be verified; other DID methods can be claimed")?;
    let bytes = base58_decode(enc).ok_or("did:key is not valid base58")?;
    match bytes.as_slice() {
        [0xed, 0x01, rest @ ..] if rest.len() == 32 => Ok(rest.try_into().unwrap()),
        _ => Err("only Ed25519 did:key identifiers (z6Mk…) can be verified".into()),
    }
}

// ---- Internet Computer ----------------------------------------------------------------------

const ED25519_DER_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
const SECP256K1_DER_PREFIX: [u8; 23] = [
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x0a, 0x03, 0x42, 0x00,
];

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// The textual form of a principal: base32(crc32 ‖ bytes), lowercase, dashes every 5 chars.
pub fn encode_principal(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut data = crc32(bytes).to_be_bytes().to_vec();
    data.extend_from_slice(bytes);
    let mut raw = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            raw.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        raw.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    raw.as_bytes().chunks(5).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

fn decode_principal(text: &str) -> Result<Vec<u8>, String> {
    let raw: String = text.chars().filter(|&c| c != '-').collect();
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in raw.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err("not an ICP principal (bad character)".into()),
        } as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if out.len() < 4 || out.len() > 33 {
        return Err("not an ICP principal (wrong length)".into());
    }
    let bytes = out[4..].to_vec();
    if encode_principal(&bytes) != text {
        return Err("not an ICP principal (checksum or grouping is wrong)".into());
    }
    Ok(bytes)
}

/// A self-authenticating principal: SHA-224 of the DER public key, then the byte 0x02.
pub fn self_authenticating_principal(der: &[u8]) -> String {
    let mut bytes = sha224(der).to_vec();
    bytes.push(0x02);
    encode_principal(&bytes)
}

fn verify_icp(principal: &str, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<String, String> {
    // Accept the DER form ICP tooling exports, or the bare key.
    let (der, algo) = if key.starts_with(&ED25519_DER_PREFIX) && key.len() == 44 {
        (key.to_vec(), "ed25519")
    } else if key.starts_with(&SECP256K1_DER_PREFIX) && key.len() == 88 {
        (key.to_vec(), "secp256k1")
    } else if key.len() == 32 {
        ([&ED25519_DER_PREFIX[..], key].concat(), "ed25519")
    } else if key.len() == 33 || key.len() == 65 {
        let vk = K256Key::from_sec1_bytes(key).map_err(|_| "not a valid secp256k1 public key")?;
        let point = vk.to_encoded_point(false);
        ([&SECP256K1_DER_PREFIX[..], point.as_bytes()].concat(), "secp256k1")
    } else {
        return Err("public_key must be an Ed25519 or secp256k1 key (raw or DER)".into());
    };
    let derived = self_authenticating_principal(&der);
    if derived != principal {
        return Err(format!(
            "that key's principal is {derived}, not {principal} — Internet Identity (delegated) \
             principals can be claimed but not verified yet; use your agent's own key identity"
        ));
    }
    if algo == "ed25519" {
        let raw: [u8; 32] = der[12..].try_into().unwrap();
        verify_ed25519(&raw, msg, sig)?;
    } else {
        let vk = K256Key::from_sec1_bytes(&der[23..]).map_err(|_| "bad secp256k1 key")?;
        let s = K256Signature::from_slice(sig).map_err(|_| "a secp256k1 signature is 64 bytes (r‖s)")?;
        let s = s.normalize_s().unwrap_or(s);
        vk.verify_prehash(&sha256(msg), &s)
            .map_err(|_| "signature does not verify for that key and challenge")?;
    }
    Ok(format!("{algo} signature by the principal's own key"))
}

// ---- Ethereum -------------------------------------------------------------------------------

fn parse_address(s: &str) -> Result<String, String> {
    let h = s.trim().strip_prefix("0x").ok_or("an address starts with 0x")?;
    if h.len() != 40 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("an address is 0x followed by 40 hex characters".into());
    }
    Ok(format!("0x{}", h.to_ascii_lowercase()))
}

/// `personal_sign` recovery: the address whose key produced `sig` over `msg`.
pub fn recover_eth(msg: &[u8], sig: &[u8]) -> Result<String, String> {
    if sig.len() != 65 {
        return Err("an Ethereum signature is 65 bytes (r‖s‖v)".into());
    }
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    prefixed.extend_from_slice(msg);
    let digest = keccak(&prefixed);
    let v = match sig[64] {
        27 | 28 => sig[64] - 27,
        0 | 1 => sig[64],
        _ => return Err("signature v must be 27/28 or 0/1".into()),
    };
    let s = K256Signature::from_slice(&sig[..64]).map_err(|_| "malformed signature")?;
    let (s, v) = match s.normalize_s() {
        Some(n) => (n, v ^ 1),
        None => (s, v),
    };
    let rid = RecoveryId::from_byte(v).ok_or("bad recovery id")?;
    let vk = K256Key::recover_from_prehash(&digest, &s, rid).map_err(|_| "signature does not recover")?;
    let point = vk.to_encoded_point(false);
    Ok(format!("0x{}", hex(&keccak(&point.as_bytes()[1..])[12..])))
}

/// Accepts `eip155:<chain>:<registry>:<agentId>` or the short `<chain>:<agentId>` (default
/// registry).
fn parse_erc8004(id: &str) -> Result<(u64, String, u128), String> {
    let parts: Vec<&str> = id.trim().split(':').collect();
    let (chain, registry, agent) = match parts.as_slice() {
        ["eip155", c, r, a] => (*c, parse_address(r)?, *a),
        [c, a] => (*c, ERC8004_REGISTRY.to_string(), *a),
        _ => return Err("an ERC-8004 id is eip155:<chainId>:<registry>:<agentId>, or <chainId>:<agentId>".into()),
    };
    let chain: u64 = chain.parse().map_err(|_| "chain id must be a number (1 = Ethereum, 8453 = Base)")?;
    let agent: u128 = agent.parse().map_err(|_| "agentId must be a number")?;
    Ok((chain, registry, agent))
}

fn erc8004_address(net: &dyn Net, chain: u64, registry: &str, agent: u128, sig: &str) -> Result<Option<String>, String> {
    let selector = &keccak(sig.as_bytes())[..4];
    let data = format!("0x{}{:064x}", hex(selector), agent);
    let result = net.eth_call(chain, registry, &data)?;
    let h = result.trim_start_matches("0x");
    if h.len() < 64 {
        return Ok(None);
    }
    let addr = format!("0x{}", &h[24..64].to_ascii_lowercase());
    Ok(if addr == format!("0x{}", "0".repeat(40)) { None } else { Some(addr) })
}

// ---- Web Bot Auth ---------------------------------------------------------------------------

fn check_public_domain(d: &str) -> Result<(), String> {
    let ok_chars = d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    let blocked = d == "localhost"
        || d.parse::<IpAddr>().is_ok()
        || [".local", ".internal", ".localhost", ".lan", ".home", ".corp"].iter().any(|s| d.ends_with(s));
    if !ok_chars || !d.contains('.') || blocked || d.len() > 253 {
        return Err("web_bot_auth id must be a public domain name like bot.example.com".into());
    }
    Ok(())
}

fn directory_lists_key(body: &str, key: &[u8; 32]) -> bool {
    let Ok(doc) = json::parse(body) else { return false };
    let Some(Json::Array(keys)) = doc.get("keys") else { return false };
    keys.iter().any(|k| {
        k.get("kty").and_then(|v| v.as_str()) == Some("OKP")
            && k.get("crv").and_then(|v| v.as_str()) == Some("Ed25519")
            && k.get("x").and_then(|v| v.as_str()).and_then(base64_decode).as_deref() == Some(&key[..])
    })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback() || v6.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
                && v6.to_ipv4_mapped().map(|m| is_public_ip(IpAddr::V4(m))).unwrap_or(true)
        }
    }
}

/// Only lets the Web Bot Auth fetch connect to public addresses, so a bot can't aim this server
/// at its own private network by registering a domain that resolves to 10.x or 127.0.0.1.
struct PublicOnly;

impl ureq::Resolver for PublicOnly {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.filter(|a| is_public_ip(a.ip())).collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "domain does not resolve to a public address"));
        }
        Ok(addrs)
    }
}

/// The real network.
pub struct LiveNet;

impl LiveNet {
    fn rpc_url(chain: u64) -> Option<String> {
        if let Ok(u) = std::env::var(format!("RPC_URL_{chain}")) {
            return Some(u);
        }
        let host = match chain {
            1 => "ethereum-rpc.publicnode.com",
            8453 => "base-rpc.publicnode.com",
            137 => "polygon-bor-rpc.publicnode.com",
            42161 => "arbitrum-one-rpc.publicnode.com",
            10 => "optimism-rpc.publicnode.com",
            56 => "bsc-rpc.publicnode.com",
            43114 => "avalanche-c-chain-rpc.publicnode.com",
            11155111 => "ethereum-sepolia-rpc.publicnode.com",
            84532 => "base-sepolia-rpc.publicnode.com",
            _ => return None,
        };
        Some(format!("https://{host}"))
    }
}

fn read_capped(resp: ureq::Response) -> Result<String, String> {
    let mut body = String::new();
    resp.into_reader()
        .take(64 * 1024)
        .read_to_string(&mut body)
        .map_err(|e| format!("could not read response: {e}"))?;
    Ok(body)
}

impl Net for LiveNet {
    fn eth_call(&self, chain_id: u64, to: &str, data: &str) -> Result<String, String> {
        let url = Self::rpc_url(chain_id).ok_or(format!(
            "chain {chain_id} is not supported yet (supported: 1, 8453, 137, 42161, 10, 56, 43114, 11155111, 84532)"
        ))?;
        let req = Json::obj(vec![
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::num(1.0)),
            ("method", Json::str("eth_call")),
            (
                "params",
                Json::Array(vec![
                    Json::obj(vec![("to", Json::str(to)), ("data", Json::str(data))]),
                    Json::str("latest"),
                ]),
            ),
        ]);
        let resp = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(8))
            .build()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&req.to_string())
            .map_err(|e| format!("chain {chain_id} RPC failed: {e}"))?;
        let body = json::parse(&read_capped(resp)?).map_err(|_| "chain RPC returned bad JSON")?;
        match body.get("result").and_then(|v| v.as_str()) {
            Some(r) => Ok(r.to_string()),
            // A revert (e.g. ownerOf on an agent id that was never minted) comes back as an
            // error, which for our purposes means "no such agent".
            None => Ok("0x".to_string()),
        }
    }

    fn wba_directory(&self, domain: &str) -> Result<String, String> {
        check_public_domain(domain)?;
        let url = format!("https://{domain}/.well-known/http-message-signatures-directory");
        let resp = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(8))
            .redirects(0)
            .resolver(PublicOnly)
            .build()
            .get(&url)
            .call()
            .map_err(|e| format!("could not fetch {url}: {e}"))?;
        read_capped(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use k256::ecdsa::SigningKey as K256Signing;

    struct FakeNet {
        owner: Option<String>,
        wallet: Option<String>,
        directory: String,
    }

    impl Net for FakeNet {
        fn eth_call(&self, _chain: u64, _to: &str, data: &str) -> Result<String, String> {
            let owner_sel = hex(&keccak(b"ownerOf(uint256)")[..4]);
            let addr = if data[2..10] == owner_sel { &self.owner } else { &self.wallet };
            Ok(match addr {
                Some(a) => format!("0x{:0>64}", a.trim_start_matches("0x")),
                None => "0x".into(),
            })
        }
        fn wba_directory(&self, _domain: &str) -> Result<String, String> {
            Ok(self.directory.clone())
        }
    }

    fn no_net() -> FakeNet {
        FakeNet { owner: None, wallet: None, directory: String::new() }
    }

    fn eth_sign(key: &K256Signing, msg: &str) -> String {
        let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
        prefixed.extend_from_slice(msg.as_bytes());
        let (sig, rid) = key.sign_prehash_recoverable(&keccak(&prefixed)).unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + rid.to_byte());
        format!("0x{}", hex(&out))
    }

    fn eth_address(key: &K256Signing) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        format!("0x{}", hex(&keccak(&point.as_bytes()[1..])[12..]))
    }

    const NOW: i64 = 1_790_000_000_000;

    #[test]
    fn crc32_and_principal_text_match_the_ic_spec() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(encode_principal(&[]), "aaaaa-aa"); // management canister
        assert_eq!(encode_principal(&[4]), "2vxsx-fae"); // anonymous
        assert_eq!(decode_principal("2vxsx-fae").unwrap(), vec![4]);
        assert!(decode_principal("2vxsx-faf").is_err());
    }

    #[test]
    fn a_known_web3_signature_recovers_to_its_address() {
        // web3.js accounts.sign("Some data", 0x4c08…2318) documentation example.
        let sig = decode_bytes("0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c").unwrap();
        assert_eq!(recover_eth(b"Some data", &sig).unwrap(), "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
    }

    #[test]
    fn icp_ed25519_proof_verifies_and_a_wrong_principal_does_not() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let der = [&ED25519_DER_PREFIX[..], sk.verifying_key().as_bytes()].concat();
        let principal = self_authenticating_principal(&der);
        assert_eq!(normalize("icp", &principal.to_uppercase()).unwrap(), principal);
        let msg = challenge("bot1", "icp", &principal, NOW);
        let sig = hex(&sk.sign(msg.as_bytes()).to_bytes());
        let pk = hex(&der);
        let proof = Proof { agent_id: "bot1", protocol: "icp", external_id: &principal, timestamp_ms: NOW, signature: &sig, public_key: Some(&pk) };
        assert!(verify(&proof, NOW, &no_net()).is_ok());
        // Same signature, claimed for a different agent: rejected.
        let stolen = Proof { agent_id: "mallory", ..proof };
        assert!(verify(&stolen, NOW, &no_net()).is_err());
        // Someone else's principal: rejected.
        let other = encode_principal(&[1, 2, 3, 2]);
        let wrong = Proof { agent_id: "bot1", protocol: "icp", external_id: &other, timestamp_ms: NOW, signature: &sig, public_key: Some(&pk) };
        assert!(verify(&wrong, NOW, &no_net()).is_err());
    }

    #[test]
    fn icp_secp256k1_proof_verifies() {
        let sk = K256Signing::from_slice(&[9u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let der = [&SECP256K1_DER_PREFIX[..], point.as_bytes()].concat();
        let principal = self_authenticating_principal(&der);
        let msg = challenge("bot1", "icp", &principal, NOW);
        let sig: K256Signature = k256::ecdsa::signature::hazmat::PrehashSigner::sign_prehash(&sk, &sha256(msg.as_bytes())).unwrap();
        let (sig, pk) = (hex(&sig.to_bytes()), hex(&der));
        let proof = Proof { agent_id: "bot1", protocol: "icp", external_id: &principal, timestamp_ms: NOW, signature: &sig, public_key: Some(&pk) };
        assert_eq!(verify(&proof, NOW, &no_net()).unwrap(), "secp256k1 signature by the principal's own key");
    }

    #[test]
    fn eth_proof_binds_only_the_signing_address_and_expires() {
        let sk = K256Signing::from_slice(&[3u8; 32]).unwrap();
        let addr = eth_address(&sk);
        let msg = challenge("bot1", "eth", &addr, NOW);
        let sig = eth_sign(&sk, &msg);
        let proof = Proof { agent_id: "bot1", protocol: "eth", external_id: &addr, timestamp_ms: NOW, signature: &sig, public_key: None };
        assert!(verify(&proof, NOW, &no_net()).is_ok());
        assert!(verify(&proof, NOW + PROOF_WINDOW_MS + 1, &no_net()).unwrap_err().contains("10 minutes"));
        let other = "0x000000000000000000000000000000000000dead".to_string();
        let wrong = Proof { external_id: &other, ..proof };
        assert!(verify(&wrong, NOW, &no_net()).is_err());
    }

    #[test]
    fn erc8004_requires_the_on_chain_owner_or_agent_wallet() {
        let sk = K256Signing::from_slice(&[5u8; 32]).unwrap();
        let addr = eth_address(&sk);
        let id = normalize("erc8004", "8453:42").unwrap();
        assert_eq!(id, format!("eip155:8453:{ERC8004_REGISTRY}:42"));
        let msg = challenge("bot1", "erc8004", &id, NOW);
        let sig = eth_sign(&sk, &msg);
        let proof = Proof { agent_id: "bot1", protocol: "erc8004", external_id: &id, timestamp_ms: NOW, signature: &sig, public_key: None };

        let owned = FakeNet { owner: Some(addr.clone()), wallet: None, directory: String::new() };
        assert!(verify(&proof, NOW, &owned).unwrap().contains("owner"));
        let wallet = FakeNet { owner: Some("0x1111111111111111111111111111111111111111".into()), wallet: Some(addr.clone()), directory: String::new() };
        assert!(verify(&proof, NOW, &wallet).unwrap().contains("agent wallet"));
        let someone_else = FakeNet { owner: Some("0x1111111111111111111111111111111111111111".into()), wallet: None, directory: String::new() };
        assert!(verify(&proof, NOW, &someone_else).unwrap_err().contains("owned by"));
        assert!(verify(&proof, NOW, &no_net()).unwrap_err().contains("does not exist"));
    }

    #[test]
    fn did_key_and_web_bot_auth_proofs() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        // Build the did:key by base58-encoding 0xed01 ‖ key.
        let mut n = vec![0xed, 0x01];
        n.extend_from_slice(&pk);
        let did = format!("did:key:z{}", base58_encode(&n));
        assert!(did.starts_with("did:key:z6Mk"));
        let msg = challenge("bot1", "did", &did, NOW);
        let sig = hex(&sk.sign(msg.as_bytes()).to_bytes());
        let proof = Proof { agent_id: "bot1", protocol: "did", external_id: &did, timestamp_ms: NOW, signature: &sig, public_key: None };
        assert!(verify(&proof, NOW, &no_net()).is_ok());

        let domain = "bot.example.com";
        let msg = challenge("bot1", "web_bot_auth", domain, NOW);
        let sig = hex(&sk.sign(msg.as_bytes()).to_bytes());
        let x: String = base64url(&pk);
        let listed = FakeNet { owner: None, wallet: None, directory: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}]}}"#) };
        let pk_hex = hex(&pk);
        let proof = Proof { agent_id: "bot1", protocol: "web_bot_auth", external_id: domain, timestamp_ms: NOW, signature: &sig, public_key: Some(&pk_hex) };
        assert!(verify(&proof, NOW, &listed).is_ok());
        let unlisted = FakeNet { owner: None, wallet: None, directory: r#"{"keys":[]}"#.into() };
        assert!(verify(&proof, NOW, &unlisted).is_err());
    }

    #[test]
    fn private_hosts_are_refused_for_web_bot_auth() {
        for d in ["localhost", "127.0.0.1", "metadata.internal", "nodot", "10.0.0.1"] {
            assert!(normalize("web_bot_auth", d).is_err(), "{d}");
        }
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
    }

    fn base58_encode(bytes: &[u8]) -> String {
        const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut digits: Vec<u8> = Vec::new();
        for &b in bytes {
            let mut carry = b as u32;
            for d in digits.iter_mut() {
                carry += (*d as u32) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let zeros = bytes.iter().take_while(|&&b| b == 0).count();
        "1".repeat(zeros) + &digits.iter().rev().map(|&d| A[d as usize] as char).collect::<String>()
    }

    fn base64url(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }
}
