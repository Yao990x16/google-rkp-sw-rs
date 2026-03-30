use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use aes::Aes128;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use ciborium::value::{Integer, Value};
use clap::{Args, Parser, Subcommand};
use cmac::{Cmac, Mac};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use p256::SecretKey;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use reqwest::blocking::Client;
use thiserror::Error;

const ALG_EDDSA: i64 = -8;
const ALG_ES256: i64 = -7;

const CWT_ISSUER: i64 = 1;
const CWT_SUBJECT: i64 = 2;
const DICE_PROFILE_NAME: i64 = -4_670_554;
const DICE_SUBJECT_PUB_KEY: i64 = -4_670_552;
const DICE_KEY_USAGE: i64 = -4_670_553;

const RKP_SERVER_URL: &str = "https://remoteprovisioning.googleapis.com/v1";

#[derive(Debug, Error)]
enum RkpError {
    #[error("device not registered: {0}")]
    DeviceNotRegistered(String),
    #[error("client error: {0}")]
    Client(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

#[derive(Clone)]
struct DeviceKeys {
    seed: [u8; 32],
    signing_key: SigningKey,
    pub_raw: [u8; 32],
}

impl DeviceKeys {
    fn new(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pub_raw = verifying_key.to_bytes();
        Self {
            seed,
            signing_key,
            pub_raw,
        }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }

    fn cose_key(&self) -> Value {
        Value::Map(vec![
            (vi(1), vi(1)),
            (vi(3), vi(ALG_EDDSA)),
            (vi(-1), vi(6)),
            (vi(-2), Value::Bytes(self.pub_raw.to_vec())),
        ])
    }
}

struct HardwareKdf {
    key: [u8; 16],
}

impl HardwareKdf {
    fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    fn cmac_block(&self, counter: u32, label: &[u8]) -> Result<[u8; 16]> {
        let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(&self.key)
            .map_err(|e| anyhow!("CMAC init failed: {e}"))?;
        let mut input = Vec::with_capacity(4 + label.len());
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(label);
        mac.update(&input);
        let out = mac.finalize().into_bytes();
        let mut block = [0u8; 16];
        block.copy_from_slice(&out);
        Ok(block)
    }

    fn derive(&self, label: &[u8], length: usize) -> Result<Vec<u8>> {
        if label.is_empty() {
            bail!("empty label not supported");
        }
        let blocks = length.div_ceil(16);
        let mut out = Vec::with_capacity(blocks * 16);
        for i in 1..=blocks {
            out.extend_from_slice(&self.cmac_block(i as u32, label)?);
        }
        out.truncate(length);
        Ok(out)
    }
}

#[derive(Parser)]
#[command(name = "google-rkp-sw")]
#[command(about = "Software RKP — Rust rewrite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Info(KeyArgs),
    Provision(ProvisionArgs),
    Keybox(KeyboxArgs),
    Verify(VerifyArgs),
}

#[derive(Args, Clone)]
struct KeyArgs {
    #[arg(long)]
    seed: Option<String>,
    #[arg(long = "hw-key")]
    hw_key: Option<String>,
    #[arg(long = "kdf-label")]
    kdf_label: Option<String>,
    #[arg(long)]
    config: Option<String>,
}

#[derive(Args, Clone)]
struct ProvisionArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[arg(short = 'n', long = "num-keys", default_value_t = 1)]
    num_keys: usize,
    #[arg(short = 'u', long = "server-url")]
    server_url: Option<String>,
}

#[derive(Args, Clone)]
struct KeyboxArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[arg(short = 'o', long = "output", default_value = "keybox.xml")]
    output: String,
    #[arg(short = 'u', long = "server-url")]
    server_url: Option<String>,
}

#[derive(Args, Clone)]
struct VerifyArgs {
    csr_file: String,
}

fn vi(n: i64) -> Value {
    Value::Integer(Integer::from(n))
}

fn cbor_dump(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).context("CBOR encode failed")?;
    Ok(out)
}

fn cbor_load(data: &[u8]) -> Result<Value> {
    ciborium::from_reader(data).context("CBOR decode failed")
}

fn parse_ini(path: &str) -> Result<HashMap<String, HashMap<String, String>>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read config: {path}"))?;

    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current = String::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_ascii_lowercase();
            sections.entry(current.clone()).or_default();
            continue;
        }

        let Some(eq) = line.find('=') else {
            continue;
        };
        if current.is_empty() {
            continue;
        }

        let key = line[..eq].trim().to_ascii_lowercase();
        let value = line[eq + 1..].trim().to_string();
        sections
            .entry(current.clone())
            .or_default()
            .insert(key, value);
    }

    Ok(sections)
}

fn default_device_info() -> HashMap<String, Value> {
    let mut map = HashMap::new();
    map.insert("brand".into(), Value::Text("generic".into()));
    map.insert("fused".into(), vi(1));
    map.insert("model".into(), Value::Text("default".into()));
    map.insert("device".into(), Value::Text("default".into()));
    map.insert("product".into(), Value::Text("default".into()));
    map.insert("vb_state".into(), Value::Text("green".into()));
    map.insert("vbmeta_digest".into(), Value::Bytes(vec![0u8; 32]));
    map.insert("os_version".into(), Value::Text("13".into()));
    map.insert("manufacturer".into(), Value::Text("generic".into()));
    map.insert("security_level".into(), Value::Text("tee".into()));
    map.insert("boot_patch_level".into(), vi(20_250_101));
    map.insert("bootloader_state".into(), Value::Text("locked".into()));
    map.insert("system_patch_level".into(), vi(202_501));
    map.insert("vendor_patch_level".into(), vi(20_250_101));
    map
}

fn load_device_config(path: Option<&str>) -> Result<HashMap<String, Value>> {
    let mut info = default_device_info();
    let Some(path) = path else {
        return Ok(info);
    };

    let cfg = parse_ini(path)?;
    let Some(device) = cfg.get("device") else {
        return Ok(info);
    };

    for (key, raw) in device {
        let val = if key == "vbmeta_digest" {
            Value::Bytes(hex::decode(raw).with_context(|| "invalid hex in vbmeta_digest")?)
        } else if key == "fused" || key.ends_with("_patch_level") {
            let n: i64 = raw
                .parse()
                .with_context(|| format!("invalid integer for {key}"))?;
            vi(n)
        } else {
            Value::Text(raw.clone())
        };
        info.insert(key.clone(), val);
    }

    Ok(info)
}

fn get_fingerprint(cfg_path: Option<&str>) -> Result<String> {
    if let Some(path) = cfg_path {
        let cfg = parse_ini(path)?;
        if let Some(fp) = cfg
            .get("fingerprint")
            .and_then(|m| m.get("value"))
            .filter(|s| !s.is_empty())
        {
            return Ok(fp.clone());
        }
    }
    Ok("generic/default/default:13/TP1A.220624.014/0:user/release-keys".into())
}

fn canonicalize_map_entries(mut entries: Vec<(Value, Value)>) -> Result<Vec<(Value, Value)>> {
    let mut keyed = Vec::with_capacity(entries.len());
    for (k, v) in entries.drain(..) {
        keyed.push((cbor_dump(&k)?, k, v));
    }

    keyed.sort_by(|a, b| {
        let len_cmp = a.0.len().cmp(&b.0.len());
        if len_cmp != Ordering::Equal {
            len_cmp
        } else {
            a.0.cmp(&b.0)
        }
    });

    Ok(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
}

fn require_text_value<'a>(info: &'a HashMap<String, Value>, key: &str) -> Result<&'a str> {
    match info.get(key) {
        Some(Value::Text(s)) => Ok(s),
        Some(_) => bail!("DeviceInfoV3 field {key} must be text"),
        None => bail!("DeviceInfoV3 missing required field: {key}"),
    }
}

fn require_int_value(info: &HashMap<String, Value>, key: &str) -> Result<i64> {
    match info.get(key) {
        Some(Value::Integer(i)) => {
            i64::try_from(*i).map_err(|_| anyhow!("DeviceInfoV3 field {key} is out of range"))
        }
        Some(_) => bail!("DeviceInfoV3 field {key} must be integer"),
        None => bail!("DeviceInfoV3 missing required field: {key}"),
    }
}

fn build_device_info_v3_map(device_info: &HashMap<String, Value>) -> Result<Value> {
    let required = [
        "brand",
        "manufacturer",
        "product",
        "model",
        "device",
        "vb_state",
        "bootloader_state",
        "vbmeta_digest",
        "system_patch_level",
        "boot_patch_level",
        "vendor_patch_level",
        "security_level",
        "fused",
    ];
    let optional = ["os_version"];
    let extra_allowed = ["dice_issuer", "dice_subject"];

    for key in device_info.keys() {
        if !required.contains(&key.as_str())
            && !optional.contains(&key.as_str())
            && !extra_allowed.contains(&key.as_str())
        {
            bail!("unsupported DeviceInfoV3 field in config: {key}");
        }
    }

    let vb_state = require_text_value(device_info, "vb_state")?;
    if !matches!(vb_state, "green" | "yellow" | "orange") {
        bail!("DeviceInfoV3 vb_state must be one of: green, yellow, orange");
    }

    let bootloader_state = require_text_value(device_info, "bootloader_state")?;
    if !matches!(bootloader_state, "locked" | "unlocked") {
        bail!("DeviceInfoV3 bootloader_state must be one of: locked, unlocked");
    }

    let security_level = require_text_value(device_info, "security_level")?;
    if !matches!(security_level, "tee" | "strongbox") {
        bail!("DeviceInfoV3 security_level must be one of: tee, strongbox");
    }

    let fused = require_int_value(device_info, "fused")?;
    if !matches!(fused, 0 | 1) {
        bail!("DeviceInfoV3 fused must be 0 or 1");
    }

    for key in [
        "system_patch_level",
        "boot_patch_level",
        "vendor_patch_level",
    ] {
        let value = require_int_value(device_info, key)?;
        if value < 0 {
            bail!("DeviceInfoV3 field {key} must be non-negative");
        }
    }

    let vbmeta = match device_info.get("vbmeta_digest") {
        Some(Value::Bytes(b)) => b,
        Some(_) => bail!("DeviceInfoV3 field vbmeta_digest must be bytes"),
        None => bail!("DeviceInfoV3 missing required field: vbmeta_digest"),
    };
    if vbmeta.len() != 32 {
        bail!("DeviceInfoV3 vbmeta_digest must be 32 bytes");
    }

    if let Some(v) = device_info.get("os_version") {
        if !matches!(v, Value::Text(_)) {
            bail!("DeviceInfoV3 field os_version must be text");
        }
    }

    let mut entries = Vec::new();
    for key in required {
        entries.push((
            Value::Text(key.to_string()),
            device_info
                .get(key)
                .ok_or_else(|| anyhow!("DeviceInfoV3 missing required field: {key}"))?
                .clone(),
        ));
    }
    for key in optional {
        if let Some(v) = device_info.get(key) {
            entries.push((Value::Text(key.to_string()), v.clone()));
        }
    }

    Ok(Value::Map(canonicalize_map_entries(entries)?))
}

fn decode_hex_exact<const N: usize>(hex_str: &str, label: &str) -> Result<[u8; N]> {
    let raw = hex::decode(hex_str).with_context(|| format!("invalid hex for {label}"))?;
    if raw.len() != N {
        bail!("{label} must be {N} bytes, got {}", raw.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn resolve_seed(key: &KeyArgs) -> Result<[u8; 32]> {
    if key.seed.is_some() && key.hw_key.is_some() {
        bail!("--seed and --hw-key are mutually exclusive");
    }

    if let Some(seed_hex) = &key.seed {
        return decode_hex_exact::<32>(seed_hex, "seed");
    }

    if let Some(hw_key_hex) = &key.hw_key {
        let label = key
            .kdf_label
            .as_deref()
            .ok_or_else(|| anyhow!("--kdf-label is required with --hw-key"))?;
        let hw_key = decode_hex_exact::<16>(hw_key_hex, "hw-key")?;
        let seed = HardwareKdf::new(hw_key).derive(label.as_bytes(), 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&seed);
        return Ok(out);
    }

    bail!("no key material provided; use --seed <64-hex> or --hw-key <32-hex> --kdf-label <label>")
}

fn cose_sign1(keys: &DeviceKeys, protected: Value, payload: &[u8]) -> Result<Value> {
    let prot_bytes = cbor_dump(&protected)?;
    let sig_input = cbor_dump(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(prot_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]))?;

    Ok(Value::Array(vec![
        Value::Bytes(prot_bytes),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(keys.sign(&sig_input)),
    ]))
}

fn build_dice_entry(keys: &DeviceKeys, device_info: &HashMap<String, Value>) -> Result<Value> {
    let issuer = text_from_map(device_info, "dice_issuer").unwrap_or_else(|| "Android".into());
    let subject = text_from_map(device_info, "dice_subject").unwrap_or_else(|| "KeyMint".into());

    let payload = cbor_dump(&Value::Map(canonicalize_map_entries(vec![
        (vi(CWT_ISSUER), Value::Text(issuer)),
        (vi(CWT_SUBJECT), Value::Text(subject)),
        (vi(DICE_PROFILE_NAME), Value::Text("android.15".into())),
        (
            vi(DICE_SUBJECT_PUB_KEY),
            Value::Bytes(cbor_dump(&keys.cose_key())?),
        ),
        (vi(DICE_KEY_USAGE), Value::Bytes(vec![0x20])),
    ])?))?;

    cose_sign1(keys, Value::Map(vec![(vi(1), vi(ALG_EDDSA))]), &payload)
}

fn build_dice_chain(keys: &DeviceKeys, device_info: &HashMap<String, Value>) -> Result<Value> {
    Ok(Value::Array(vec![
        keys.cose_key(),
        build_dice_entry(keys, device_info)?,
    ]))
}

fn generate_ec_keypair() -> Result<(SecretKey, Value)> {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| anyhow!("missing X coordinate"))?
        .to_vec();
    let y = point
        .y()
        .ok_or_else(|| anyhow!("missing Y coordinate"))?
        .to_vec();

    let cose_pub = Value::Map(vec![
        (vi(1), vi(2)),
        (vi(3), vi(ALG_ES256)),
        (vi(-1), vi(1)),
        (vi(-2), Value::Bytes(x)),
        (vi(-3), Value::Bytes(y)),
    ]);

    Ok((secret, cose_pub))
}

fn build_csr(
    keys: &DeviceKeys,
    challenge: &[u8],
    keys_to_sign: &[Value],
    device_info: &HashMap<String, Value>,
) -> Result<Vec<u8>> {
    if challenge.len() > 64 {
        bail!("challenge size must be <= 64 bytes for generateCertificateRequestV2");
    }

    let device_map = build_device_info_v3_map(device_info)?;

    let csr_payload = cbor_dump(&Value::Array(vec![
        vi(3),
        Value::Text("keymint".into()),
        device_map,
        Value::Array(keys_to_sign.to_vec()),
    ]))?;

    let dice = build_dice_chain(keys, device_info)?;

    let signed_payload = cbor_dump(&Value::Array(vec![
        Value::Bytes(challenge.to_vec()),
        Value::Bytes(csr_payload),
    ]))?;
    let signed_data = cose_sign1(
        keys,
        Value::Map(vec![(vi(1), vi(ALG_EDDSA))]),
        &signed_payload,
    )?;

    // AuthenticatedRequest per generateCertificateRequestV2.cddl:
    // [1, UdsCerts, DiceCertChain, SignedData]
    cbor_dump(&Value::Array(vec![
        vi(1),
        Value::Map(vec![]),
        dice,
        signed_data,
    ]))
}

fn map_get_i<'a>(entries: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| {
        let Value::Integer(i) = k else {
            return None;
        };
        let n = i64::try_from(*i).ok()?;
        (n == key).then_some(v)
    })
}

fn value_as_i64(v: &Value) -> Option<i64> {
    let Value::Integer(i) = v else {
        return None;
    };
    i64::try_from(*i).ok()
}

fn value_as_bytes(v: &Value) -> Option<&[u8]> {
    let Value::Bytes(b) = v else {
        return None;
    };
    Some(b)
}

fn value_as_array(v: &Value) -> Option<&[Value]> {
    let Value::Array(arr) = v else {
        return None;
    };
    Some(arr)
}

fn text_from_map(map: &HashMap<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(Value::Text(s)) => Some(s.clone()),
        Some(Value::Integer(i)) => i64::try_from(*i).ok().map(|n| n.to_string()),
        _ => None,
    }
}

fn fetch_eek(
    client: &Client,
    fingerprint: &str,
    server_url: &str,
) -> Result<(Vec<u8>, Vec<u8>, i64, Value)> {
    let url = format!("{server_url}:fetchEekChain");
    let prov_info = cbor_dump(&Value::Map(vec![
        (
            Value::Text("fingerprint".into()),
            Value::Text(fingerprint.into()),
        ),
        (Value::Text("id".into()), vi(42)),
    ]))?;

    println!("  Fetching EEK from {url}...");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/cbor")
        .body(prov_info)
        .send()
        .with_context(|| "fetchEekChain request failed")?;

    let status = resp.status();
    let data = resp
        .bytes()
        .with_context(|| "failed to read fetchEekChain response")?
        .to_vec();
    if !status.is_success() {
        bail!("fetchEekChain HTTP {}", status.as_u16());
    }

    let result = cbor_load(&data)?;
    let arr = value_as_array(&result).ok_or_else(|| anyhow!("invalid fetchEekChain payload"))?;
    if arr.len() < 2 {
        bail!("fetchEekChain payload too short");
    }

    let eek_chains = arr[0].clone();
    let challenge = value_as_bytes(&arr[1])
        .ok_or_else(|| anyhow!("invalid challenge field"))?
        .to_vec();

    println!(
        "  Challenge: {}... ({}B)",
        hex::encode(&challenge)[..20.min(challenge.len() * 2)].to_string(),
        challenge.len()
    );

    let eek_chain_arr = value_as_array(&arr[0]).ok_or_else(|| anyhow!("invalid eek_chains"))?;
    println!("  EEK chains: {} curves", eek_chain_arr.len());

    let mut eek_pub: Option<Vec<u8>> = None;
    let mut eek_curve: Option<i64> = None;

    for chain_entry in eek_chain_arr {
        let Some(entry) = value_as_array(chain_entry) else {
            continue;
        };
        if entry.len() < 2 {
            continue;
        }

        let Some(curve) = value_as_i64(&entry[0]) else {
            continue;
        };
        let Some(chain) = value_as_array(&entry[1]) else {
            continue;
        };
        let Some(last_cert) = chain.last().and_then(value_as_array) else {
            continue;
        };
        if last_cert.len() < 3 {
            continue;
        }

        let Some(payload_bytes) = value_as_bytes(&last_cert[2]) else {
            continue;
        };
        let Ok(payload) = cbor_load(payload_bytes) else {
            continue;
        };
        let Some(payload_map) = (match payload {
            Value::Map(ref m) => Some(m.as_slice()),
            _ => None,
        }) else {
            continue;
        };

        let pub_bytes = map_get_i(payload_map, -2).and_then(value_as_bytes);
        let crv = map_get_i(payload_map, -1).and_then(value_as_i64);

        if let (Some(pb), Some(c)) = (pub_bytes, crv) {
            if curve == 2 && c == 4 {
                eek_pub = Some(pb.to_vec());
                eek_curve = Some(curve);
                break;
            }
        }
    }

    if eek_pub.is_none() {
        for chain_entry in eek_chain_arr {
            let Some(entry) = value_as_array(chain_entry) else {
                continue;
            };
            if entry.len() < 2 {
                continue;
            }
            let Some(curve) = value_as_i64(&entry[0]) else {
                continue;
            };
            if curve != 1 {
                continue;
            }

            let Some(chain) = value_as_array(&entry[1]) else {
                continue;
            };
            let Some(last_cert) = chain.last().and_then(value_as_array) else {
                continue;
            };
            if last_cert.len() < 3 {
                continue;
            }

            let Some(payload_bytes) = value_as_bytes(&last_cert[2]) else {
                continue;
            };
            let Ok(payload) = cbor_load(payload_bytes) else {
                continue;
            };
            let Some(payload_map) = (match payload {
                Value::Map(ref m) => Some(m.as_slice()),
                _ => None,
            }) else {
                continue;
            };

            if let Some(pb) = map_get_i(payload_map, -2).and_then(value_as_bytes) {
                eek_pub = Some(pb.to_vec());
                eek_curve = Some(curve);
                break;
            }
        }
    }

    let pub_bytes = eek_pub.ok_or_else(|| anyhow!("no usable EEK public key found"))?;
    let curve = eek_curve.unwrap_or(2);
    Ok((challenge, pub_bytes, curve, eek_chains))
}

fn submit_csr(
    client: &Client,
    csr_bytes: &[u8],
    challenge: &[u8],
    server_url: &str,
) -> std::result::Result<Vec<Vec<u8>>, RkpError> {
    let challenge_b64 = URL_SAFE.encode(challenge);
    let url = format!("{server_url}:signCertificates?challenge={challenge_b64}");

    println!("  Submitting CSR to server...");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/cbor")
        .body(csr_bytes.to_vec())
        .send()
        .map_err(|e| RkpError::Transport(e.to_string()))?;

    let status = resp.status();
    let code = status.as_u16();

    if !status.is_success() {
        let body = resp.text().unwrap_or_else(|_| "<no body>".into());
        return match code {
            444 => Err(RkpError::DeviceNotRegistered(body)),
            400..=499 => Err(RkpError::Client(format!("HTTP {code}: {body}"))),
            500..=599 => Err(RkpError::Server(format!("HTTP {code}: {body}"))),
            _ => Err(RkpError::Transport(format!("HTTP {code}: {body}"))),
        };
    }

    let data = resp
        .bytes()
        .map_err(|e| RkpError::Transport(e.to_string()))?
        .to_vec();
    println!("  Response: {} bytes", data.len());

    let result = cbor_load(&data).map_err(|e| RkpError::Protocol(e.to_string()))?;
    let outer = value_as_array(&result)
        .ok_or_else(|| RkpError::Protocol("invalid response structure".into()))?;

    let inner = if let Some(first) = outer.first() {
        if let Some(arr) = value_as_array(first) {
            arr
        } else {
            outer
        }
    } else {
        return Ok(vec![]);
    };

    if inner.len() < 2 {
        return Ok(vec![]);
    }

    let shared = value_as_bytes(&inner[0]).unwrap_or(&[]);
    let unique = value_as_array(&inner[1]).unwrap_or(&[]);

    let mut chains = Vec::new();
    for uc in unique {
        if let Some(unique_bytes) = value_as_bytes(uc) {
            let mut chain = Vec::with_capacity(shared.len() + unique_bytes.len());
            chain.extend_from_slice(shared);
            chain.extend_from_slice(unique_bytes);
            chains.push(chain);
        }
    }
    println!("  Received {} certificate chain(s)", chains.len());

    Ok(chains)
}

fn parse_der_cert_chain(data: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() && data[pos] == 0x30 {
        let len_byte = data[pos + 1];
        let (header_len, content_len) = if (len_byte & 0x80) != 0 {
            let num_len_bytes = (len_byte & 0x7f) as usize;
            if pos + 2 + num_len_bytes > data.len() {
                break;
            }
            let mut len = 0usize;
            for b in &data[pos + 2..pos + 2 + num_len_bytes] {
                len = (len << 8) | (*b as usize);
            }
            (2 + num_len_bytes, len)
        } else {
            (2usize, len_byte as usize)
        };

        let cert_len = header_len + content_len;
        if pos + cert_len > data.len() {
            break;
        }

        certs.push(data[pos..pos + cert_len].to_vec());
        pos += cert_len;
    }

    certs
}

fn cert_subject_issuer(der: &[u8]) -> Option<(String, String)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some((cert.subject().to_string(), cert.issuer().to_string()))
}

fn sort_cert_chain(certs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if certs.len() <= 1 {
        return certs.to_vec();
    }

    let mut meta: Vec<(String, String)> = Vec::with_capacity(certs.len());
    for cert in certs {
        let Some((subject, issuer)) = cert_subject_issuer(cert) else {
            return certs.to_vec();
        };
        meta.push((subject, issuer));
    }

    let mut by_subject: HashMap<String, usize> = HashMap::new();
    for (idx, (subject, _)) in meta.iter().enumerate() {
        by_subject.insert(subject.clone(), idx);
    }

    let mut subjects_that_issue: HashSet<String> = HashSet::new();
    for (subject, issuer) in &meta {
        if subject != issuer {
            subjects_that_issue.insert(issuer.clone());
        }
    }

    let mut leaf_idx = None;
    for (idx, (subject, _)) in meta.iter().enumerate() {
        if !subjects_that_issue.contains(subject) {
            leaf_idx = Some(idx);
            break;
        }
    }

    let Some(mut current) = leaf_idx else {
        return certs.to_vec();
    };

    let mut ordered_indices = Vec::new();
    let mut seen = HashSet::new();

    ordered_indices.push(current);
    seen.insert(meta[current].0.clone());

    while ordered_indices.len() < certs.len() {
        let issuer = &meta[current].1;
        if let Some(next) = by_subject.get(issuer) {
            if seen.contains(&meta[*next].0) {
                break;
            }
            current = *next;
            ordered_indices.push(current);
            seen.insert(meta[current].0.clone());
        } else {
            break;
        }
    }

    for (idx, (subject, _)) in meta.iter().enumerate() {
        if !seen.contains(subject) {
            ordered_indices.push(idx);
        }
    }

    ordered_indices
        .into_iter()
        .map(|i| certs[i].clone())
        .collect()
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}

fn indent_lines(s: &str, indent: &str) -> String {
    s.lines()
        .map(|l| format!("{indent}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_keybox_xml(ec_priv_pem: &str, ec_cert_chain: &[Vec<u8>], device_id: &str) -> String {
    let ordered = sort_cert_chain(ec_cert_chain);

    let indent1 = "    ";
    let indent2 = "        ";
    let indent3 = "            ";

    let mut lines = vec![
        "<?xml version=\"1.0\"?>".to_string(),
        "<AndroidAttestation>".to_string(),
        format!("{indent1}<NumberOfKeyboxes>1</NumberOfKeyboxes>"),
        format!("{indent1}<Keybox DeviceID=\"{device_id}\">"),
        format!("{indent2}<Key algorithm=\"ecdsa\">"),
        format!("{indent2}    <PrivateKey format=\"pem\">"),
        indent_lines(ec_priv_pem.trim(), &format!("{indent2}    ")),
        format!("{indent2}    </PrivateKey>"),
        format!("{indent2}    <CertificateChain>"),
        format!(
            "{indent3}    <NumberOfCertificates>{}</NumberOfCertificates>",
            ordered.len()
        ),
    ];

    for cert in ordered {
        let cert_pem = pem_wrap("CERTIFICATE", &cert);
        lines.push(format!("{indent3}    <Certificate format=\"pem\">"));
        lines.push(indent_lines(&cert_pem, &format!("{indent3}    ")));
        lines.push(format!("{indent3}    </Certificate>"));
    }

    lines.extend([
        format!("{indent2}    </CertificateChain>"),
        format!("{indent2}</Key>"),
        format!("{indent1}</Keybox>"),
        "</AndroidAttestation>".to_string(),
        String::new(),
    ]);

    lines.join("\n")
}

fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("failed to build HTTP client")
}

fn cmd_info(args: KeyArgs) -> Result<()> {
    let seed = resolve_seed(&args)?;
    let keys = DeviceKeys::new(seed);
    let device_info = load_device_config(args.config.as_deref())?;

    println!("Ed25519 seed:   {}", hex::encode(keys.seed));
    println!("Ed25519 pubkey: {}", hex::encode(keys.pub_raw));
    println!(
        "Device:         {} {} ({})",
        text_from_map(&device_info, "brand").unwrap_or_else(|| "unknown".into()),
        text_from_map(&device_info, "model").unwrap_or_else(|| "unknown".into()),
        text_from_map(&device_info, "device").unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Fused:          {}",
        text_from_map(&device_info, "fused").unwrap_or_else(|| "unknown".into())
    );
    println!(
        "VB state:       {}",
        text_from_map(&device_info, "vb_state").unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Bootloader:     {}",
        text_from_map(&device_info, "bootloader_state").unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Patches:        boot={} system={} vendor={}",
        text_from_map(&device_info, "boot_patch_level").unwrap_or_else(|| "unknown".into()),
        text_from_map(&device_info, "system_patch_level").unwrap_or_else(|| "unknown".into()),
        text_from_map(&device_info, "vendor_patch_level").unwrap_or_else(|| "unknown".into()),
    );

    if let (Some(hw_key_hex), Some(label)) = (args.hw_key, args.kdf_label) {
        let hw_key = decode_hex_exact::<16>(&hw_key_hex, "hw-key")?;
        let out = HardwareKdf::new(hw_key).derive(label.as_bytes(), 32)?;
        println!("\nHardware KDF simulation:");
        println!("  KDF(\"{label}\"): {}", hex::encode(out));
    }

    Ok(())
}

fn cmd_provision(args: ProvisionArgs) -> Result<()> {
    let seed = resolve_seed(&args.key)?;
    let keys = DeviceKeys::new(seed);
    let device_info = load_device_config(args.key.config.as_deref())?;
    let fingerprint = get_fingerprint(args.key.config.as_deref())?;

    let mode = if args.key.hw_key.is_some() {
        "hw-kdf"
    } else {
        "direct-seed"
    };
    println!("Mode:            {mode}");
    println!("CDI_Leaf pubkey: {}", hex::encode(keys.pub_raw));

    println!("\n[1] Generating {} EC P-256 keypair(s)...", args.num_keys);
    let mut cose_pubs = Vec::new();
    for i in 0..args.num_keys {
        let (_priv, pubkey) = generate_ec_keypair()?;
        cose_pubs.push(pubkey);
        println!("  Key {i}: P-256");
    }

    let server_url = args.server_url.as_deref().unwrap_or(RKP_SERVER_URL);
    let client = build_client()?;

    println!("\n[2] Fetching EEK from RKP server...");
    let challenge = match fetch_eek(&client, &fingerprint, server_url) {
        Ok((challenge, _eek_pub, _eek_curve, _eek_chains)) => challenge,
        Err(e) => {
            println!("  Failed: {e}");
            println!("  Falling back to local test mode...");
            let mut challenge = [0u8; 32];
            OsRng.fill_bytes(&mut challenge);
            challenge.to_vec()
        }
    };

    println!("\n[3] Building CSR...");
    let csr_bytes = build_csr(&keys, &challenge, &cose_pubs, &device_info)?;
    println!("  CSR: {} bytes", csr_bytes.len());

    let csr = cbor_load(&csr_bytes)?;
    let csr_arr = value_as_array(&csr).ok_or_else(|| anyhow!("invalid CSR"))?;
    if csr_arr.len() < 4 {
        bail!("invalid CSR shape");
    }

    let sd = value_as_array(&csr_arr[3]).ok_or_else(|| anyhow!("invalid SignedData"))?;
    if sd.len() < 4 {
        bail!("invalid SignedData shape");
    }

    let sig_struct = cbor_dump(&Value::Array(vec![
        Value::Text("Signature1".into()),
        sd[0].clone(),
        Value::Bytes(vec![]),
        sd[2].clone(),
    ]))?;

    let sig_bytes = value_as_bytes(&sd[3]).ok_or_else(|| anyhow!("missing signature"))?;
    let sig = Ed25519Signature::try_from(sig_bytes)
        .map_err(|e| anyhow!("invalid Ed25519 signature: {e}"))?;
    let vk = VerifyingKey::from_bytes(&keys.pub_raw)
        .map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))?;
    vk.verify(&sig_struct, &sig)
        .map_err(|e| anyhow!("signature verify failed: {e}"))?;
    println!("  Signature verification: OK");

    println!("\n[4] Submitting CSR...");
    match submit_csr(&client, &csr_bytes, &challenge, server_url) {
        Ok(chains) => {
            for (i, chain_der) in chains.iter().enumerate() {
                let fname = format!("cert_chain_{i}.der");
                fs::write(&fname, chain_der).with_context(|| format!("failed to write {fname}"))?;

                let certs = parse_der_cert_chain(chain_der);
                println!("  Chain {i}: {} certs, saved to {fname}", certs.len());
                for (j, cert_der) in certs.iter().enumerate() {
                    if let Some((subject, _issuer)) = cert_subject_issuer(cert_der) {
                        println!("    [{j}] {subject}");
                    } else {
                        println!("    [{j}] <unparsed>");
                    }
                }
            }
        }
        Err(RkpError::DeviceNotRegistered(msg)) => {
            println!("  Device not registered: {msg}");
            fs::write("csr_output.cbor", &csr_bytes)?;
            println!("  CSR saved to csr_output.cbor");
        }
        Err(RkpError::Client(msg)) => {
            println!("  Client error: {msg}");
            fs::write("csr_output.cbor", &csr_bytes)?;
            println!("  CSR saved to csr_output.cbor");
        }
        Err(RkpError::Server(msg)) => {
            println!("  Server error: {msg}");
            fs::write("csr_output.cbor", &csr_bytes)?;
            println!("  CSR saved to csr_output.cbor");
        }
        Err(e) => {
            println!("  Transport/protocol error: {e}");
            fs::write("csr_output.cbor", &csr_bytes)?;
            println!("  CSR saved to csr_output.cbor");
        }
    }

    Ok(())
}

fn cmd_keybox(args: KeyboxArgs) -> Result<()> {
    let seed = resolve_seed(&args.key)?;
    let keys = DeviceKeys::new(seed);
    let device_info = load_device_config(args.key.config.as_deref())?;
    let fingerprint = get_fingerprint(args.key.config.as_deref())?;

    println!("CDI_Leaf pubkey: {}", hex::encode(keys.pub_raw));

    let server_url = args.server_url.as_deref().unwrap_or(RKP_SERVER_URL);
    let client = build_client()?;

    let (ec_priv, ec_cose_pub) = generate_ec_keypair()?;

    println!("Fetching EEK...");
    let (challenge, _eek_pub, _curve, _chains) = fetch_eek(&client, &fingerprint, server_url)?;

    println!("Building and submitting EC CSR...");
    let csr_bytes = build_csr(&keys, &challenge, &[ec_cose_pub], &device_info)?;

    let ec_chains = submit_csr(&client, &csr_bytes, &challenge, server_url)
        .map_err(|e| anyhow!("provisioning failed: {e}"))?;

    if ec_chains.is_empty() {
        bail!("no certificate chains received");
    }

    let ec_certs = parse_der_cert_chain(&ec_chains[0]);
    println!("EC chain: {} certificates", ec_certs.len());

    let manufacturer =
        text_from_map(&device_info, "manufacturer").unwrap_or_else(|| "generic".into());
    let mut random_bytes = [0u8; 6];
    OsRng.fill_bytes(&mut random_bytes);
    let device_id = format!("{manufacturer}-{}", hex::encode(random_bytes));

    let ec_priv_pem = ec_priv
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode private key PEM: {e}"))?
        .to_string();

    let xml = build_keybox_xml(&ec_priv_pem, &ec_certs, &device_id);
    fs::write(&args.output, xml).with_context(|| format!("failed to write {}", args.output))?;
    println!("Keybox written to {}", args.output);

    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<()> {
    let path = Path::new(&args.csr_file);
    let csr_bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    let csr = cbor_load(&csr_bytes)?;
    let csr_arr = value_as_array(&csr).ok_or_else(|| anyhow!("invalid CSR"))?;
    if csr_arr.len() != 4 {
        bail!("AuthenticatedRequest must be array(4)");
    }

    println!(
        "Version:        {}",
        value_as_i64(&csr_arr[0]).unwrap_or_default()
    );

    let uds_certs = value_as_map(&csr_arr[1]).ok_or_else(|| anyhow!("invalid UdsCerts map"))?;
    println!("UdsCerts:       {} entries", uds_certs.len());

    let dice = value_as_array(&csr_arr[2]).ok_or_else(|| anyhow!("invalid DiceCertChain"))?;
    println!("DiceCertChain:  {} entries", dice.len());

    let uds_pub = {
        let first = dice
            .first()
            .and_then(value_as_map)
            .ok_or_else(|| anyhow!("missing UDS COSE key"))?;
        map_get_i(first, -2)
            .and_then(value_as_bytes)
            .ok_or_else(|| anyhow!("missing UDS public key bytes"))?
            .to_vec()
    };

    println!("UDS_Pub:        {}", hex::encode(&uds_pub));

    let sd = value_as_array(&csr_arr[3]).ok_or_else(|| anyhow!("invalid SignedData"))?;
    if sd.len() != 4 {
        bail!("SignedData must be COSE_Sign1 array(4)");
    }

    let sig_struct = cbor_dump(&Value::Array(vec![
        Value::Text("Signature1".into()),
        sd[0].clone(),
        Value::Bytes(vec![]),
        sd[2].clone(),
    ]))?;

    let signature_ok = {
        let vk_bytes: [u8; 32] = uds_pub
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("UDS public key must be 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| anyhow!("invalid UDS public key: {e}"))?;
        let sig = Ed25519Signature::try_from(
            value_as_bytes(&sd[3]).ok_or_else(|| anyhow!("missing signature bytes"))?,
        )
        .map_err(|e| anyhow!("invalid signature bytes: {e}"))?;
        vk.verify(&sig_struct, &sig).is_ok()
    };

    if signature_ok {
        println!("Signature:      VALID");
    } else {
        println!("Signature:      INVALID");
    }

    let payload =
        cbor_load(value_as_bytes(&sd[2]).ok_or_else(|| anyhow!("missing SignedData payload"))?)?;
    let payload_arr =
        value_as_array(&payload).ok_or_else(|| anyhow!("invalid SignedData payload"))?;
    if payload_arr.len() != 2 {
        bail!("SignedDataPayload must be array(2)");
    }

    let challenge =
        value_as_bytes(&payload_arr[0]).ok_or_else(|| anyhow!("challenge must be bstr"))?;
    if challenge.len() > 64 {
        bail!("challenge length exceeds 64 bytes");
    }

    let csr_payload = cbor_load(
        value_as_bytes(&payload_arr[1]).ok_or_else(|| anyhow!("missing csr_payload bytes"))?,
    )?;
    let csr_payload_arr =
        value_as_array(&csr_payload).ok_or_else(|| anyhow!("invalid csr_payload"))?;
    if csr_payload_arr.len() != 4 {
        bail!("CsrPayload must be array(4)");
    }

    let csr_version = csr_payload_arr
        .first()
        .and_then(value_as_i64)
        .ok_or_else(|| anyhow!("CsrPayload version must be integer"))?;
    println!("CSR version:    {csr_version}");
    if csr_version != 3 {
        bail!("CsrPayload version must be 3");
    }

    let cert_type = csr_payload_arr
        .get(1)
        .and_then(|v| match v {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("CsrPayload cert type must be text"))?;
    println!("CertType:       {cert_type}");
    if cert_type != "keymint" {
        bail!("CsrPayload cert type must be \"keymint\"");
    }

    let brand = csr_payload_arr
        .get(2)
        .and_then(value_as_map)
        .and_then(|m| map_get_s(m, "brand"))
        .and_then(|v| match v {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "<unknown>".into());
    println!("Brand:          {brand}");

    let raw_device_map = csr_payload_arr
        .get(2)
        .and_then(value_as_map)
        .ok_or_else(|| anyhow!("DeviceInfo must be a map"))?;
    let mut device_info = HashMap::new();
    for (k, v) in raw_device_map {
        let Value::Text(name) = k else {
            bail!("DeviceInfo key must be text");
        };
        device_info.insert(name.clone(), v.clone());
    }
    build_device_info_v3_map(&device_info)?;

    let keys_to_sign_len = csr_payload_arr
        .get(3)
        .and_then(value_as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    println!("KeysToSign:     {keys_to_sign_len} keys");

    Ok(())
}

fn value_as_map(v: &Value) -> Option<&[(Value, Value)]> {
    let Value::Map(entries) = v else {
        return None;
    };
    Some(entries)
}

fn map_get_s<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info(args) => cmd_info(args)?,
        Commands::Provision(args) => cmd_provision(args)?,
        Commands::Keybox(args) => cmd_keybox(args)?,
        Commands::Verify(args) => cmd_verify(args)?,
    }

    Ok(())
}
