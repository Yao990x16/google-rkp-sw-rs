# Android Remote Key Provisioning (Rust)

中文文档：[`README.zh-CN.md`](README.zh-CN.md)

Rust implementation of Android Remote Key Provisioning (RKP).

This tool builds `AuthenticatedRequest` CSRs, talks to Google's production RKP
server (`fetchEekChain` / `signCertificates`), and exports `keybox.xml`.

## Source Repository

- This repository is a Rust rewrite/fork.
- Upstream (original Python implementation): https://github.com/MhmRdd/google-rkp-sw

## What Changed vs Python Version

1. Language/runtime
- Rewritten from Python to Rust; distributed as a compiled binary.

2. CSR strictness
- Rust version now enforces `generateCertificateRequestV2` structure checks:
  - `AuthenticatedRequest = [1, UdsCerts, DiceCertChain, SignedData]`
  - `CsrPayload = [3, "keymint", DeviceInfoV3, KeysToSign]`
  - `challenge <= 64 bytes`
  - strict `DeviceInfoV3` field/type/value validation

3. Behavior compatibility
- CLI functionality is kept equivalent: `info`, `provision`, `keybox`, `verify`.

4. Performance notes
- Rust binary typically has lower runtime overhead than Python for local CBOR/
  crypto processing.
- End-to-end provisioning is still mostly network-bound (RKP API calls), so
  overall wall-clock improvement may be limited without benchmarking.

## Requirements

- Rust toolchain (Cargo)
- OpenSSL-compatible environment for TLS (handled via `reqwest` + rustls in this project)

Install Rust: https://www.rust-lang.org/tools/install

## Build

```bash
cargo build --release
```

Binary path:

```bash
./target/release/google-rkp-sw
```

## Configuration

Copy `template.conf` to your private device config:

```bash
cp template.conf device_prop.conf
```

Fill `[device]` and `[fingerprint]` with device-specific values.

## Usage

### Show device and key info

```bash
./target/release/google-rkp-sw info --seed <64-hex> --config device_prop.conf
./target/release/google-rkp-sw info --hw-key <32-hex> --kdf-label rkp_bcc_km --config device_prop.conf
```

### Provision attestation keys

```bash
./target/release/google-rkp-sw provision --seed <64-hex> --config device_prop.conf
./target/release/google-rkp-sw provision --hw-key <32-hex> --kdf-label rkp_bcc_km --config device_prop.conf -n 2
```

### Export keybox.xml

```bash
./target/release/google-rkp-sw keybox --seed <64-hex> --config device_prop.conf -o keybox.xml
```

### Verify CSR

```bash
./target/release/google-rkp-sw verify csr_output.cbor
```

### Development mode (without release build)

```bash
cargo run -- info --seed <64-hex> --config device_prop.conf
cargo run -- provision --seed <64-hex> --config device_prop.conf
cargo run -- keybox --seed <64-hex> --config device_prop.conf -o keybox.xml
cargo run -- verify csr_output.cbor
```

## Protocol References

- Android RKP overview: https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning
- Android RKP AIDL/CDDL: https://cs.android.com/android/platform/superproject/+/main:hardware/interfaces/security/rkp/aidl/
- RFC 9052 (COSE): https://datatracker.ietf.org/doc/html/rfc9052
- RFC 9053 (COSE Algorithms): https://datatracker.ietf.org/doc/html/rfc9053
- RFC 8392 (CWT): https://datatracker.ietf.org/doc/html/rfc8392
- Open DICE: https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md
- NIST SP 800-108r1: https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final

## License

Apache-2.0. See [LICENSE](LICENSE).
