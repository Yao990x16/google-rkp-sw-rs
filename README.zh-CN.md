# Android 远程密钥配置（Rust 版）

本项目是 Android Remote Key Provisioning (RKP) 的 Rust 实现。

它可以生成 `AuthenticatedRequest` CSR，请求 Google 生产 RKP 服务
（`fetchEekChain` / `signCertificates`），并导出 `keybox.xml`。

## 源仓库说明

- 本仓库为 Rust 重写/分叉版本。
- 上游原始 Python 项目：<https://github.com/MhmRdd/google-rkp-sw>

## 与 Python 版的差异

1. 语言与运行方式
- 从 Python 重写为 Rust，使用编译后的二进制运行。

2. CSR 结构更严格
- 按 `generateCertificateRequestV2` 做结构约束：
  - `AuthenticatedRequest = [1, UdsCerts, DiceCertChain, SignedData]`
  - `CsrPayload = [3, "keymint", DeviceInfoV3, KeysToSign]`
  - `challenge <= 64 bytes`
  - `DeviceInfoV3` 字段/类型/取值严格校验

3. 功能范围
- CLI 功能与 Python 版对齐：`info`、`provision`、`keybox`、`verify`。

4. 性能说明
- 本地 CBOR/加解密/签名处理通常比 Python 开销更低。
- 端到端耗时仍主要受网络请求影响（RKP API），实际体感提升需结合场景评估。

## 环境要求

- Rust 工具链（Cargo）

Rust 安装：<https://www.rust-lang.org/tools/install>

## 编译

```bash
cargo build --release
```

二进制路径：

```bash
./target/release/google-rkp-sw
```

## 配置

复制 `template.conf` 为私有配置：

```bash
cp template.conf device_prop.conf
```

按设备实际信息填写 `[device]` 与 `[fingerprint]`。

## 使用方式

### 查看设备与密钥信息

```bash
./target/release/google-rkp-sw info --seed <64-hex> --config device_prop.conf
./target/release/google-rkp-sw info --hw-key <32-hex> --kdf-label rkp_bcc_km --config device_prop.conf
```

### 申请证明证书

```bash
./target/release/google-rkp-sw provision --seed <64-hex> --config device_prop.conf
./target/release/google-rkp-sw provision --hw-key <32-hex> --kdf-label rkp_bcc_km --config device_prop.conf -n 2
```

### 导出 keybox.xml

```bash
./target/release/google-rkp-sw keybox --seed <64-hex> --config device_prop.conf -o keybox.xml
```

### 校验 CSR

```bash
./target/release/google-rkp-sw verify csr_output.cbor
```

### 开发模式（不构建 release）

```bash
cargo run -- info --seed <64-hex> --config device_prop.conf
cargo run -- provision --seed <64-hex> --config device_prop.conf
cargo run -- keybox --seed <64-hex> --config device_prop.conf -o keybox.xml
cargo run -- verify csr_output.cbor
```

## 协议参考

- Android RKP 概览：<https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning>
- Android RKP AIDL/CDDL：<https://cs.android.com/android/platform/superproject/+/main:hardware/interfaces/security/rkp/aidl/>
- RFC 9052（COSE）：<https://datatracker.ietf.org/doc/html/rfc9052>
- RFC 9053（COSE Algorithms）：<https://datatracker.ietf.org/doc/html/rfc9053>
- RFC 8392（CWT）：<https://datatracker.ietf.org/doc/html/rfc8392>
- Open DICE：<https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md>
- NIST SP 800-108r1：<https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final>

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
