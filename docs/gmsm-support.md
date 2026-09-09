# 国密（SM2/SM3）验证支持

> 验证侧 | 不涉及 TLS 握手路径 | 默认构建零行为变化 | 模块：`github.com/varwof/gateway-core`，包别名 `gw`

## 1. 能力范围

本模块向网关提供 **验证侧** 的国密（SM2/SM3）能力：在 CNC 密码（商密）合规要求下，
接收由已备案 CA / 网关自建 CA 签发的 SM2 证书链与 SM2 数据签名，并完成验证：

- SM2 证书链验证（SM2-with-SM3，OID `1.2.156.10197.1.501`），支持 根CA→叶子 与
  根CA→中间CA→叶子 两级形态；
- 单一数据签名验证（消息确认为 SM3(ZA‖msg)，与 tjfoc 签名方向同构）；
- SM2 证书解析（经 tjfoc/gmsm）并对叶子复用既有 AIC 提取（`ParseAIC`）；
- 最小公共验证入口 `VerifySM2Bundle`，与 TLS 握手/证书校验配置完全解耦。

不修改 TLS 握手路径、不改变默认构建（无 `-tags gmsm`）的任何行为。

## 2. 构建模式：gmsm build tag 配对

| 文件 | build tag | 行为 |
| --- | --- | --- |
| `gmsm.go` | `//go:build gmsm` | 真实实现，import `github.com/tjfoc/gmsm` |
| `gmsm_stub.go` | `//go:build !gmsm` | 全部入口 fail-closed 返回 `ErrSM2NotSupported` |
| `gmsm_shared.go` | 无 tag | 公共类型/OID/稳定原因码，不 import tjfoc（默认构建可编译） |

测试对等配对：`gmsm_test.go`（`gmsm`）+ `gmsm_stub_test.go`（`!gmsm`）。

```bash
# 默认（无国密）——出厂行为不变
go build ./... && go test ./...

# 启用国密验证
go build -tags gmsm ./... && go test -tags gmsm ./...
```

依赖说明：`go.mod` 中固定 `github.com/tjfoc/gmsm v1.4.1`（与 core 同库同版本）。
默认构建只编译 `gmsm_shared.go` + `gmsm_stub.go`，不 import gmsm 库。

## 3. 公共 API

```go
// 解析 SM2 证书为 *x509.Certificate（内部走 gmsm；标准库无法解析 SM2 SPKI）。
func ParseSM2Certificate(der []byte) (*x509.Certificate, error)

// 是否为 SM2 证书（仅判 signatureAlgorithm OID 501；解析失败视为非 SM2，fail-closed）。
func IsSM2Certificate(der []byte) bool

// 单签名验证：pub 为 PKIX SPKI（即证书 RawSubjectPublicKeyInfo 形态）或 gmsm 原生
// oidSM2 SPKI；digest 为签名方实际签名的消息字节（标志的 ZA‖digest 内部处理）。
func VerifySM2Signature(pub, digest, sig []byte) error

// SM2 证书链验证：roots 中命中叶子 issuer，链上每级 SM2-with-SM3 验签成功。
// 返回叶子（*x509.Certificate）。
func VerifySM2CertificateChain(leafDER []byte, intermediates, roots [][]byte) (*x509.Certificate, error)

// 最小公共验证入口：链验证 → （RequireAIC 时）AIC 提取 → （Signature 非空时）
// 叶子公钥验 Data 签名。失败通过 AuditLogger 以 deny_reason=sm2_verify_* 落审计。
func VerifySM2Bundle(in SM2BundleInput) (*SM2BundleResult, error)
```

`SM2BundleInput`：`LeafDER`、`Intermediates`、`Roots`、`Data`、`Signature`、
`RequireAIC`、`AuditLogger`、`SrcIP`、`MappingName`、`Target`。

`SM2BundleResult`：`Cert *x509.Certificate`、`AIC *AIC`。

## 4. OID

| 用途 | OID |
| --- | --- |
| SM2-with-SM3 签名算法 | `1.2.156.10197.1.501` |
| SM3 摘要算法 | `1.2.156.10197.1.401` |
| SM2 曲线 | `1.2.156.10197.1.301` |
| AIC 扩展 | `1.3.6.1.4.1.66257.1.1`（复用 `ParseAIC`） |

## 5. 稳定原因码（审计 deny_reason）

`SM2VerifyError{Code, Detail}`，`Error()` 输出 `"code: detail"`：

| code | 触发 |
| --- | --- |
| `sm2_verify_parse_certificate` | 叶子/链上证书 DER 解析失败（含截断） |
| `sm2_verify_not_sm2_certificate` | 叶子签名算法非 OID 501（如 ECDSA/RSA 链） |
| `sm2_verify_parse_public_key` | 公钥 SPKI 解析失败 |
| `sm2_verify_unsupported_public_key` | 公钥非 SM2 曲线/类型 |
| `sm2_verify_signature` | 数据签名验证失败 |
| `sm2_verify_chain_not_built` | 未能构造到任意 root 的链 |
| `sm2_verify_chain_signature` | 某级 ASN.1 验签失败（含篡改） |
| `sm2_verify_chain_untrusted` | 叶子不匹配任何受信 root（无相同 Subject 的根） |
| `sm2_verify_mixed_chain` | 链中出现非 SM2 证书 |
| `sm2_verify_chain_validity` | 叶子/中间件有效期失效（roots 豁免） |
| `sm2_verify_missing_aic` | `RequireAIC` 但叶子无 AIC 扩展 |
| `sm2_verify_not_supported` | 默认构建（无 gmsm tag）调用任何国密入口 |

## 6. 验证语义

- **链验证**：从叶子起按 `RawIssuer==RawSubject` 匹配（中间件优先），逐级以签发者公钥
  `CheckSignatureFrom` 验签；全部链成员（根除外）须为 SM2-with-SM3；环/深度保护
  （anti-cert-bomb），深度上限 = `len(intermediates)+1`。
- **验签数学**：SM2-with-SM3 证书签名的 e = SM3(ZA‖RawTBSCertificate)；单签名验证的
  消息即签名方的 digest（ZA‖msg 由内部计算），调用方不要再套一层哈希。
- **密钥判定**：标准 PKIX SPKI（`id-ecPublicKey` + SM2 曲线 OID）与 gmsm 原生
  `oidSM2` SPKI 均接受；曲线必须为 `sm2.P256Sm2()`。
- **AIC**：`ParseSM2Certificate` 产出 stdlib 证书后直接复用 `ParseAIC`，SM2 与标准
  ECDSA 证书路径提取结果一致（奇偶校验测试保证）。

## 7. 测试

fixture 在测试内实时生成（tjfoc/gmsm）：根自签 → 中间CA → 叶子（含 AIC 扩展，
DA 由主体 SM2 密钥签名、算法标注 SM2-with-SM3）。手工复现步骤：

1. `sm2.GenerateKey(rand.Reader)` 生成根/中间/叶子与主体密钥；
2. 模板构造 AIC 扩展 `asn1.Marshal(*aic)` 放入模板 `ExtraExtensions`；
3. `gmx509.Certificate{}.FromX509Certificate(tmpl)` 后 `gmx509.CreateCertificate`
   逐级签发（父证书用已解析的根/中间件）；
4. AIC 的 DelegationAuthTBS DER 以 `userPriv.Sign(rand, sha256(tbs), nil)` 签名。

覆盖：正向链（两级/单级）、错 CA、同名异钥根、非 SM2 链、截断 DER、空输入、
RequireAIC 缺失/满足、篡改链签名、篡改数据签名、单签名一字节篡改、AIC 奇偶一致性、
原因码格式与 `ErrSM2NotSupported` 文案。

```bash
go test -tags gmsm -run SM2 -v ./            # 国密用例
go test -tags gmsm -race -count=1 ./         # 国密模式全量 + 竞态
go test -count=1 ./                          # 默认模式全量（基线不变）
```

## 8. 金标向量（core 签发 → gateway 验证 字节级闭环）

`testdata/gmsm/` 内一组**固定 DER** 由 core 仓库生产签发路径签出（`-tags gmsm`），
证明跨仓库互操作不依赖"生成逻辑同构"：

| 文件 | 内容 |
| --- | --- |
| `root.der` | SM2 根 CA（纯 SM2-with-SM3 OID 1.2.156.10197.1.501，自签） |
| `intermediate.der` | SM2 中间 CA（root 签发，IsCA、pathlen=0） |
| `leaf.der` | SM2 叶子（含 AIC 扩展，**由 `ca.Sign`（ProfileAgentProxy+BuildAIC）签发**） |
| `leaf.spki.der` | 叶子公钥 PKIX SPKI |
| `leaf.data.bin` / `leaf.sig.bin` | 叶子密钥对固定数据的 SM2 签名 |
| `expected.json` | 期望值清单（CN/序列号/AIC 字段/签名算法 OID） |

同一组字节同时存在于 `core/internal/ca/testdata/gmsm/`；core 侧
`TestSM2GoldenVectorRoundTrip`（`-tags gmsm`）与 gateway 侧 `TestSM2GoldenFromCore_*`
对完全相同字节各自验证：全链纯 SM2-with-SM3、链级验签通过、AIC 还原字段一致、
demo 签名（含一字节篡改拒绝）。两侧结论一致 = 字节级闭环。

再生成步骤（工具不入库，签出后即删除；再生成会得到新的随机序列号，测试断言不依赖
固定序列号值，仅校验其存在）：

```bash
cd /home/varwof/src/github.com/core
# 临时工具 cmd/sm2golden/main.go（//go:build gmsm）：GenerateSubCAKey("sm2") 生成
# 四把 SM2 密钥 → gmx509 自签 root、root 签 intermediate → 汇成 DelegationAuthTBS
# （sha256digest，主体 SM2 密钥签名）→ ca.Sign(*SignConfig{AIC: &AICConfig{...},
# Profile: ca.ProfileAgentProxy, SkipDB: true, MaxAgentProxyValidity: 24h, …}) 签发
# 叶子（经 BuildAIC 内嵌 AIC 扩展）→ 叶子密钥签名固定数据 → 写盘 7 个文件。
go run -tags gmsm ./cmd/sm2golden -out /tmp/gmsm_golden
# 把 *.der *.bin expected.json 复制到两仓库 testdata/gmsm/：
cp /tmp/gmsm_golden/* /home/varwof/src/github.com/gateway-core/testdata/gmsm/
cp /tmp/gmsm_golden/* /home/varwof/src/github.com/core/internal/ca/testdata/gmsm/
```

两侧验证命令：

```bash
go test -tags gmsm -run Golden -v ./                     # gateway
go test -tags gmsm -run Golden -v ./internal/ca/         # core
```

## 9. 不变量（回归防护）

- 默认构建不 import tjfoc/gmsm（`go list -f '{{.GoFiles}}' .` 仅含
  `gmsm_shared.go`/`gmsm_stub.go`）；
- 默认构建调用任何国密入口返回 `ErrSM2NotSupported`（fail-closed），与基线行为一致；
- 链必须整体为 SM2；根密钥必须 SM2；拒绝混合链。