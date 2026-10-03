# ACPs v2.2.0 AAC 切片（gateway-core）

本目录记录 gateway-core 对 **国标 GB/Z 185《人工智能 智能体互联》** 配套规范族
（ACPs-community v2.2.0）中 **AAC（智能体访问控制）** 的 **v0 实验切片**实现，
并给出与规范条款的逐条对照。

- 规范与参考实现仓库：https://github.com/AIP-PUB/ACPs-community
- 规范基线：tag `v2.2.0`，commit `3985c1330209f075c124669cc9d31f0e75448140`
- 本切片状态：**实验（Preview）**——不用于生产；不改动默认管线（可选信封，禁用时字节级透传）

## 文档索引

| 文档 | 内容 |
| --- | --- |
| [`ACPs-v02.2-requirements.md`](ACPs-v02.2-requirements.md) | 规范要求项提取：每条给出规范定位（manifest + 章节/行号）与本实现的处理方式 |
| [`aac-to-gateway-core-mapping.md`](aac-to-gateway-core-mapping.md) | ACPs 概念 → gateway-core 机制的映射 |
| [`conformance-matrix.md`](conformance-matrix.md) | **一致性矩阵**：✅ 已实现并测试 / 🟡 部分实现 / ⛔ 不在 v0（**语义为库级**） |
| [`wiring-matrix.md`](wiring-matrix.md) | **接线矩阵**：每项能力在**非测试代码**里的实际消费点（含集成契约与责任边界） |

> `conformance-matrix` 与 `wiring-matrix` 语义不同，勿混读：前者回答"实现了吗"，后者回答"接进运行路径了吗"。

## 快速验证（两条命令）

```bash
# 1. 包测试（AIC 解析/CRC、上下文构建、PDP、委托与边界、重放、模糊测试）
go test ./acps/
#   → ok  github.com/varwof/gateway-core/acps

# 2. 端到端冒烟：自带证书生成（mTLS 对端证书）→ RunAccessPipelineAAC 全流程
go run ./cmd/acps-smoke
#   → 11 项断言逐条 [PASS]，末行：冒烟结果: 全部通过
```

冒烟覆盖：AIC 结构 + CRC 校验、篡改校验码被拒、对端身份提取（CN + SAN `acps://`）、
senderId 一致性、可信上下文构建、fail-closed PDP、audience/链深/一次性 jti 防重放、
审计与对外公开文案。零外部依赖（仅 Go 标准库 + 本仓库 gw 包），无需任何服务或配置。

## 代码位置

| 位置 | 内容 |
| --- | --- |
| `acps/` | AAC 切片实现（**不 import gateway-core 根包**，可独立编译与测试） |
| `pipeline_aac.go`（gw 包） | 唯一正式接线点：`RunAccessPipelineAAC`（可选信封） |
| `cmd/acps-smoke/` | 端到端冒烟 CLI（演示与自检） |

## 边界声明

- **实验切片**：v0 覆盖 AAC 核心闭环 + AIC/AIA/AIP 中与 AAC 直接相关的子集；未覆盖项一律 fail closed
- **不是可部署服务**：当前为库实现 + 冒烟演示，无生产运行；网关侧接线（信封）为一个可选入口示例
- **验签责任边界**：委托 token 假定已由网关既有 JWT 验证器完成验签与 presenter（cnf）绑定，
  信封内不重复验签；详见 `wiring-matrix.md` 的「集成契约」一节
- 本轮**暂不合并主干**（分支 `feat/acps-aac`），保持可对照的稳定快照

## 许可

Apache-2.0（SPDX：`Apache-2.0`，版权行见各文件头）。贡献至 ACPs-community（木兰宽松许可证
第 2 版，Mulan PSL v2）时按该仓库许可分发。
