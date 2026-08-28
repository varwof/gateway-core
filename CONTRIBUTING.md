# 贡献指南

## 前提
- Go 1.26+
- `go vet ./...` 零警告
- 所有测试通过

## 开发流程

```bash
# 克隆
git clone https://github.com/varwof/gateway-core

# 构建
go build ./...

# 测试
go test -count=1 -race ./...

# 代码检查
go vet ./...
gofmt -s -l .
```

## 提交信息格式

```
<type>: <简短描述>

类型: feat / fix / docs / test / refactor / chore
```

## PR 要求
1. 新增功能需包含测试
2. 配置变更需同步更新 docs/
3. OpenAPI 变更需同步更新 openapi.yaml


## 贡献者许可协议（CLA）

提交 Pull Request 即表示您同意签署
[个人 CLA](https://github.com/varwof/.github/blob/main/CLA-INDIVIDUAL.md)
（企业赞助贡献请签[企业 CLA](https://github.com/varwof/.github/blob/main/CLA-CORPORATE.md)）。
CLA Assistant 机器人会在您打开第一个 Pull Request 时提示签署；签署一次覆盖所有 Varwof 仓库。

您的贡献将按 Apache-2.0 许可证授权，详见 [LICENSE](LICENSE)。
