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
