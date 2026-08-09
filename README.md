# a_srs

用于将远程 `version: 4` JSON 规则集合并、去重并编译为 sing-box SRS。

## 远程规则

无后缀文件每行一个 URL，例如：

```text
apple
cn
```

文件内容：

```text
https://example.com/a.json
https://example.com/b.json
```

工作流会先拉取所有远程 JSON，合并为同名 `.json`，然后统一编译为同名 `.srs`。

## 去重规则

同一个最小 `[]` 内：

- `domain`：完全匹配去重
- `domain_keyword`：完全匹配 + 包含匹配
- `domain_suffix`：完全匹配 + DNS 后缀包含匹配
- `domain_regex`：完全匹配 + 规则文本包含匹配
- `ip_cidr`：完全匹配 + CIDR 网络包含匹配

跨字段层级：

```text
domain_regex
    ↓
domain_keyword
    ↓
domain_suffix
    ↓
domain
```

其中：

- `domain_regex` 对 `domain_keyword`、`domain_suffix`、`domain` 做实际正则匹配
- `domain_keyword` 对 `domain_suffix`、`domain` 做字符串包含匹配
- `domain_suffix` 对 `domain` 做 DNS 后缀包含匹配

空 `[]` 自动删除，空 `{}` 自动删除，并由 JSON 序列化器重新处理逗号。

## 构建状态

<!-- SRS-BUILD-STATUS:START -->

## SRS 构建状态

首次运行工作流后会在这里显示最近一次构建结果。

<!-- SRS-BUILD-STATUS:END -->
