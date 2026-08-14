# a_srs

将远程 `version: 4` JSON 规则集合并、统一去重并编译为 sing-box SRS。

## 核心顺序

**所有远程 JSON 全部拉取并合并完成后，才开始去重。**

```text
远程 JSON 1 ─┐
远程 JSON 2 ─┤
远程 JSON 3 ─┤
远程 JSON N ─┘
       ↓
标准 version: 4 JSON
       ↓
同字段完全/包含去重
       ↓
1→2 / 1→3 / 1→4
2→3 / 2→4
3→4
       ↓
删除空 []
       ↓
删除空 {}
       ↓
JSON → SRS
```

### 标准合并结构

```json
{
  "version": 4,
  "rules": [
    {
      "domain": [],
      "domain_suffix": [],
      "domain_keyword": [],
      "domain_regex": [],
      "ip_cidr": []
    }
  ]
}
```

每个远程 JSON 的五类字段直接追加到同名数组。**合并阶段不去重。**

### 统一去重

字段层级：

```text
1 = domain_regex
2 = domain_keyword
3 = domain_suffix
4 = domain
```

跨字段严格按：

```text
1 → 2
1 → 3
1 → 4

2 → 3
2 → 4

3 → 4
```

父或子数组为空时只跳过当前比较，不影响后续比较。

- `domain`：完全匹配去重
- `domain_keyword`：完全匹配 + 包含匹配
- `domain_suffix`：完全匹配 + DNS 后缀包含
- `domain_regex`：完全匹配 + 规则字符串包含；跨字段时对候选值执行正则匹配
- `ip_cidr`：完全匹配 + CIDR 包含

所有去重完成后才删除空 `[]`；如果最小 `{}` 为空，也删除。

## 远程 URL 文件

仓库中无后缀、且每个非空行都是 `http://` 或 `https://` 的文件，会被当作远程规则文件。

单 URL 或多 URL 都是：

```text
全部拉取
↓
全部合并
↓
统一去重
↓
生成同名 .json
```

单个 URL 失败不会阻止其它 URL；全部失败则跳过该文件。

## SRS

所有 `.json` 最后统一使用：

```text
sing-box rule-set compile
```

单个 JSON 编译失败不会阻止其它文件。

## README 错误状态

工作流每次覆盖 README 中：

```text
<!-- SRS-BUILD-STATUS:START -->

## SRS 构建状态

### ⚠️ 本次工作流存在失败

单个 URL、JSON 或 SRS 失败不会阻止其它文件继续处理。

| 文件 | 阶段 | 详细错误 |
|---|---|---|
| `google` | 远程 JSON 合并/去重/生成 | https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google-play.json: rules[0].domain 必须是数组 |
| `netflix` | 远程 JSON 合并/去重/生成 | https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.json: rules[0].domain 必须是数组 |
| `x_facebook` | 远程 JSON 合并/去重/生成 | https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/facebook.json: rules[0].domain 必须是数组 |

<!-- SRS-BUILD-STATUS:END -->
```

因此 README 始终显示最近一次工作流的处理结果。

## 测试

正式构建前运行：

```text
python3 tests/test_build_srs.py
```

测试通过后才执行 SRS 构建。

## 去重算法优化说明

本项目的去重不再对全部规则进行两两穷举比较，而是采用与成熟广告规则项目相近的“集合索引 + 父域剪枝”思路。参考了 REIJI007/AdBlock_Rule_For_Sing-box 的 HashSet、父域遍历、父域剪枝思路，以及 privacy-protection-tools/anti-AD 的“合并去重后再抽象化/优化”思路。

- `domain`：HashSet 完全匹配去重。
- `domain_suffix`：先完全去重，再按 DNS 标签从右向左检查父后缀；不使用普通字符串 `in`，避免 `ample.com` 之类错误包含。
- `domain_keyword`：使用 Aho-Corasick 自动机处理关键字之间以及关键字对下级字段的包含关系，避免大规模 O(n²) 穷举。
- `domain_regex`：先完全匹配去重；对下级字段执行真实正则匹配。对于包含明确字面量的正则，先使用 n-gram 倒排索引筛掉不可能匹配的候选，再执行正则，从而减少大量无效 `regex × domain` 比较；无法安全提取字面量时不做预筛选，以保持匹配语义。
- `ip_cidr`：使用前缀祖先索引检查包含关系，不再让所有 CIDR 两两比较。

### 父系关系

仍严格保持项目约定：

```text
1 domain_regex
  ├─→ 2 domain_keyword
  ├─→ 3 domain_suffix
  └─→ 4 domain

2 domain_keyword
  ├─→ 3 domain_suffix
  └─→ 4 domain

3 domain_suffix
  └─→ 4 domain
```

父数组为空时只跳过当前比较，不影响后续父系；所有远程 JSON 必须先完整合并，之后才统一执行这些优化算法。
