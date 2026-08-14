#!/usr/bin/env python3
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(".").resolve()
README = ROOT / "README.md"
TARGET_VERSION = 4

RULE_FIELDS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
)

SKIP_DIRS = {".git", ".github", "tests"}
SKIP_FILES = {"README.md"}


def log(message):
    print(message, flush=True)


def rel(path):
    return str(path.relative_to(ROOT))


def is_url(value):
    return value.startswith(("http://", "https://"))


def is_url_file(path):
    if path.suffix or path.name in SKIP_FILES:
        return False
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception:
        return False
    return bool(lines) and all(is_url(line) for line in lines)


def find_url_files():
    result = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if is_url_file(path):
            result.append(path)
    return sorted(result)


def find_json_files():
    result = []
    for path in ROOT.rglob("*.json"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        result.append(path)
    return sorted(result)


def parse_json_bytes(content, source):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source}: UTF-8 解码失败: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: JSON 解析失败: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{source}: JSON 根节点必须是对象")

    version = data.get("version")
    if not isinstance(version, int):
        raise ValueError(f"{source}: version 必须是整数")
    if version > TARGET_VERSION:
        raise ValueError(
            f"{source}: version={version} 高于目标 version={TARGET_VERSION}"
        )

    rules = data.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"{source}: rules 必须是数组")

    return {"version": TARGET_VERSION, "rules": rules}


def load_local_json(path):
    return parse_json_bytes(path.read_bytes(), rel(path))


def download_json(url):
    log(f"      拉取: {url}")
    request = Request(url, headers={"User-Agent": "a_srs/2.0"})
    try:
        with urlopen(request, timeout=60) as response:
            content = response.read()
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"网络错误: {exc.reason}") from exc
    except Exception as exc:
        raise RuntimeError(f"拉取失败: {exc}") from exc
    return parse_json_bytes(content, url)


def exact_key(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def exact_dedupe(values):
    seen = set()
    result = []
    for value in values:
        key = exact_key(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def normalize_domain(value):
    if not isinstance(value, str):
        return value
    value = value.strip().lower()
    return value[:-1] if value.endswith(".") else value


def suffix_covers(parent, child):
    parent = normalize_domain(parent)
    child = normalize_domain(child)
    if not isinstance(parent, str) or not isinstance(child, str):
        return False
    return child == parent or child.endswith("." + parent)


def parse_network(value):
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def dedupe_domain(values):
    # domain 只做完全匹配去重。
    return exact_dedupe(values)


class AhoCorasick:
    """轻量级 Aho-Corasick：用于大量 domain_keyword 的包含关系判断。"""

    def __init__(self, patterns):
        self.next = [{}]
        self.fail = [0]
        self.output = [[]]
        self.patterns = list(patterns)

        for idx, pattern in enumerate(self.patterns):
            node = 0
            for ch in pattern:
                nxt = self.next[node].get(ch)
                if nxt is None:
                    nxt = len(self.next)
                    self.next[node][ch] = nxt
                    self.next.append({})
                    self.fail.append(0)
                    self.output.append([])
                node = nxt
            self.output[node].append(idx)

        from collections import deque
        q = deque()
        for child in self.next[0].values():
            q.append(child)
            self.fail[child] = 0

        while q:
            node = q.popleft()
            for ch, child in self.next[node].items():
                q.append(child)
                f = self.fail[node]
                while f and ch not in self.next[f]:
                    f = self.fail[f]
                self.fail[child] = self.next[f].get(ch, 0)
                self.output[child].extend(self.output[self.fail[child]])

    def find_other_pattern(self, text, own_index):
        node = 0
        for ch in text:
            while node and ch not in self.next[node]:
                node = self.fail[node]
            node = self.next[node].get(ch, 0)
            for idx in self.output[node]:
                if idx != own_index:
                    return True
        return False


def dedupe_keyword(values):
    """完全匹配 + 包含匹配；用 Aho-Corasick 避免 O(n²) 穷举。"""
    values = [v for v in exact_dedupe(values) if isinstance(v, str)]
    normalized = [v.strip().lower() for v in values]
    ac = AhoCorasick(normalized) if normalized else None

    result = []
    for idx, value in enumerate(values):
        # 如果当前 keyword 本身包含另一个 keyword，则当前项被父 keyword 覆盖。
        if ac and ac.find_other_pattern(normalized[idx], idx):
            continue
        result.append(value)
    return result


def dedupe_suffix(values):
    """完全匹配 + DNS 标签边界的父后缀包含；按标签树 O(n*label)。"""
    values = [v for v in exact_dedupe(values) if isinstance(v, str)]
    normalized = [normalize_domain(v) for v in values]
    suffix_set = set(normalized)

    result = []
    for value, current in zip(values, normalized):
        labels = current.split('.') if current else []
        covered = False
        # 从更短的父域开始检查，例如 a.b.example.com -> b.example.com -> example.com
        for i in range(1, len(labels)):
            parent = '.'.join(labels[i:])
            if parent in suffix_set:
                covered = True
                break
        if not covered:
            result.append(value)
    return result


def dedupe_regex(values):
    """正则字符串完全匹配去重；跨字段时再执行真实 regex 匹配。"""
    return exact_dedupe(values)


def dedupe_ip_cidr(values):
    """完全匹配 + CIDR 包含；按前缀祖先索引，避免网络之间两两比较。"""
    values = exact_dedupe(values)
    valid = []
    invalid = []

    for value in values:
        network = parse_network(value)
        if network is None:
            invalid.append(value)
        else:
            valid.append((network, value))

    # 先处理父网段，再处理子网段；这样 ancestor_set 中只需要检查已经存在的父节点。
    valid.sort(key=lambda item: (item[0].version, item[0].prefixlen, int(item[0].network_address)))
    ancestor_set = set()
    kept = []

    for network, original in valid:
        bits = 32 if network.version == 4 else 128
        address = int(network.network_address)
        covered = False

        # /0 没有更短父网段；其它前缀只需检查自己的所有祖先前缀。
        for prefixlen in range(0, network.prefixlen):
            shift = bits - prefixlen
            ancestor_key = (network.version, prefixlen, address >> shift)
            if ancestor_key in ancestor_set:
                covered = True
                break

        if covered:
            continue

        kept.append((network, original))
        ancestor_set.add((network.version, network.prefixlen, address >> (bits - network.prefixlen)))

    return [original for _, original in kept] + invalid


def build_substring_index(values, gram_size=3):
    """建立候选字符串的 n-gram 倒排索引，供 regex 跨字段匹配预筛选。"""
    from collections import defaultdict
    index = defaultdict(set)
    unique_values = list(dict.fromkeys(v for v in values if isinstance(v, str)))
    for value in unique_values:
        text = value.strip().lower()
        if len(text) < gram_size:
            continue
        grams = {text[i:i + gram_size] for i in range(len(text) - gram_size + 1)}
        for gram in grams:
            index[gram].add(value)
    return index


def extract_regex_literal(pattern):
    """提取正则中最长的连续字面量，作为安全的候选预筛选条件。

    只有明确知道某段文本必须出现在匹配字符串中时才使用它；没有可证明字面量时返回 None，
    这样不会改变 regex 的真实语义，只减少明显不可能匹配的候选。
    """
    if not isinstance(pattern, str):
        return None
    runs = []
    current = []
    escaped = False
    in_class = False

    for ch in pattern:
        if escaped:
            # \., \\, \-, 等均可安全还原为字面量；\\d / \\w 等不是固定字面量。
            if ch in r".\\-_/+:@=" and not in_class:
                current.append(ch)
            else:
                if current:
                    runs.append(''.join(current))
                    current = []
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if ch == '[':
            in_class = True
            if current:
                runs.append(''.join(current))
                current = []
            continue
        if ch == ']':
            in_class = False
            if current:
                runs.append(''.join(current))
                current = []
            continue
        if in_class or ch in '^$.*+?{}()|':
            if current:
                runs.append(''.join(current))
                current = []
            continue
        current.append(ch)

    if escaped and current:
        runs.append(''.join(current))
    elif current:
        runs.append(''.join(current))

    literals = [x.lower() for x in runs if len(x) >= 3]
    return max(literals, key=len) if literals else None


def regex_filter_candidates(pattern, values, index):
    literal = extract_regex_literal(pattern)
    if not literal or len(literal) < 3:
        return values
    gram_size = 3
    grams = {literal[i:i + gram_size] for i in range(len(literal) - gram_size + 1)}
    candidate_sets = [index.get(g) for g in grams]
    candidate_sets = [s for s in candidate_sets if s is not None]
    if not candidate_sets:
        return []
    candidate_sets.sort(key=len)
    candidates = set(candidate_sets[0])
    for candidate_set in candidate_sets[1:]:
        candidates.intersection_update(candidate_set)
        if not candidates:
            return []
    return candidates


def regex_remove_covered(patterns, values):
    """对每个 regex 只对可能命中的候选执行 re.search，避免 regex × 全量域名穷举。"""
    if not patterns or not values:
        return values

    compiled = []
    for pattern in patterns:
        try:
            compiled.append((pattern, re.compile(pattern, re.IGNORECASE)))
        except re.error:
            # 非法 regex 不应该吞掉其它有效规则；后续 sing-box compile 会报告原始语义错误。
            continue

    if not compiled:
        return values

    index = build_substring_index(values)
    remaining = list(values)
    for pattern, regex in compiled:
        if not remaining:
            break
        candidates = regex_filter_candidates(pattern, remaining, index)
        if not candidates:
            continue
        remaining = [value for value in remaining if value not in candidates or not regex.search(value)]
    return remaining

def dedupe_same_field(rule):
    if "domain" in rule:
        rule["domain"] = dedupe_domain(rule["domain"])
    if "domain_keyword" in rule:
        rule["domain_keyword"] = dedupe_keyword(rule["domain_keyword"])
    if "domain_suffix" in rule:
        rule["domain_suffix"] = dedupe_suffix(rule["domain_suffix"])
    if "domain_regex" in rule:
        rule["domain_regex"] = dedupe_regex(rule["domain_regex"])
    if "ip_cidr" in rule:
        rule["ip_cidr"] = dedupe_ip_cidr(rule["ip_cidr"])
    return rule


def regex_matches(pattern, candidate):
    if not isinstance(pattern, str) or not isinstance(candidate, str):
        return False
    try:
        return re.search(pattern, candidate, re.IGNORECASE) is not None
    except re.error:
        return False


def apply_parent_hierarchy(rule):
    """按 1→2/3/4、2→3/4、3→4 的层级做剪枝。

    每一级为空都只跳过当前比较；不会阻止后面的父系继续比较。
    domain_keyword/domain_suffix/domain 的跨字段包含判断均使用索引/标签树，
    regex 则使用字面量 n-gram 预筛选 + 真实 regex 匹配。
    """
    regex_rules = rule.get("domain_regex", [])
    keywords = rule.get("domain_keyword", [])
    suffixes = rule.get("domain_suffix", [])
    domains = rule.get("domain", [])

    # 1 → 2 / 3 / 4
    if regex_rules and keywords:
        keywords = regex_remove_covered(regex_rules, keywords)
    if regex_rules and suffixes:
        suffixes = regex_remove_covered(regex_rules, suffixes)
    if regex_rules and domains:
        domains = regex_remove_covered(regex_rules, domains)

    # 2 → 3 / 4：Aho-Corasick 一次建立 keyword 自动机。
    if keywords and suffixes:
        ac = AhoCorasick([x.strip().lower() for x in keywords if isinstance(x, str)])
        suffixes = [
            value for value in suffixes
            if not ac.find_other_pattern(value.strip().lower(), -1)
        ]
    if keywords and domains:
        ac = AhoCorasick([x.strip().lower() for x in keywords if isinstance(x, str)])
        domains = [
            value for value in domains
            if not ac.find_other_pattern(value.strip().lower(), -1)
        ]

    # 3 → 4：反向标签树思想，域名只按 DNS label 边界判断，避免简单 substring 误删。
    if suffixes and domains:
        suffix_set = {normalize_domain(x) for x in suffixes if isinstance(x, str)}
        filtered = []
        for value in domains:
            current = normalize_domain(value)
            labels = current.split('.') if current else []
            covered = False
            for i in range(len(labels)):
                if '.'.join(labels[i:]) in suffix_set:
                    covered = True
                    break
            if not covered:
                filtered.append(value)
        domains = filtered

    rule["domain_keyword"] = keywords
    rule["domain_suffix"] = suffixes
    rule["domain"] = domains
    return rule

def clean_empty_arrays(rule):
    return {
        key: value
        for key, value in rule.items()
        if not (isinstance(value, list) and not value)
    }


def create_empty_standard_rule():
    return {
        "domain": [],
        "domain_suffix": [],
        "domain_keyword": [],
        "domain_regex": [],
        "ip_cidr": [],
    }


def append_remote_json_to_standard(standard_rule, remote_data, source):
    for rule_index, remote_rule in enumerate(remote_data["rules"]):
        if not isinstance(remote_rule, dict):
            raise ValueError(f"{source}: rules[{rule_index}] 不是对象")

        for field in RULE_FIELDS:
            values = remote_rule.get(field)
            if values is None:
                continue
            if not isinstance(values, list):
                raise ValueError(
                    f"{source}: rules[{rule_index}].{field} 必须是数组"
                )
            # 这里只合并，不去重。
            standard_rule[field].extend(values)


def merge_all_remote_json(rule_sets):
    standard_rule = create_empty_standard_rule()

    # 所有远程 JSON 全部合并完成。
    for source, data in rule_sets:
        append_remote_json_to_standard(standard_rule, data, source)

    # 合并完成后才开始统一去重。
    standard_rule = dedupe_same_field(standard_rule)
    standard_rule = apply_parent_hierarchy(standard_rule)
    standard_rule = clean_empty_arrays(standard_rule)

    rules = [standard_rule] if standard_rule else []

    return {"version": TARGET_VERSION, "rules": rules}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write("\n")


def compile_srs(json_path, srs_path):
    command = [
        "sing-box", "rule-set", "compile",
        "--output", str(srs_path), str(json_path)
    ]
    log("      编译 SRS: " + " ".join(command))
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        if result.stdout.strip():
            detail += ("\n" if detail else "") + result.stdout.strip()
        raise RuntimeError(detail or "sing-box 编译失败")
    if not srs_path.exists() or srs_path.stat().st_size == 0:
        raise RuntimeError("sing-box 返回成功，但 SRS 文件不存在或为空")


def process_url_file(path, failures):
    log("")
    log(f"[远程规则] {rel(path)}")

    urls = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    rule_sets = []

    # 先拉取所有 URL；这里不合并、不去重。
    for url in urls:
        try:
            rule_sets.append((url, download_json(url)))
        except Exception as exc:
            failures.append({
                "file": rel(path),
                "stage": "远程 JSON 拉取",
                "detail": f"{url} → {exc}",
            })
            log(f"      ❌ {url}: {exc}")

    if not rule_sets:
        log("      ❌ 没有任何 URL 拉取成功，跳过该文件")
        return

    # 所有成功 URL 拉取完成后，一次性合并并去重。
    try:
        merged = merge_all_remote_json(rule_sets)
        json_path = path.with_suffix(".json")
        write_json(json_path, merged)
        log(f"      ✓ 生成 JSON: {rel(json_path)}")
    except Exception as exc:
        failures.append({
            "file": rel(path),
            "stage": "远程 JSON 合并/去重/生成",
            "detail": str(exc),
        })
        log(f"      ❌ 合并/去重/生成失败: {exc}")


def build_all_srs(failures):
    json_files = find_json_files()

    log("")
    log("========================================")
    log("统一阶段：JSON → SRS")
    log(f"JSON 数量: {len(json_files)}")
    log("========================================")

    for json_path in json_files:
        srs_path = json_path.with_suffix(".srs")
        try:
            data = load_local_json(json_path)
            if data.get("version") != TARGET_VERSION:
                raise ValueError(f"version 必须为 {TARGET_VERSION}")
            compile_srs(json_path, srs_path)
            log(f"      ✓ {rel(srs_path)}")
        except Exception as exc:
            failures.append({
                "file": rel(json_path),
                "stage": "JSON → SRS",
                "detail": str(exc),
            })
            log(f"      ❌ {rel(json_path)}: {exc}")


def update_readme(failures):
    start_marker = "<!-- SRS-BUILD-STATUS:START -->"
    end_marker = "<!-- SRS-BUILD-STATUS:END -->"

    content = (
        README.read_text(encoding="utf-8")
        if README.exists()
        else "# a_srs\n"
    )

    lines = [start_marker, "", "## SRS 构建状态", ""]

    if not failures:
        lines.extend([
            "### ✅ 本次工作流全部成功",
            "",
            "所有远程规则拉取、合并、统一去重、JSON 生成及 SRS 编译均成功。",
        ])
    else:
        lines.extend([
            "### ⚠️ 本次工作流存在失败",
            "",
            "单个 URL、JSON 或 SRS 失败不会阻止其它文件继续处理。",
            "",
            "| 文件 | 阶段 | 详细错误 |",
            "|---|---|---|",
        ])
        for item in failures:
            file_name = str(item["file"]).replace("|", "\\|")
            stage = str(item["stage"]).replace("|", "\\|")
            detail = (
                str(item["detail"])
                .replace("|", "\\|")
                .replace("\n", "<br>")
            )
            lines.append(f"| `{file_name}` | {stage} | {detail} |")

    lines.extend(["", end_marker])
    block = "\n".join(lines)

    if start_marker in content and end_marker in content:
        start = content.index(start_marker)
        end = content.index(end_marker) + len(end_marker)
        content = content[:start] + block + content[end:]
    else:
        content = content.rstrip() + "\n\n" + block + "\n"

    README.write_text(content, encoding="utf-8", newline="\n")


def main():
    failures = []

    log("========================================")
    log("a_srs SRS Builder")
    log("version 4 / merge-then-dedupe")
    log("========================================")

    url_files = find_url_files()

    log("")
    log("========================================")
    log("第一阶段：远程 JSON")
    log(f"URL 文件数量: {len(url_files)}")
    log("========================================")

    for path in url_files:
        try:
            process_url_file(path, failures)
        except Exception as exc:
            failures.append({
                "file": rel(path),
                "stage": "URL 文件处理",
                "detail": str(exc),
            })
            log(f"      ❌ 文件处理失败: {exc}")

    build_all_srs(failures)
    update_readme(failures)

    log("")
    log("========================================")
    log(f"工作流处理完成，失败数量: {len(failures)}")
    log("========================================")

    # 容错：单个文件失败不阻止其它文件完成。
    sys.exit(0)


if __name__ == "__main__":
    main()
