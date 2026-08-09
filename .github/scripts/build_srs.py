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
SKIP_DIRS = {".git", ".github"}
SKIP_FILES = {"README.md"}

RULE_FIELDS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
)


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
            x.strip()
            for x in path.read_text(encoding="utf-8").splitlines()
            if x.strip()
        ]
    except Exception:
        return False
    return bool(lines) and all(is_url(x) for x in lines)


def find_url_files():
    result = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rp = path.relative_to(ROOT)
        if any(x in SKIP_DIRS for x in rp.parts):
            continue
        if is_url_file(path):
            result.append(path)
    return sorted(result)


def find_json_files():
    result = []
    for path in ROOT.rglob("*.json"):
        if not path.is_file():
            continue
        rp = path.relative_to(ROOT)
        if any(x in SKIP_DIRS for x in rp.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        result.append(path)
    return sorted(result)


def parse_json_bytes(content, source):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{source}: UTF-8 解码失败: {e}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"{source}: JSON 解析失败: {e}")

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
    except HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {e.reason}")
    except URLError as e:
        raise RuntimeError(f"网络错误: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"拉取失败: {e}")
    return parse_json_bytes(content, url)


def collect_rules(rule_sets):
    merged = {field: [] for field in RULE_FIELDS}
    extra = {}

    for data in rule_sets:
        for rule in data["rules"]:
            if not isinstance(rule, dict):
                raise ValueError("rules 中存在不是对象的项目")

            for key, value in rule.items():
                if key in RULE_FIELDS:
                    if not isinstance(value, list):
                        raise ValueError(f"字段 {key} 必须是数组")
                    merged[key].extend(value)
                else:
                    extra.setdefault(key, []).append(value)

    return merged, extra


def normalize_domain(value):
    if not isinstance(value, str):
        return value
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    return value


def exact_dedupe(values):
    seen = set()
    result = []
    for value in values:
        key = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def dedupe_domain(values):
    return exact_dedupe(values)


def dedupe_keyword(values):
    values = [x for x in exact_dedupe(values) if isinstance(x, str)]
    normalized = []
    seen_norm = set()

    for value in values:
        v = value.strip().lower()
        if v not in seen_norm:
            seen_norm.add(v)
            normalized.append(value)

    ordered = sorted(normalized, key=lambda x: (len(x), x.lower()))
    result = []

    for value in ordered:
        v = value.strip().lower()
        if any(parent.strip().lower() in v for parent in result):
            continue
        result.append(value)

    return result


def suffix_covers(parent, child):
    parent = normalize_domain(parent)
    child = normalize_domain(child)

    if not isinstance(parent, str) or not isinstance(child, str):
        return False

    return child == parent or child.endswith("." + parent)


def dedupe_suffix(values):
    values = [x for x in exact_dedupe(values) if isinstance(x, str)]
    normalized = []
    seen = set()

    for value in values:
        v = normalize_domain(value)
        if v not in seen:
            seen.add(v)
            normalized.append(value)

    ordered = sorted(
        normalized,
        key=lambda x: (
            normalize_domain(x).count("."),
            len(normalize_domain(x)),
            normalize_domain(x),
        ),
    )

    result = []
    for value in ordered:
        v = normalize_domain(value)
        if any(suffix_covers(existing, v) for existing in result):
            continue
        result.append(value)

    return result


def dedupe_regex(values):
    values = [x for x in exact_dedupe(values) if isinstance(x, str)]
    normalized = []
    seen = set()

    for value in values:
        v = value.strip()
        if v not in seen:
            seen.add(v)
            normalized.append(value)

    ordered = sorted(normalized, key=lambda x: (len(x), x))
    result = []

    for value in ordered:
        if any(parent in value for parent in result):
            continue
        result.append(value)

    return result


def parse_network(value):
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def dedupe_ip_cidr(values):
    values = exact_dedupe(values)
    valid = []
    invalid = []
    seen_text = set()

    for value in values:
        if not isinstance(value, str):
            invalid.append(value)
            continue

        text = value.strip()
        if text in seen_text:
            continue
        seen_text.add(text)

        network = parse_network(text)
        if network is None:
            invalid.append(value)
        else:
            valid.append((network, value))

    valid.sort(
        key=lambda item: (
            item[0].version,
            item[0].prefixlen,
            str(item[0].network_address),
        )
    )

    kept = []
    for network, original in valid:
        covered = False
        for parent, _ in kept:
            if network.version == parent.version and network.subnet_of(parent):
                covered = True
                break
        if not covered:
            kept.append((network, original))

    return [original for _, original in kept] + invalid


def normalize_rule_arrays(rule):
    result = {}

    for field, values in rule.items():
        if not isinstance(values, list):
            result[field] = values
            continue

        if field == "domain":
            values = dedupe_domain(values)
        elif field == "domain_keyword":
            values = dedupe_keyword(values)
        elif field == "domain_suffix":
            values = dedupe_suffix(values)
        elif field == "domain_regex":
            values = dedupe_regex(values)
        elif field == "ip_cidr":
            values = dedupe_ip_cidr(values)
        else:
            values = exact_dedupe(values)

        if values:
            result[field] = values

    return result


def regex_matches(pattern, candidate):
    if not isinstance(pattern, str) or not isinstance(candidate, str):
        return False
    try:
        return re.search(pattern, candidate, re.IGNORECASE) is not None
    except re.error:
        return False


def remove_by_regex(rule):
    regexes = rule.get("domain_regex", [])
    if not regexes:
        return rule

    result = dict(rule)

    for field in ("domain_keyword", "domain_suffix", "domain"):
        values = result.get(field, [])
        new_values = [
            value
            for value in values
            if not any(regex_matches(pattern, value) for pattern in regexes)
        ]

        if new_values:
            result[field] = new_values
        else:
            result.pop(field, None)

    return result


def keyword_covers(keyword, candidate):
    if not isinstance(keyword, str) or not isinstance(candidate, str):
        return False
    return keyword.strip().lower() in candidate.strip().lower()


def remove_by_keyword(rule):
    keywords = rule.get("domain_keyword", [])
    if not keywords:
        return rule

    result = dict(rule)

    for field in ("domain_suffix", "domain"):
        values = result.get(field, [])
        new_values = [
            value
            for value in values
            if not any(keyword_covers(keyword, value) for keyword in keywords)
        ]

        if new_values:
            result[field] = new_values
        else:
            result.pop(field, None)

    return result


def remove_by_suffix(rule):
    suffixes = rule.get("domain_suffix", [])
    if not suffixes:
        return rule

    result = dict(rule)
    domains = result.get("domain", [])

    new_domains = [
        domain
        for domain in domains
        if not any(suffix_covers(suffix, domain) for suffix in suffixes)
    ]

    if new_domains:
        result["domain"] = new_domains
    else:
        result.pop("domain", None)

    return result


def apply_parent_hierarchy(rule):
    rule = remove_by_regex(rule)
    rule = remove_by_keyword(rule)
    rule = remove_by_suffix(rule)
    return rule


def clean_empty_arrays(rule):
    return {
        key: value
        for key, value in rule.items()
        if not (isinstance(value, list) and not value)
    }


def merge_rule_sets(rule_sets):
    merged, extra = collect_rules(rule_sets)

    normalized = normalize_rule_arrays(merged)
    normalized = apply_parent_hierarchy(normalized)
    normalized = clean_empty_arrays(normalized)

    rules = []
    if normalized:
        rules.append(normalized)

    for key, values in extra.items():
        values = exact_dedupe(values)
        if not values:
            continue
        if rules:
            rules[0][key] = values
        else:
            rules.append({key: values})

    return {"version": TARGET_VERSION, "rules": rules}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def compile_srs(json_path, srs_path):
    command = [
        "sing-box",
        "rule-set",
        "compile",
        "--output",
        str(srs_path),
        str(json_path),
    ]

    log("      编译 SRS: " + " ".join(command))

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        detail = result.stderr.strip()
        if result.stdout.strip():
            detail += ("\n" if detail else "") + result.stdout.strip()
        raise RuntimeError(detail or "sing-box 编译失败")

    if not srs_path.exists():
        raise RuntimeError("sing-box 返回成功，但没有生成 SRS 文件")
    if srs_path.stat().st_size == 0:
        raise RuntimeError("生成的 SRS 文件为空")


def process_url_file(path, failures):
    log("")
    log(f"[远程规则] {rel(path)}")

    lines = [
        x.strip()
        for x in path.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]

    rule_sets = []

    for url in lines:
        try:
            rule_sets.append(download_json(url))
        except Exception as e:
            failures.append({
                "file": rel(path),
                "stage": "远程 JSON",
                "detail": f"{url} → {e}",
            })
            log(f"      ❌ {url}: {e}")
            continue

    if not rule_sets:
        log("      ❌ 所有 URL 均失败，跳过该文件")
        return

    try:
        merged = merge_rule_sets(rule_sets)
    except Exception as e:
        failures.append({
            "file": rel(path),
            "stage": "合并去重",
            "detail": str(e),
        })
        log(f"      ❌ 合并去重失败: {e}")
        return

    json_path = path.with_suffix(".json")

    try:
        write_json(json_path, merged)
        log(f"      ✓ 生成 JSON: {rel(json_path)}")
    except Exception as e:
        failures.append({
            "file": rel(path),
            "stage": "生成 JSON",
            "detail": str(e),
        })
        log(f"      ❌ JSON 生成失败: {e}")


def build_all_srs(failures):
    json_files = find_json_files()

    log("")
    log("========================================")
    log("第二阶段：统一 JSON → SRS")
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

        except Exception as e:
            failures.append({
                "file": rel(json_path),
                "stage": "JSON → SRS",
                "detail": str(e),
            })
            log(f"      ❌ {rel(json_path)}: {e}")
            continue


def update_readme(failures):
    start_marker = "<!-- SRS-BUILD-STATUS:START -->"
    end_marker = "<!-- SRS-BUILD-STATUS:END -->"

    content = README.read_text(encoding="utf-8") if README.exists() else "# a_srs\n"

    lines = [start_marker, "", "## SRS 构建状态", ""]

    if not failures:
        lines += [
            "### ✅ 本次工作流全部成功",
            "",
            "所有远程规则拉取、JSON 合并去重、JSON 生成及 SRS 编译均成功。",
        ]
    else:
        lines += [
            "### ⚠️ 本次工作流存在失败",
            "",
            "单个 URL、JSON 或 SRS 失败不会阻止其它文件继续处理。",
            "",
            "| 文件 | 阶段 | 详细错误 |",
            "|---|---|---|",
        ]

        for item in failures:
            file_name = str(item["file"]).replace("|", "\\|")
            stage = str(item["stage"]).replace("|", "\\|")
            detail = (
                str(item["detail"])
                .replace("|", "\\|")
                .replace("\n", "<br>")
            )
            lines.append(f"| `{file_name}` | {stage} | {detail} |")

    lines += ["", end_marker]
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
    log("Target Source Format: version 4")
    log("========================================")

    url_files = find_url_files()

    log("")
    log("========================================")
    log("第一阶段：拉取远程 JSON")
    log(f"URL 文件数量: {len(url_files)}")
    log("========================================")

    for path in url_files:
        try:
            process_url_file(path, failures)
        except Exception as e:
            failures.append({
                "file": rel(path),
                "stage": "URL 文件处理",
                "detail": str(e),
            })
            log(f"      ❌ 文件处理失败: {e}")
            continue

    build_all_srs(failures)
    update_readme(failures)

    log("")
    log("========================================")
    log("工作流处理完成")
    log(f"失败数量: {len(failures)}")
    log("========================================")

    sys.exit(0)


if __name__ == "__main__":
    main()
