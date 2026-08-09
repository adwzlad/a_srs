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


def dedupe_domain(values):
    return exact_dedupe(values)


def dedupe_keyword(values):
    values = [
        v for v in exact_dedupe(values) if isinstance(v, str)
    ]
    values.sort(key=lambda v: (len(v.strip()), v.strip().lower()))
    result = []
    for value in values:
        current = value.strip().lower()
        if any(parent.strip().lower() in current for parent in result):
            continue
        result.append(value)
    return result


def dedupe_suffix(values):
    values = [
        v for v in exact_dedupe(values) if isinstance(v, str)
    ]
    values.sort(
        key=lambda v: (
            normalize_domain(v).count("."),
            len(normalize_domain(v)),
            normalize_domain(v),
        )
    )
    result = []
    for value in values:
        if any(suffix_covers(parent, value) for parent in result):
            continue
        result.append(value)
    return result


def dedupe_regex(values):
    values = [
        v for v in exact_dedupe(values) if isinstance(v, str)
    ]
    values.sort(key=lambda v: (len(v.strip()), v.strip()))
    result = []
    for value in values:
        current = value.strip()
        if any(parent.strip() in current for parent in result):
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

    for value in values:
        network = parse_network(value)
        if network is None:
            invalid.append(value)
        else:
            valid.append((network, value))

    valid.sort(
        key=lambda item: (
            item[0].version,
            item[0].prefixlen,
            int(item[0].network_address),
        )
    )

    kept = []
    for network, original in valid:
        if any(
            network.version == parent.version
            and network.subnet_of(parent)
            for parent, _ in kept
        ):
            continue
        kept.append((network, original))

    return [original for _, original in kept] + invalid


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


def parent_1_to_2(rule):
    parent = rule.get("domain_regex", [])
    child = rule.get("domain_keyword", [])
    if not parent or not child:
        return
    rule["domain_keyword"] = [
        value for value in child
        if not any(regex_matches(pattern, value) for pattern in parent)
    ]


def parent_1_to_3(rule):
    parent = rule.get("domain_regex", [])
    child = rule.get("domain_suffix", [])
    if not parent or not child:
        return
    rule["domain_suffix"] = [
        value for value in child
        if not any(regex_matches(pattern, value) for pattern in parent)
    ]


def parent_1_to_4(rule):
    parent = rule.get("domain_regex", [])
    child = rule.get("domain", [])
    if not parent or not child:
        return
    rule["domain"] = [
        value for value in child
        if not any(regex_matches(pattern, value) for pattern in parent)
    ]


def parent_2_to_3(rule):
    parent = rule.get("domain_keyword", [])
    child = rule.get("domain_suffix", [])
    if not parent or not child:
        return
    rule["domain_suffix"] = [
        value for value in child
        if not any(
            isinstance(keyword, str)
            and isinstance(value, str)
            and keyword.strip().lower() in value.strip().lower()
            for keyword in parent
        )
    ]


def parent_2_to_4(rule):
    parent = rule.get("domain_keyword", [])
    child = rule.get("domain", [])
    if not parent or not child:
        return
    rule["domain"] = [
        value for value in child
        if not any(
            isinstance(keyword, str)
            and isinstance(value, str)
            and keyword.strip().lower() in value.strip().lower()
            for keyword in parent
        )
    ]


def parent_3_to_4(rule):
    parent = rule.get("domain_suffix", [])
    child = rule.get("domain", [])
    if not parent or not child:
        return
    rule["domain"] = [
        value for value in child
        if not any(suffix_covers(parent_suffix, value) for parent_suffix in parent)
    ]


def apply_parent_hierarchy(rule):
    parent_1_to_2(rule)
    parent_1_to_3(rule)
    parent_1_to_4(rule)
    parent_2_to_3(rule)
    parent_2_to_4(rule)
    parent_3_to_4(rule)
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
