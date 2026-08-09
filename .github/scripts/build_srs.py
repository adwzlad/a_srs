#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ============================================================
# 基本配置
# ============================================================

ROOT = Path(".").resolve()

README = ROOT / "README.md"

TARGET_VERSION = 4

SKIP_DIRS = {
    ".git",
    ".github",
}

SKIP_FILES = {
    "README.md",
}


# ============================================================
# 日志
# ============================================================

def log(message):
    print(message, flush=True)


def relative(path):
    return str(path.relative_to(ROOT))


# ============================================================
# URL 判断
# ============================================================

def is_url(value):
    return (
        value.startswith("http://")
        or value.startswith("https://")
    )


# ============================================================
# 判断无后缀文件是否为 URL 文件
#
# 例如：
#
# apple
# ├── https://xxx/apple.json
# └── https://xxx/apple-ip.json
#
# ============================================================

def is_url_file(path):

    if path.suffix:
        return False

    if path.name in SKIP_FILES:
        return False

    try:
        text = path.read_text(
            encoding="utf-8"
        )
    except Exception:
        return False

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        return False

    return all(
        is_url(line)
        for line in lines
    )


# ============================================================
# 查找所有无后缀 URL 文件
# ============================================================

def find_url_files():

    result = []

    for path in ROOT.rglob("*"):

        if not path.is_file():
            continue

        relative_path = path.relative_to(ROOT)

        if any(
            part in SKIP_DIRS
            for part in relative_path.parts
        ):
            continue

        if path.name in SKIP_FILES:
            continue

        if is_url_file(path):
            result.append(path)

    return sorted(result)


# ============================================================
# 查找所有 JSON 文件
# ============================================================

def find_json_files():

    result = []

    for path in ROOT.rglob("*.json"):

        if not path.is_file():
            continue

        relative_path = path.relative_to(ROOT)

        if any(
            part in SKIP_DIRS
            for part in relative_path.parts
        ):
            continue

        if path.name in SKIP_FILES:
            continue

        result.append(path)

    return sorted(result)


# ============================================================
# JSON 加载
# ============================================================

def load_json_bytes(
    content,
    source
):

    try:
        text = content.decode(
            "utf-8"
        )

    except UnicodeDecodeError as e:

        raise ValueError(
            f"{source}: UTF-8 解码失败: {e}"
        )

    try:

        data = json.loads(text)

    except json.JSONDecodeError as e:

        raise ValueError(
            f"{source}: JSON 解析失败: {e}"
        )

    if not isinstance(
        data,
        dict
    ):

        raise ValueError(
            f"{source}: JSON 根节点必须是对象"
        )

    if "rules" not in data:

        raise ValueError(
            f"{source}: 缺少 rules"
        )

    if not isinstance(
        data["rules"],
        list
    ):

        raise ValueError(
            f"{source}: rules 必须是数组"
        )

    return data


# ============================================================
# 加载本地 JSON
# ============================================================

def load_local_json(path):

    with path.open(
        "rb"
    ) as f:

        content = f.read()

    return load_json_bytes(
        content,
        relative(path)
    )


# ============================================================
# 下载远程 JSON
# ============================================================

def download_json(url):

    log(
        f"      拉取: {url}"
    )

    request = Request(
        url,
        headers={
            "User-Agent": "a_srs/1.0"
        }
    )

    try:

        with urlopen(
            request,
            timeout=60
        ) as response:

            content = response.read()

    except HTTPError as e:

        raise RuntimeError(
            f"HTTP {e.code} {e.reason}"
        )

    except URLError as e:

        raise RuntimeError(
            f"网络错误: {e.reason}"
        )

    except Exception as e:

        raise RuntimeError(
            f"拉取失败: {e}"
        )

    return load_json_bytes(
        content,
        url
    )


# ============================================================
# 统一 Source Format version
#
# 允许：
#
# version 1
# version 2
# version 3
# version 4
#
# 最终统一输出：
#
# version 4
#
# version > 4 拒绝处理
# 因为不能安全降级未来版本格式。
# ============================================================

def normalize_version(
    data,
    source
):

    version = data.get(
        "version"
    )

    if version is None:

        raise ValueError(
            f"{source}: 缺少 version"
        )

    if not isinstance(
        version,
        int
    ):

        raise ValueError(
            f"{source}: version 必须是整数"
        )

    if version > TARGET_VERSION:

        raise ValueError(
            f"{source}: version={version} "
            f"高于目标 version={TARGET_VERSION}"
        )

    return {
        "version": TARGET_VERSION,
        "rules": data["rules"]
    }


# ============================================================
# 完全匹配去重
#
# 保持第一次出现的顺序。
# ============================================================

def dedupe_exact_array(
    values
):

    result = []

    seen = set()

    for value in values:

        key = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(
                ",",
                ":"
            )
        )

        if key in seen:
            continue

        seen.add(key)

        result.append(value)

    return result


# ============================================================
# 域名标准化
#
# 只用于比较，不修改最终输出。
# ============================================================

def normalize_domain(
    value
):

    if not isinstance(
        value,
        str
    ):
        return value

    value = value.strip().lower()

    # 删除 DNS 名称末尾的 .
    if value.endswith("."):
        value = value[:-1]

    return value


# ============================================================
# 判断 domain_suffix 是否覆盖某个域名
#
# parent:
#     example.com
#
# child:
#     www.example.com
#
# True
#
# 但：
#
# example.com
# badexample.com
#
# False
#
# ============================================================

def domain_suffix_covers(
    parent,
    child
):

    parent = normalize_domain(
        parent
    )

    child = normalize_domain(
        child
    )

    if not isinstance(
        parent,
        str
    ):
        return False

    if not isinstance(
        child,
        str
    ):
        return False

    if parent == child:
        return True

    return child.endswith(
        "." + parent
    )


# ============================================================
# domain_suffix 智能去重
#
# 例如：
#
# example.com
# sub.example.com
# api.sub.example.com
#
# 最终：
#
# example.com
#
# ============================================================

def dedupe_domain_suffix(
    values
):

    # 第一层：完全匹配去重
    values = dedupe_exact_array(
        values
    )

    result = []

    for value in values:

        if not isinstance(
            value,
            str
        ):

            result.append(value)

            continue

        covered = False

        for existing in result:

            if not isinstance(
                existing,
                str
            ):
                continue

            if domain_suffix_covers(
                existing,
                value
            ):

                covered = True

                break

        if not covered:

            result.append(value)

    return result


# ============================================================
# 处理单个 Rule
#
# 所有数组字段：
#     完全匹配去重
#
# domain_suffix：
#     完全匹配 + 父后缀智能去重
#
# 空 []：
#     删除字段
#
# ============================================================

def process_rule(
    rule
):

    if not isinstance(
        rule,
        dict
    ):

        raise ValueError(
            "rules 中存在不是对象的项目"
        )

    result = {}

    for key, value in rule.items():

        if isinstance(
            value,
            list
        ):

            if key == "domain_suffix":

                value = dedupe_domain_suffix(
                    value
                )

            else:

                value = dedupe_exact_array(
                    value
                )

            # 空数组自动删除
            if not value:
                continue

        elif value is None:

            continue

        result[key] = value

    return result


# ============================================================
# 收集全部 domain_suffix
# ============================================================

def collect_domain_suffixes(
    rules
):

    suffixes = []

    for rule in rules:

        values = rule.get(
            "domain_suffix",
            []
        )

        for value in values:

            if isinstance(
                value,
                str
            ):

                suffixes.append(
                    value
                )

    return dedupe_domain_suffix(
        suffixes
    )


# ============================================================
# domain_suffix → domain
#
# 如果 suffix 能覆盖 domain：
#
#     删除 domain
#
# 例如：
#
# domain:
#     www.example.com
#
# domain_suffix:
#     example.com
#
# 删除：
#
# www.example.com
#
# ============================================================

def remove_domains_covered_by_suffix(
    rules
):

    suffixes = collect_domain_suffixes(
        rules
    )

    if not suffixes:
        return rules

    result = []

    for rule in rules:

        if "domain" not in rule:

            result.append(
                rule
            )

            continue

        domains = rule.get(
            "domain",
            []
        )

        new_domains = []

        for domain in domains:

            if not isinstance(
                domain,
                str
            ):

                new_domains.append(
                    domain
                )

                continue

            covered = False

            for suffix in suffixes:

                if domain_suffix_covers(
                    suffix,
                    domain
                ):

                    covered = True

                    break

            if not covered:

                new_domains.append(
                    domain
                )

        new_rule = dict(
            rule
        )

        if new_domains:

            new_rule["domain"] = (
                dedupe_exact_array(
                    new_domains
                )
            )

        else:

            # domain 变成空数组
            # 直接删除字段
            new_rule.pop(
                "domain",
                None
            )

        # 如果 {}：
        # 不加入 rules
        if new_rule:

            result.append(
                new_rule
            )

    return result


# ============================================================
# 最终 Rule 清理
#
# 1. [] 删除
# 2. {} 删除
#
# ============================================================

def clean_rules(
    rules
):

    cleaned = []

    for rule in rules:

        if not isinstance(
            rule,
            dict
        ):
            continue

        # 删除所有空数组字段
        new_rule = {}

        for key, value in rule.items():

            if isinstance(
                value,
                list
            ):

                if not value:
                    continue

            if value is None:
                continue

            new_rule[
                key
            ] = value

        # 空 {} 删除
        if not new_rule:
            continue

        cleaned.append(
            new_rule
        )

    return cleaned


# ============================================================
# 合并多个 Rule Set
#
# ============================================================

def merge_rule_sets(
    rule_sets
):

    merged_rules = []

    for data in rule_sets:

        for rule in data[
            "rules"
        ]:

            processed = process_rule(
                rule
            )

            # 空 {} 不加入
            if processed:

                merged_rules.append(
                    processed
                )

    # --------------------------------------------------------
    # domain_suffix 自身智能去重
    # --------------------------------------------------------

    for rule in merged_rules:

        if "domain_suffix" in rule:

            rule[
                "domain_suffix"
            ] = dedupe_domain_suffix(
                rule[
                    "domain_suffix"
                ]
            )

    # --------------------------------------------------------
    # domain_suffix → domain
    #
    # suffix 覆盖 domain
    # 删除 domain
    # --------------------------------------------------------

    merged_rules = (
        remove_domains_covered_by_suffix(
            merged_rules
        )
    )

    # --------------------------------------------------------
    # 最终清理
    #
    # [] → 删除
    # {} → 删除
    # --------------------------------------------------------

    merged_rules = clean_rules(
        merged_rules
    )

    return {
        "version": TARGET_VERSION,
        "rules": merged_rules
    }


# ============================================================
# 写 JSON
#
# 绝对不手工处理逗号。
#
# json.dump 会自动保证：
#
#     最后一个数组元素没有 ,
#     最后一个对象字段没有 ,
#
# 因此删除 {} 后不会出现：
#
#     [ , {...} ]
#
# 或：
#
#     [{...},]
#
# ============================================================

def write_json(
    path,
    data
):

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2
        )

        f.write("\n")


# ============================================================
# 编译 SRS
# ============================================================

def compile_srs(
    json_path,
    srs_path
):

    command = [
        "sing-box",
        "rule-set",
        "compile",
        "--output",
        str(srs_path),
        str(json_path)
    ]

    log(
        "      编译 SRS: "
        + " ".join(command)
    )

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        message = (
            result.stderr.strip()
        )

        if result.stdout.strip():

            if message:

                message += "\n"

            message += (
                result.stdout.strip()
            )

        raise RuntimeError(
            message or
            "sing-box 编译失败"
        )

    if not srs_path.exists():

        raise RuntimeError(
            "sing-box 返回成功，"
            "但没有生成 SRS 文件"
        )

    if srs_path.stat().st_size == 0:

        raise RuntimeError(
            "生成的 SRS 文件为空"
        )


# ============================================================
# 第一阶段：
#
# 无后缀 URL 文件 → JSON
#
# ============================================================

def process_url_file(
    path,
    failures
):

    log("")
    log(
        f"[远程规则] {relative(path)}"
    )

    lines = [
        line.strip()
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    rule_sets = []

    # --------------------------------------------------------
    # 一个 URL 或多个 URL
    #
    # 都先下载。
    #
    # 一个 URL：
    #     最终也经过 version 4 转换
    #
    # 多个 URL：
    #     下载后合并
    # --------------------------------------------------------

    for url in lines:

        try:

            data = download_json(
                url
            )

            data = normalize_version(
                data,
                url
            )

            rule_sets.append(
                data
            )

        except Exception as e:

            failures.append({
                "file": relative(path),
                "stage": "远程 JSON",
                "detail": (
                    f"{url} → {e}"
                )
            })

            log(
                f"      ❌ {url}: {e}"
            )

            # 当前 URL 失败
            # 继续下一个 URL
            continue

    # --------------------------------------------------------
    # 所有 URL 都失败
    # --------------------------------------------------------

    if not rule_sets:

        log(
            "      ❌ 所有 URL 都失败，"
            "跳过该文件"
        )

        return

    # --------------------------------------------------------
    # 合并 / 去重
    # --------------------------------------------------------

    try:

        merged = merge_rule_sets(
            rule_sets
        )

    except Exception as e:

        failures.append({
            "file": relative(path),
            "stage": "合并",
            "detail": str(e)
        })

        log(
            f"      ❌ 合并失败: {e}"
        )

        return

    # --------------------------------------------------------
    # 生成同名 JSON
    # --------------------------------------------------------

    json_path = path.with_suffix(
        ".json"
    )

    try:

        write_json(
            json_path,
            merged
        )

        log(
            f"      ✓ 生成 JSON: "
            f"{relative(json_path)}"
        )

    except Exception as e:

        failures.append({
            "file": relative(path),
            "stage": "生成 JSON",
            "detail": str(e)
        })

        log(
            f"      ❌ JSON 生成失败: {e}"
        )

        return


# ============================================================
# 检查本地 JSON
#
# 本地 JSON 必须已经是 version 4。
# ============================================================

def process_local_json(
    path,
    failures
):

    log("")
    log(
        f"[本地 JSON] {relative(path)}"
    )

    try:

        data = load_local_json(
            path
        )

        version = data.get(
            "version"
        )

        if version != TARGET_VERSION:

            raise ValueError(
                f"要求 version: "
                f"{TARGET_VERSION}，"
                f"实际为 version: "
                f"{version}"
            )

    except Exception as e:

        failures.append({
            "file": relative(path),
            "stage": "JSON 检查",
            "detail": str(e)
        })

        log(
            f"      ❌ {e}"
        )

        return


# ============================================================
# 第二阶段：
#
# 所有 JSON → SRS
#
# 注意：
#
# 必须等第一阶段所有远程 JSON 全部处理完，
# 才进入这里。
# ============================================================

def build_all_srs(
    failures
):

    json_files = find_json_files()

    log("")
    log(
        "========================================"
    )
    log(
        "第二阶段：统一 JSON → SRS"
    )
    log(
        f"JSON 数量: {len(json_files)}"
    )
    log(
        "========================================"
    )

    for json_path in json_files:

        srs_path = json_path.with_suffix(
            ".srs"
        )

        try:

            data = load_local_json(
                json_path
            )

            if data.get(
                "version"
            ) != TARGET_VERSION:

                raise ValueError(
                    f"version 必须为 "
                    f"{TARGET_VERSION}"
                )

            compile_srs(
                json_path,
                srs_path
            )

            log(
                f"      ✓ {relative(srs_path)}"
            )

        except Exception as e:

            failures.append({
                "file": relative(json_path),
                "stage": "JSON → SRS",
                "detail": str(e)
            })

            log(
                f"      ❌ "
                f"{relative(json_path)}: {e}"
            )

            # 当前 JSON 失败
            # 继续下一个 JSON
            continue


# ============================================================
# README 状态
#
# 只保留最近一次工作流结果。
#
# 不保留历史错误。
# ============================================================

def update_readme(
    failures
):

    if README.exists():

        content = README.read_text(
            encoding="utf-8"
        )

    else:

        content = "# a_srs\n"

    start_marker = (
        "<!-- SRS-BUILD-STATUS:START -->"
    )

    end_marker = (
        "<!-- SRS-BUILD-STATUS:END -->"
    )

    lines = []

    lines.append(
        start_marker
    )

    lines.append("")

    lines.append(
        "## SRS 构建状态"
    )

    lines.append("")

    # --------------------------------------------------------
    # 全部成功
    # --------------------------------------------------------

    if not failures:

        lines.append(
            "### ✅ 本次工作流全部成功"
        )

        lines.append("")

        lines.append(
            "所有远程规则拉取、JSON 合并、"
            "JSON 生成及 SRS 编译均成功。"
        )

    # --------------------------------------------------------
    # 存在失败
    # --------------------------------------------------------

    else:

        lines.append(
            "### ⚠️ 本次工作流存在失败"
        )

        lines.append("")

        lines.append(
            "单个文件或 URL 失败不会影响其它"
            "文件继续处理。"
        )

        lines.append("")

        lines.append(
            "| 文件 | 阶段 | 详细错误 |"
        )

        lines.append(
            "|---|---|---|"
        )

        for item in failures:

            file_name = (
                item["file"]
                .replace(
                    "|",
                    "\\|"
                )
            )

            stage = (
                item["stage"]
                .replace(
                    "|",
                    "\\|"
                )
            )

            detail = (
                str(item["detail"])
                .replace(
                    "|",
                    "\\|"
                )
                .replace(
                    "\n",
                    "<br>"
                )
            )

            lines.append(
                f"| `{file_name}` | "
                f"{stage} | "
                f"{detail} |"
            )

    lines.append("")

    lines.append(
        end_marker
    )

    new_block = "\n".join(
        lines
    )

    # --------------------------------------------------------
    # 替换上一次状态
    # --------------------------------------------------------

    if (
        start_marker in content
        and end_marker in content
    ):

        start = content.index(
            start_marker
        )

        end = (
            content.index(
                end_marker
            )
            + len(end_marker)
        )

        content = (
            content[:start]
            + new_block
            + content[end:]
        )

    else:

        content = (
            content.rstrip()
            + "\n\n"
            + new_block
            + "\n"
        )

    README.write_text(
        content,
        encoding="utf-8",
        newline="\n"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    failures = []

    log(
        "========================================"
    )

    log(
        "a_srs SRS Builder"
    )

    log(
        "Target Source Format: version 4"
    )

    log(
        "========================================"
    )

    # ========================================================
    # 第一阶段
    #
    # 所有无后缀 URL 文件
    # → 下载
    # → 合并
    # → 去重
    # → JSON
    # ========================================================

    url_files = find_url_files()

    log("")

    log(
        "========================================"
    )

    log(
        "第一阶段：拉取远程 JSON"
    )

    log(
        f"URL 文件数量: {len(url_files)}"
    )

    log(
        "========================================"
    )

    for path in url_files:

        try:

            process_url_file(
                path,
                failures
            )

        except Exception as e:

            failures.append({
                "file": relative(path),
                "stage": "URL 文件处理",
                "detail": str(e)
            })

            log(
                f"      ❌ 文件处理失败: {e}"
            )

            # 继续下一个文件
            continue

    # ========================================================
    # 第二阶段
    #
    # 所有 JSON
    # → SRS
    # ========================================================

    build_all_srs(
        failures
    )

    # ========================================================
    # README
    #
    # 覆盖上一次工作流状态
    # ========================================================

    update_readme(
        failures
    )

    # ========================================================
    # 完成
    # ========================================================

    log("")

    log(
        "========================================"
    )

    log(
        "工作流处理完成"
    )

    log(
        f"失败数量: {len(failures)}"
    )

    log(
        "========================================"
    )

    # --------------------------------------------------------
    # 即使有部分失败，也返回 0。
    #
    # 目的：
    #
    # A 文件失败
    # ↓
    # B/C/D 继续生成
    #
    # --------------------------------------------------------

    sys.exit(0)


if __name__ == "__main__":

    main()
