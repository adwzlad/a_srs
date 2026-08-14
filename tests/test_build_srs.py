#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github/scripts"))

from build_srs import (
    dedupe_domain,
    dedupe_keyword,
    dedupe_suffix,
    dedupe_ip_cidr,
    merge_all_remote_json,
)


def test_domain_exact_only():
    assert dedupe_domain(["example.com", "example.com", "www.example.com"]) == [
        "example.com", "www.example.com"
    ]


def test_keyword_parent_contains_child():
    assert dedupe_keyword(["google", "googlevideo", "ogle"]) == ["ogle"]


def test_suffix_parent_covers_child():
    assert dedupe_suffix(["example.com", "www.example.com", "com"]) == ["com"]


def test_ip_cidr_parent_contains_child():
    assert dedupe_ip_cidr([
        "1.1.1.0/24", "1.1.1.0/25", "1.1.1.128/25", "8.8.8.0/24"
    ]) == ["1.1.1.0/24", "8.8.8.0/24"]


def test_all_remote_sources_merge_before_dedupe():
    result = merge_all_remote_json([
        ("url-1", {"version": 4, "rules": [
            {"domain": ["a.example", "a.example"], "domain_suffix": ["example.com"]}
        ]}),
        ("url-2", {"version": 4, "rules": [
            {"domain": ["a.example", "b.example"],
             "domain_suffix": ["example.com", "test.com"]}
        ]}),
    ])
    assert result == {
        "version": 4,
        "rules": [{
            "domain": ["a.example", "b.example"],
            "domain_suffix": ["example.com", "test.com"],
        }],
    }


def test_parent_empty_skips_only_current_comparison():
    result = merge_all_remote_json([
        ("url-1", {"version": 4, "rules": [{
            "domain_regex": [],
            "domain_keyword": [],
            "domain_suffix": ["example.com"],
            "domain": ["www.example.com", "other.test"],
        }]}),
        ("url-2", {"version": 4, "rules": [{
            "domain_suffix": ["example.com"],
            "domain": ["www.example.com", "other.test"],
        }]}),
    ])
    assert result == {
        "version": 4,
        "rules": [{
            "domain_suffix": ["example.com"],
            "domain": ["other.test"],
        }],
    }


def test_regex_to_all_children():
    result = merge_all_remote_json([
        ("url-1", {"version": 4, "rules": [{
            "domain_regex": [r"^(.+\.)?example\.com$"],
            "domain_keyword": ["example.com", "google"],
            "domain_suffix": ["example.com", "google.com"],
            "domain": ["www.example.com", "www.google.com"],
        }]}),
    ])
    rule = result["rules"][0]
    assert rule["domain_regex"] == [r"^(.+\.)?example\.com$"]
    assert rule["domain_keyword"] == ["google"]
    assert "domain_suffix" not in rule
    assert "domain" not in rule


def test_empty_arrays_and_empty_rule_are_removed():
    result = merge_all_remote_json([
        ("url-1", {"version": 4, "rules": [{
            "domain": [], "domain_suffix": [], "domain_keyword": [],
            "domain_regex": [], "ip_cidr": [],
        }]}),
    ])
    assert result == {"version": 4, "rules": []}


def test_multiple_remote_rules_are_flattened():
    result = merge_all_remote_json([
        ("url-1", {"version": 4, "rules": [
            {"domain": ["a.com"]},
            {"domain_suffix": ["b.com"]},
        ]}),
        ("url-2", {"version": 4, "rules": [
            {"domain_keyword": ["xyz"]},
            {"ip_cidr": ["1.1.1.0/24"]},
        ]}),
    ])
    assert result == {
        "version": 4,
        "rules": [{
            "domain": ["a.com"],
            "domain_suffix": ["b.com"],
            "domain_keyword": ["xyz"],
            "ip_cidr": ["1.1.1.0/24"],
        }],
    }


if __name__ == "__main__":
    tests = [
        test_domain_exact_only,
        test_keyword_parent_contains_child,
        test_suffix_parent_covers_child,
        test_ip_cidr_parent_contains_child,
        test_all_remote_sources_merge_before_dedupe,
        test_parent_empty_skips_only_current_comparison,
        test_regex_to_all_children,
        test_empty_arrays_and_empty_rule_are_removed,
        test_multiple_remote_rules_are_flattened,
    ]
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print(f"\n全部 {len(tests)} 项测试通过")
