import csv
import os
import tempfile
from pathlib import Path

import pytest

from evaluation.prepare_dataset import build_dataset, parse_cic_trap4phish_file, normalize_url_for_eval


def write_csv(content: str) -> Path:
    fd, path = tempfile.mkstemp(suffix='.csv')
    os.close(fd)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    return Path(path)


def test_parse_basic():
    csv_content = "url,label\nhttp://example.com,1\nhttps://good.com,0\n"
    path = write_csv(csv_content)
    rows = list(parse_cic_trap4phish_file(path))
    assert len(rows) == 2
    assert rows[0]["label"] == "phishing"
    assert rows[1]["label"] == "legitimate"


def test_invalid_label_and_url():
    csv_content = "url,label\nnot-a-url,1\nhttp://valid.com,2\nhttp://valid2.com,0\n"
    path = write_csv(csv_content)
    rows = list(parse_cic_trap4phish_file(path))
    # only the valid benign entry should pass (label 0, valid URL)
    assert len(rows) == 1
    assert rows[0]["url"] == "http://valid2.com"
    assert rows[0]["label"] == "legitimate"


def test_limit_enforcement():
    csv_content = "url,label\n" + "http://a.com,1\n" * 5
    path = write_csv(csv_content)
    rows = list(parse_cic_trap4phish_file(path, limit=3))
    assert len(rows) == 3


def test_build_dataset_includes_cic():
    csv_content = "url,label\nhttp://phish.com,1\nhttps://good.org,0\n"
    cic_path = write_csv(csv_content)
    samples, stats = build_dataset(cic_trap4phish_file=cic_path)
    labels = {s["label"] for s in samples}
    assert labels == {"phishing", "legitimate"}
    assert stats["source_counts"].get("cic_trap4phish") == 2


def test_build_dataset_limit_and_conflict():
    csv_content = "url,label\nhttp://dup.com,1\nhttp://dup.com,0\n"
    cic_path = write_csv(csv_content)
    samples, stats = build_dataset(cic_trap4phish_file=cic_path)
    assert len(samples) == 1
    assert samples[0]["label"] == "phishing"

def test_limit_zero_raises():
    csv_content = "url,label\nhttp://example.com,1\n"
    path = write_csv(csv_content)
    with pytest.raises(ValueError):
        list(parse_cic_trap4phish_file(path, limit=0))

def test_limit_negative_raises():
    csv_content = "url,label\nhttp://example.com,1\n"
    path = write_csv(csv_content)
    with pytest.raises(ValueError):
        list(parse_cic_trap4phish_file(path, limit=-5))

def test_url_validation_cases():
    csv_content = "url,label\n" \
        "https://example.com,1\n" \
        "example.com,1\n" \
        "not a url,1\n" \
        "https://.,1\n" \
        "https://a..b,1\n" \
        "ftp://example.com,1\n" \
        ",1\n" \
        "   ,1\n"
    path = write_csv(csv_content)
    rows = list(parse_cic_trap4phish_file(path))
    # Expected: https://example.com (already has scheme) and example.com (gets default https) are accepted.
    # Others should be filtered out.
    urls = {r["url"] for r in rows}
    assert "https://example.com" in urls
    assert "example.com" in urls
    assert len(urls) == 2

def test_limit_one_enforces_single_record():
    csv_content = "url,label\nhttp://first.com,1\nhttp://second.com,0\n"
    path = write_csv(csv_content)
    rows = list(parse_cic_trap4phish_file(path, limit=1))
    assert len(rows) == 1
    assert rows[0]["url"] == "http://first.com"
    assert rows[0]["label"] == "phishing"
