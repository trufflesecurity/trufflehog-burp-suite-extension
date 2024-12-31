# -*- coding: utf-8 -*-
import pytest
import os
import subprocess
import tempfile
from unittest.mock import patch
from scanner import (
    redact_secret,
    build_raw_secret,
    parse_args,
    get_all_files,
    parse_req_id_from_filename,
    get_req_files,
    filter_req_files,
    create_subdir,
    move_req_files,
    reverse_move_req_files,
    scan_req_files,
    get_req_id_from_metadata,
    build_result_obj,
    parse_results,
)


@pytest.fixture
def temp_dir():
    # Create a temporary directory for file operations
    d = tempfile.mkdtemp()
    yield d
    # Cleanup after test
    try:
        os.rmdir(d)
    except OSError:
        pass


def test_redact_secret_short_secret():
    # Short secret should become *****.
    secret = "abcd"
    redacted = redact_secret("", secret)
    assert redacted == "*****"  # Should be fully masked for short secrets.


def test_redact_secret_long_secret():
    # Long secret should be partially masked.
    secret = "abcdefghijklmnopqrstuvwxyz"
    redacted = redact_secret("", secret)
    # Check partial redaction
    assert redacted.startswith("abc")  
    assert redacted.endswith("uvwxyz")
    assert "*****" in redacted


def test_redact_secret_already_redacted():
    # If redacted is already set, it should just return the existing redacted value.
    result = redact_secret("some-redacted-value", "realsecret")
    assert result == "some-redacted-value"


def test_build_raw_secret_basic():
    # Should return 'raw' if raw_v2 is empty or whitespace.
    raw = "secret1"
    raw_v2 = ""
    result = build_raw_secret(raw, raw_v2)
    assert result == "secret1"


def test_build_raw_secret_appended():
    # Should append raw2 to raw if not present.
    raw = "secret1"
    raw_v2 = "secret2"
    result = build_raw_secret(raw, raw_v2)
    assert result == "secret1:secret2"


def test_build_raw_secret_duplicate():
    # Should return raw_v2 if raw is in raw_v2.
    raw = "secret1"
    raw_v2 = "secret1-and-more"
    result = build_raw_secret(raw, raw_v2)
    assert result == "secret1-and-more"


def test_parse_args_required_flags():
    # Check that parse_args requires certain flags.
    test_args = [
        "--tempdir", "/tmp",
        "--trufflehog-path", "/usr/local/bin/trufflehog"
    ]
    with patch("sys.argv", ["prog"] + test_args):
        args = parse_args()
        assert args.tempdir == "/tmp"
        assert args.trufflehog_path == "/usr/local/bin/trufflehog"


def test_get_all_files(temp_dir):
    # Check retrieving all files in a directory.
    open(os.path.join(temp_dir, "file1.txt"), "w").close()
    open(os.path.join(temp_dir, "file2.txt"), "w").close()
    files = get_all_files(temp_dir)
    assert len(files) == 2


def test_parse_req_id_from_filename():
    # Check extracting req_id from filename.
    filename = "123_headers.txt"
    req_id = parse_req_id_from_filename(filename)
    assert req_id == "123"


def test_parse_req_id_from_filename_none():
    # Check no extraction if pattern doesn't match.
    filename = "invalidname.txt"
    req_id = parse_req_id_from_filename(filename)
    assert req_id is None


def test_get_req_files():
    # Check grouping by req_id.
    files = ["/tmp/1_headers.txt", "/tmp/1_body.txt", "/tmp/2_headers.txt"]
    req_map = get_req_files(files)
    assert len(req_map) == 2
    assert "1" in req_map and "2" in req_map
    assert "/tmp/1_body.txt" in req_map["1"]


def test_filter_req_files():
    # Only keep req_ids with exactly two files.
    req_map = {
        "1": ["1_headers.txt", "1_body.txt"],
        "2": ["2_headers.txt"],
        "3": ["3_headers.txt", "3_body.txt", "extra.txt"]
    }
    final_req_files = filter_req_files(req_map)
    assert len(final_req_files) == 1
    assert "1" in final_req_files
    assert "3" not in final_req_files
    assert "2" not in final_req_files


def test_create_subdir(temp_dir):
    # Check creating subdirectory.
    subdir = create_subdir(temp_dir)
    assert os.path.exists(subdir)


def test_move_and_reverse_files(temp_dir):
    # Check moving and reversing files.
    f1 = os.path.join(temp_dir, "1_headers.txt")
    f2 = os.path.join(temp_dir, "1_body.txt")
    open(f1, "w").close()
    open(f2, "w").close()
    subdir = create_subdir(temp_dir)
    final_req_files = {"1": [f1, f2]}
    move_req_files(final_req_files, subdir)
    assert not os.path.exists(f1)
    assert os.path.exists(os.path.join(subdir, "1_headers.txt"))
    reverse_move_req_files(final_req_files, subdir)
    assert os.path.exists(f1)
    assert not os.path.exists(os.path.join(subdir, "1_headers.txt"))


@patch("subprocess.check_output")
def test_scan_req_files_success(mock_subproc):
    # Check scanning executes the correct command and returns output.
    mock_subproc.return_value = "test-output"
    fake_req_files = {"1": ["/tmp/1_headers.txt", "/tmp/1_body.txt"]}
    class FakeArgs:
        only_verified = False
        allow_verification_overlap = False
        trufflehog_path = "/usr/local/bin/trufflehog"
    output = scan_req_files(fake_req_files, FakeArgs(), "/tmp")
    assert output == "test-output"


@patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "cmd"))
def test_scan_req_files_failure(mock_subproc):
    # Check that None is returned on subprocess error and reverse move is called.
    fake_req_files = {"1": ["/tmp/1_headers.txt", "/tmp/1_body.txt"]}
    class FakeArgs:
        only_verified = False
        allow_verification_overlap = False
        trufflehog_path = "/usr/local/bin/trufflehog"
    with patch("shutil.move") as mock_move:
        output = scan_req_files(fake_req_files, FakeArgs(), "/tmp")
        assert output is None
        assert mock_move.called


def test_get_req_id_from_metadata():
    # Check extraction from metadata dict.
    metadata = {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "/tmp/123_body.txt"
                }
            }
        }
    }
    req_id = get_req_id_from_metadata(metadata)
    assert req_id == "123"


def test_build_result_obj():
    # Check result object from partial JSON response.
    partial_res = {
        "Redacted": "",
        "Raw": "abc",
        "DetectorName": "ExampleDetector",
        "DecoderName": "GenericDecoder",
        "Verified": True,
        "ExtraData": {"key": "value"},
        "DetectorDescription": "Detects example secrets"
    }
    result = build_result_obj(partial_res)
    assert result["secretType"] == "ExampleDetector"
    assert result["redacted"] != "abc"  # Should be partially redacted or similar.
    assert result["verified"] is True
    assert result["extraData"]["key"] == "value"


def test_parse_results_only_verified():
    # Check ignoring unverified results if --only-verified is set.
    output = """
    {"SourceMetadata": {"Data":{"Filesystem":{"file":"1_body.txt"}}}, "Verified": false, "Raw":"secret1", "Redacted": "****", "DetectorName":"Test1"}
    {"SourceMetadata": {"Data":{"Filesystem":{"file":"1_headers.txt"}}}, "Verified": true, "Raw":"secret2", "Redacted": "****", "DetectorName":"Test2"}
    """
    class FakeArgs:
        only_verified = True
    results = parse_results(output, FakeArgs())
    # Should only contain secret2 if only_verified is True.
    assert len(results) == 1


def test_parse_results_all():
    # Check including all results if only_verified is False.
    output = """
    {"SourceMetadata": {"Data":{"Filesystem":{"file":"1_body.txt"}}}, "Verified": false, "Raw":"secret1", "Redacted": "****", "DetectorName":"Test1"}
    {"SourceMetadata": {"Data":{"Filesystem":{"file":"2_headers.txt"}}}, "Verified": true, "Raw":"secret2", "Redacted": "****", "DetectorName":"Test2"}
    {"SourceMetadata": {"Data":{"Filesystem":{"file":"3_headers.txt"}}}, "Verified": true, "Raw":"secret3", "Redacted": "****", "DetectorName":"Test3"}
    """
    class FakeArgs:
        only_verified = False
    results = parse_results(output, FakeArgs())
    # Should have results for req_ids: "1" and "2".
    assert len(results) == 3
    assert "1" in results
    assert "2" in results
    assert "3" in results