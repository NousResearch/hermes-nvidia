"""The installer's Authenticode check (launcher/authenticode.py): how a WinVerifyTrust result is read on any
system, and the real call on Windows against files this test makes or finds (a signed Windows program, a copy of
it with one byte changed, a file that is no program, a missing file)."""
import ctypes
import os
import sys
from pathlib import Path

import pytest

from openshell.launcher import authenticode as A

windows_only = pytest.mark.skipif(os.name != "nt", reason="asks Windows (WinVerifyTrust)")


@pytest.mark.parametrize("code, want", [
    (0, "valid"),
    (0x800B0100, "unsigned"),  # TRUST_E_NOSIGNATURE
    (0x800B0003, "unsigned"),  # TRUST_E_SUBJECT_FORM_UNKNOWN: not a file that carries a signature
    (-2146762496, "unsigned"),  # 0x800B0100 as the signed LONG the API returns
    (0x80096010, "invalid"),  # TRUST_E_BAD_DIGEST: the file changed after it was signed
    (0x80096004, "invalid"),  # TRUST_E_CERT_SIGNATURE
    (0x8009200D, "invalid"),  # CRYPT_E_BAD_MSG: a damaged signature
    (0xC000A000, "invalid"),  # STATUS_INVALID_SIGNATURE: a damaged signature
    (0x800B0109, "invalid"),  # CERT_E_UNTRUSTEDROOT: a certificate this PC does not trust (a self-made one)
    (0x800B010A, "invalid"),  # CERT_E_CHAINING
    (0x800B0101, "invalid"),  # CERT_E_EXPIRED
    (0x800B010C, "invalid"),  # CERT_E_REVOKED
    (0x800B0111, "invalid"),  # TRUST_E_EXPLICIT_DISTRUST
    (0x800B0004, "invalid"),  # TRUST_E_SUBJECT_NOT_TRUSTED
    (0x80092026, "invalid"),  # CRYPT_E_SECURITY_SETTINGS
    (0x80004005, "invalid"),  # an error nobody listed: not accepted is not valid
    (0x800B0001, None),  # TRUST_E_PROVIDER_UNKNOWN
    (0x800B0002, None),  # TRUST_E_ACTION_UNKNOWN
    (0x80096001, None),  # TRUST_E_SYSTEM_ERROR
    (0x80092003, None),  # CRYPT_E_FILE_ERROR: the file could not be read
    (0x80070002, None),  # file not found
    (0x80070005, None),  # access denied
    (0x80070020, None),  # sharing violation
    (0x8007000E, None),  # out of memory
    (2, None), (5, None), (1450, None),  # plain Win32 error numbers
])
def test_a_winverifytrust_result_is_a_verdict_or_a_check_that_did_not_run(code, want):
    assert A.classify(code) == want


def test_only_zero_is_valid():
    assert [c for c in (*range(-4, 5), 0x800B0100, 0x80096010, 0xFFFFFFFF) if A.classify(c) == A.VALID] == [0]
    assert (A.VALID, A.UNSIGNED, A.INVALID) == ("valid", "unsigned", "invalid")


@pytest.mark.skipif(os.name == "nt", reason="the check runs on Windows")
def test_off_windows_the_check_is_unavailable(tmp_path):
    (tmp_path / "a.exe").write_bytes(b"MZ")
    with pytest.raises(A.Unavailable, match="Windows only"):
        A.signature(tmp_path / "a.exe")


MICROSOFT = ("Microsoft Windows", "Microsoft Corporation")


def _signed_windows_program():
    """(path, the names its signer may have) of a program on this PC that Windows accepts as signed in the file
    itself (not through a catalog), or None."""
    system = Path(os.environ.get("SystemRoot") or "C:/Windows")
    base = Path(getattr(sys, "base_prefix", sys.prefix))
    for path, signers in ((system / "explorer.exe", MICROSOFT), (system / "System32" / "ntdll.dll", MICROSOFT),
                          (system / "System32" / "kernel32.dll", MICROSOFT),
                          (base / "python.exe", ("Python Software Foundation",))):
        try:
            if path.is_file() and A.signature(path)["status"] == A.VALID:
                return path, signers
        except A.Unavailable:
            continue
    return None


@windows_only
def test_a_file_that_is_no_program_is_unsigned(tmp_path):
    for name, data in (("notes.exe", b"not a program\r\n" * 50), ("empty.dll", b""), ("stub.exe", b"MZ" + b"\0" * 200)):
        (tmp_path / name).write_bytes(data)
        got = A.signature(tmp_path / name)
        assert got["status"] == A.UNSIGNED and got["signer"] is None and got["code"] in (0x800B0100, 0x800B0003)
        assert f"0x{got['code']:08X}" in got["detail"]


@windows_only
def test_a_missing_file_is_a_check_that_could_not_run(tmp_path):
    with pytest.raises(A.Unavailable, match="WinVerifyTrust failed: .*0x"):
        A.signature(tmp_path / "missing.exe")


@windows_only
def test_a_signed_program_is_valid_and_names_its_signer_and_a_changed_copy_is_not(tmp_path):
    found = _signed_windows_program()
    if found is None:
        pytest.skip("no program with an embedded signature found on this PC")
    program, signers = found
    got = A.signature(program)
    assert got == {"status": A.VALID, "signer": got["signer"], "code": 0, "detail": "valid"}
    assert got["signer"] in signers  # the signing certificate's own name, not its issuer's
    data = bytearray(program.read_bytes())
    same = tmp_path / ("copy" + program.suffix)
    same.write_bytes(bytes(data))
    assert A.signature(same) == got  # the signature travels with the bytes, whatever the file is called
    data[len(data) // 3] ^= 0x01  # one bit, inside the signed part of the image
    changed = tmp_path / ("changed" + program.suffix)
    changed.write_bytes(bytes(data))
    bad = A.signature(changed)
    assert bad["status"] == A.INVALID and bad["signer"] is None and bad["code"] != 0
    assert A.signature(str(same))["status"] == A.VALID  # a str path works too, and one call leaves no state behind


@windows_only
def test_a_failure_to_reach_the_api_is_unavailable_not_a_verdict(tmp_path, monkeypatch):
    (tmp_path / "a.exe").write_bytes(b"MZ")

    def no_dll(name, **kw):
        raise OSError(f"cannot load {name}")

    monkeypatch.setattr(ctypes, "WinDLL", no_dll)
    with pytest.raises(A.Unavailable, match="WinVerifyTrust could not be called .*cannot load wintrust"):
        A.signature(tmp_path / "a.exe")
