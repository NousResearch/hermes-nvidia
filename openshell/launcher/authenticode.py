"""Authenticode check for the installer: is a file's embedded signature valid on this PC, and whose is it.

``signature(path)`` asks Windows itself, with ``WinVerifyTrust`` (wintrust.dll, the generic verify action: the
call behind a file's Digital Signatures tab) through ctypes. No program is started, so no console window can
open, and the plugin gains no dependency. No revocation lookup is made: the installer has already matched the
file against its pinned sha256, and the answer must be the same without a network.

The answer's ``status`` is one of

* ``valid``: the signature covers the file's bytes and chains to a root this PC trusts. ``signer`` is the common
  name of the signing certificate.
* ``unsigned``: the file carries no signature.
* ``invalid``: Windows did not accept the signature (the file or the signature changed after signing, or the
  certificate is untrusted, expired, revoked or distrusted on this PC). ``detail`` is Windows' message and code.

``Unavailable`` is raised when the check could not be made at all: not Windows, the API missing, the file
unreadable, or a failure of the trust provider itself. The caller decides what that means.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

VALID, UNSIGNED, INVALID = "valid", "unsigned", "invalid"


class Unavailable(Exception):
    """The signature could not be checked (as opposed to: it was checked and is not valid)."""


# WINTRUST_ACTION_GENERIC_VERIFY_V2
_ACTION = (0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY, _WTD_STATEACTION_CLOSE = 1, 2
_WTD_REVOCATION_CHECK_NONE = 0x10
_CERT_NAME_ATTR_TYPE = 3
_OID_COMMON_NAME = b"2.5.4.3"

_NO_SIGNATURE = (0x800B0100,  # TRUST_E_NOSIGNATURE
                 0x800B0003)  # TRUST_E_SUBJECT_FORM_UNKNOWN: not a kind of file that carries a signature
# Failures of the check itself, not judgements of a signature: the trust provider or action is unknown, a system
# error in the provider, the file could not be read.
_DID_NOT_RUN = (0x800B0001, 0x800B0002, 0x80096001, 0x80092003)


def classify(code: int) -> str | None:
    """What a WinVerifyTrust result says about the file: ``valid`` (0), ``unsigned``, ``invalid``, or None when
    the check did not run (the codes above, and Windows' general errors such as a missing or locked file or no
    memory: 0x8007xxxx and plain Win32 error numbers). Every other failure is Windows not accepting the
    signature. A damaged signature comes back under several codes, not only the certificate and trust ones
    (0x8009200D, 0x80096004, 0x80096010, 0xC000A000 were all measured), so the rule names what is not a
    judgement instead of what is."""
    code &= 0xFFFFFFFF
    if code == 0:
        return VALID
    if code in _NO_SIGNATURE:
        return UNSIGNED
    if code in _DID_NOT_RUN or code < 0x10000 or (code >> 16) == 0x8007:
        return None
    return INVALID


def signature(path) -> dict:
    """``{"status": "valid" | "unsigned" | "invalid", "signer": <common name> | None, "code": <HRESULT>,
    "detail": <text>}`` for the file at *path*. Raises ``Unavailable`` when the check cannot be made."""
    if os.name != "nt":
        raise Unavailable("Authenticode signatures are checked on Windows only")
    try:
        return _verify(Path(path))
    except Unavailable:
        raise
    except (OSError, AttributeError, ValueError, TypeError, ctypes.ArgumentError) as exc:
        raise Unavailable(f"WinVerifyTrust could not be called ({type(exc).__name__}: {exc})") from exc


def _verify(path: Path) -> dict:
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    class FileInfo(ctypes.Structure):  # WINTRUST_FILE_INFO
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class Data(ctypes.Structure):  # WINTRUST_DATA
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(FileInfo)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    class ProviderCert(ctypes.Structure):  # CRYPT_PROVIDER_CERT: its first two members
        _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(Data)]
    verify.restype = wintypes.LONG
    prov_data = wintrust.WTHelperProvDataFromStateData
    prov_data.argtypes, prov_data.restype = [wintypes.HANDLE], ctypes.c_void_p
    prov_signer = wintrust.WTHelperGetProvSignerFromChain
    prov_signer.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    prov_signer.restype = ctypes.c_void_p
    prov_cert = wintrust.WTHelperGetProvCertFromChain
    prov_cert.argtypes, prov_cert.restype = [ctypes.c_void_p, wintypes.DWORD], ctypes.POINTER(ProviderCert)
    cert_name = crypt32.CertGetNameStringW
    cert_name.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR,
                          wintypes.DWORD]
    cert_name.restype = wintypes.DWORD

    action = GUID(_ACTION[0], _ACTION[1], _ACTION[2], (ctypes.c_ubyte * 8)(*_ACTION[3]))
    info = FileInfo(ctypes.sizeof(FileInfo), str(path), None, None)
    data = Data()
    data.cbStruct = ctypes.sizeof(Data)
    data.dwUIChoice = _WTD_UI_NONE  # never a dialog
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.dwProvFlags = _WTD_REVOCATION_CHECK_NONE
    no_window = wintypes.HANDLE(-1)  # INVALID_HANDLE_VALUE: no interactive user
    code = verify(no_window, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF
    try:
        if code == 0:
            return {"status": VALID, "signer": _signer(data.hWVTStateData, prov_data, prov_signer, prov_cert, cert_name),
                    "code": 0, "detail": "valid"}
    finally:
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        verify(no_window, ctypes.byref(action), ctypes.byref(data))
    text = ctypes.FormatError(ctypes.c_long(code).value).strip()
    detail = f"{text if text and not text.startswith('<') else 'the signature did not verify'} (0x{code:08X})"
    status = classify(code)
    if status is None:
        raise Unavailable(f"WinVerifyTrust failed: {detail}")
    return {"status": status, "signer": None, "code": code, "detail": detail}


def _signer(state, prov_data, prov_signer, prov_cert, cert_name) -> str:
    """The common name of the certificate that signed the file (the first signer's own certificate)."""
    provider = prov_data(state)
    signer = prov_signer(provider, 0, False, 0) if provider else None
    cert = prov_cert(signer, 0) if signer else None
    context = cert.contents.pCert if cert else None
    if not context:
        raise Unavailable("Windows accepted the signature but returned no signing certificate")
    oid = ctypes.c_char_p(_OID_COMMON_NAME)
    size = cert_name(context, _CERT_NAME_ATTR_TYPE, 0, oid, None, 0)
    buf = ctypes.create_unicode_buffer(max(size, 1))
    cert_name(context, _CERT_NAME_ATTR_TYPE, 0, oid, buf, size)
    return buf.value
