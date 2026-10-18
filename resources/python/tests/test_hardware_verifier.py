from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from adverserial._jws import b64url_encode
from adverserial.hardware_verifier import EvidenceError, _command, protocol_bindings, verify


def fingerprint(raw: bytes) -> str:
    return "sha256:" + b64url_encode(hashlib.sha256(raw).digest())


def evidence_request():
    tls = generate_private_key(SECP256R1()).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    receipt = generate_private_key(SECP256R1()).public_key().public_numbers()
    receipt_jwk = {"kty": "EC", "crv": "P-256", "x": b64url_encode(receipt.x.to_bytes(32, "big")), "y": b64url_encode(receipt.y.to_bytes(32, "big"))}
    nonce = b64url_encode(b"n" * 32)
    return {"nonce": nonce, "model": "lordx64/cyberglm", "endpoint": "https://api.adverserial.ai", "evidence": {
        "nonce": nonce, "tdx_quote": "abcd", "tdx_event_log": {"rtmr": ["aa"]}, "gpu_evidence": {"eats": ["bb"]},
        "tls_spki_der": b64url_encode(tls), "tls_spki_sha256": fingerprint(tls), "receipt_pubkey_jwk": receipt_jwk,
        "workload": {"model_id": "lordx64/cyberglm"},
    }}


class HardwareVerifierTests(unittest.TestCase):
    def test_vendor_adapter_command_must_be_a_resolved_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = root / "adapter.py"
            adapter.write_text("#!/bin/sh\nexit 0\n")
            adapter.chmod(adapter.stat().st_mode | stat.S_IXUSR)
            with patch.dict(os.environ, {"ADVERSERIAL_TDX_VERIFIER_COMMAND": str(adapter)}, clear=False):
                self.assertEqual(_command("ADVERSERIAL_TDX_VERIFIER_COMMAND"), str(adapter.resolve()))
            with patch.dict(os.environ, {"ADVERSERIAL_TDX_VERIFIER_COMMAND": "adapter.py"}, clear=False):
                with self.assertRaisesRegex(EvidenceError, "absolute"):
                    _command("ADVERSERIAL_TDX_VERIFIER_COMMAND")
            with patch.dict(os.environ, {"ADVERSERIAL_TDX_VERIFIER_COMMAND": directory}, clear=False):
                with self.assertRaisesRegex(EvidenceError, "executable file"):
                    _command("ADVERSERIAL_TDX_VERIFIER_COMMAND")

    def test_protocol_bindings_rejects_dev_and_tampered_tls(self):
        request = evidence_request()
        request["evidence"]["dev"] = True
        with self.assertRaises(EvidenceError):
            protocol_bindings(request)
        request["evidence"].pop("dev")
        request["evidence"]["tls_spki_sha256"] = "sha256:" + "A" * 43
        with self.assertRaises(EvidenceError):
            protocol_bindings(request)

    def test_vendor_adapters_must_echo_exact_bindings(self):
        request = evidence_request()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tdx = root / "tdx.py"
            gpu = root / "gpu.py"
            tdx.write_text("#!/usr/bin/env python3\nimport json,sys\np=json.load(sys.stdin); e=p['expected']; print(json.dumps({'verified':True,'verifier':'dcap-test@1','tee':'intel-tdx','report_data_hex':e['report_data_hex'],'tdx_event_log_sha256':e['tdx_event_log_sha256']}))\n")
            gpu.write_text("#!/usr/bin/env python3\nimport json,sys\np=json.load(sys.stdin); e=p['expected']; print(json.dumps({'verified':True,'verifier':'nvidia-test@1','gpu':'nvidia-h200','gpu_evidence_sha256':e['gpu_evidence_sha256']}))\n")
            tdx.chmod(tdx.stat().st_mode | stat.S_IXUSR)
            gpu.chmod(gpu.stat().st_mode | stat.S_IXUSR)
            with patch.dict(os.environ, {"ADVERSERIAL_TDX_VERIFIER_COMMAND": str(tdx), "ADVERSERIAL_GPU_VERIFIER_COMMAND": str(gpu)}, clear=False):
                result = verify(request)
        self.assertTrue(result["verified"])
        self.assertIn("dcap-test@1", result["verifier"])

    def test_adapter_cannot_skip_report_data(self):
        request = evidence_request()
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / "adapter.py"
            adapter.write_text("#!/usr/bin/env python3\nimport json,sys\njson.load(sys.stdin); print(json.dumps({'verified':True,'verifier':'bad','tee':'tdx','report_data_hex':'00','tdx_event_log_sha256':'sha256:bad'}))\n")
            adapter.chmod(adapter.stat().st_mode | stat.S_IXUSR)
            with patch.dict(os.environ, {"ADVERSERIAL_TDX_VERIFIER_COMMAND": str(adapter), "ADVERSERIAL_GPU_VERIFIER_COMMAND": str(adapter)}, clear=False):
                with self.assertRaises(EvidenceError):
                    verify(request)


if __name__ == "__main__":
    unittest.main()
