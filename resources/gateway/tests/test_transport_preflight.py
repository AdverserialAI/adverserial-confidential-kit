import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from adverserial_gateway.core import VerificationFailed


spec = importlib.util.spec_from_file_location(
    "verify_transport", Path(__file__).resolve().parents[2] / "verify-transport.py"
)
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class TransportPreflightTests(unittest.TestCase):
    def test_uses_selected_model_and_gateway_configuration(self):
        with patch.dict(os.environ, {"ADVERSERIAL_MODEL": "adverserial/cyberseek"}), patch.object(
            transport.Config, "from_env", return_value="test-config"
        ), patch.object(transport, "Dispatcher") as dispatcher:
            self.assertEqual(transport.main(), 0)
            dispatcher.assert_called_once_with("test-config")
            dispatcher.return_value.proof_for.assert_called_once_with("adverserial/cyberseek")

    def test_failure_cannot_print_verified(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"ADVERSERIAL_MODEL": "adverserial/cyberseek"}), patch.object(
            transport.Config, "from_env"
        ), patch.object(transport, "Dispatcher") as dispatcher, contextlib.redirect_stderr(output):
            dispatcher.return_value.proof_for.side_effect = VerificationFailed("TLS certificate pin mismatch")
            self.assertEqual(transport.main(), 1)
        self.assertIn("ADVERSERIAL ATTESTATION: FAILED", output.getvalue())
        self.assertIn("TLS certificate pin mismatch", output.getvalue())
        self.assertNotIn("VERIFIED", output.getvalue())

    def test_json_failure_remains_machine_readable(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"ADVERSERIAL_MODEL": "adverserial/cyberseek"}), patch.object(
            transport.Config, "from_env"
        ), patch.object(transport, "Dispatcher") as dispatcher, contextlib.redirect_stdout(output):
            dispatcher.return_value.proof_for.side_effect = VerificationFailed("TLS certificate pin mismatch")
            self.assertEqual(transport.main(["--json"]), 1)
        verdict = json.loads(output.getvalue())
        self.assertEqual(verdict["status"], "failed")
        self.assertEqual(verdict["reason"], "TLS certificate pin mismatch")
        self.assertEqual(verdict["config"]["modelId"], "adverserial/cyberseek")
        self.assertEqual(verdict["trust"], "pinned")
