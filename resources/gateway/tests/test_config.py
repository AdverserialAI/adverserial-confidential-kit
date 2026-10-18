import json
import sys
import tempfile
import unittest
from pathlib import Path

from adverserial_gateway.config import Config, ConfigError


class ConfigTests(unittest.TestCase):
    def test_loopback_and_required_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"kid": {"kty": "EC"}}))
            env = {"ADVERSERIAL_RECEIPT_KEYS_FILE": str(keys), "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": sys.executable}
            cfg = Config.from_env(env)
            self.assertEqual(cfg.listen_host, "127.0.0.1")
            self.assertEqual(cfg.max_output_tokens, 65536)
            with self.assertRaises(ConfigError):
                Config.from_env({**env, "ADVERSERIAL_GATEWAY_HOST": "0.0.0.0"})
            with self.assertRaises(ConfigError):
                Config.from_env({k: v for k, v in env.items() if k != "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND"})
            with self.assertRaisesRegex(ConfigError, "absolute executable path"):
                Config.from_env({**env, "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": "adverserial-hardware-verify"})
            with self.assertRaisesRegex(ConfigError, "executable file"):
                Config.from_env({**env, "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": tmp})

    def test_endpoint_configuration_refuses_credential_and_path_confusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"kid": {"kty": "EC"}}))
            env = {"ADVERSERIAL_RECEIPT_KEYS_FILE": str(keys), "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": sys.executable}
            for name, value in (
                ("ADVERSERIAL_CC_API_URL", "https://user:pass@api.example/v1"),
                ("ADVERSERIAL_CC_API_URL", "https://api.example/v1?redirect=https://evil.example"),
                ("ADVERSERIAL_BILLING_URL", "https://billing.example/not-the-billing-origin"),
            ):
                with self.subTest(name=name, value=value), self.assertRaises(ConfigError):
                    Config.from_env({**env, name: value})


if __name__ == "__main__":
    unittest.main()
