"""Fail before a VERIFIED verdict if the gateway cannot authenticate TLS."""
import os
import sys
import json

from adverserial_gateway.config import Config, ConfigError
from adverserial_gateway.core import Dispatcher, GatewayError


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        Dispatcher(Config.from_env()).proof_for(os.environ["ADVERSERIAL_MODEL"])
    except (ConfigError, GatewayError, OSError) as exc:
        if "--json" in argv:
            print(json.dumps({
                "status": "failed", "reason": str(exc), "trust": "pinned",
                "config": {
                    "baseURL": os.environ.get("ADVERSERIAL_API_URL", ""),
                    "modelId": os.environ.get("ADVERSERIAL_MODEL", ""),
                    "hardwareVerifierConfigured": bool(os.environ.get("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND")),
                },
            }))
        else:
            print(f"ADVERSERIAL ATTESTATION: FAILED\n  transport  {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
