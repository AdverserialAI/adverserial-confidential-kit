import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from adverserial_gateway.hardware import verifier_from_command


class HardwareCommandTests(unittest.TestCase):
    def test_javascript_adapter_uses_pinned_node_without_a_shell(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for the bundled hardware verifier')
        with tempfile.TemporaryDirectory(prefix='ack verifier & spaces ') as home:
            script = Path(home) / 'adapter.mjs'
            script.write_text("let data=''; for await (const part of process.stdin) data+=part; "
                              "const request=JSON.parse(data); console.log(JSON.stringify({"
                              "verified:request.nonce==='test-nonce',verifier:'test-only@1'}));")
            with patch.dict(os.environ, {'ADVERSERIAL_NODE_EXECUTABLE': node}):
                result = verifier_from_command(str(script))({}, 'test-nonce', 'test-model', None)
                self.assertTrue(result.verified)
            with patch.dict(os.environ, {'ADVERSERIAL_NODE_EXECUTABLE': 'node'}):
                with self.assertRaisesRegex(RuntimeError, 'absolute Node executable'):
                    verifier_from_command(str(script))({}, 'test-nonce', 'test-model', None)
