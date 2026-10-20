"""Deterministic local load tests: no keys, billing, or remote inference."""
import http.client
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from adverserial_gateway.server import BoundedThreadingHTTPServer, Handler


class FixtureDispatcher:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.closed = 0
        self.gate = None

    def completion(self, _key, payload):
        with self.lock:
            self.calls += 1
        if self.gate is not None and not self.gate.wait(10):
            raise RuntimeError("test gate timed out")
        if payload.get("stream"):
            owner = self
            class Stream:
                receipt_verified = True
                def __iter__(self):
                    yield {"choices": [{"delta": {"content": "fixture reply"}, "finish_reason": "stop"}]}
                def close(self):
                    with owner.lock:
                        owner.closed += 1
            return Stream()
        return {"choices": [{"message": {"content": "fixture reply"}, "finish_reason": "stop"}]}

    def adapted_completion(self, key, model, payload):
        return self.completion(key, {**payload, "model": model})


class GatewayStressTests(unittest.TestCase):
    def setUp(self):
        self.dispatcher = FixtureDispatcher()
        class TestHandler(Handler):
            dispatcher = self.dispatcher
        self.server = BoundedThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        self.server.logger = lambda *_: None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, path, body):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            connection.request("POST", path, body, {"Content-Type": "application/json", "Connection": "close"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_mixed_360_request_burst_recovers_from_bad_payloads(self):
        paths = ("/v1/chat/completions", "/v1/messages", "/v1/responses")
        valid = {"model": "cyberglm", "messages": [{"role": "user", "content": "hello"}], "input": "hello", "max_tokens": 8}
        invalid = [b"{", b"[]", b"null", b'{"stream":"false"}', b'{"temperature":NaN}', b'{"temperature":Infinity}']
        def run(index):
            if index % 3 == 0:
                status, _ = self.request(paths[(index // 3) % 3], invalid[(index // 9) % len(invalid)])
                self.assertEqual(status, 400)
            else:
                payload = {**valid, "stream": index % 2 == 0}
                status, body = self.request(paths[(index // 3) % 3], json.dumps(payload))
                self.assertEqual(status, 200)
                self.assertIn(b"fixture reply", body)
                self.assertNotIn(b"event: error", body)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, range(360)))
        self.assertEqual(self.dispatcher.calls, 240)
        self.assertEqual(self.dispatcher.closed, 120)
        self.assertEqual(self.request(paths[0], json.dumps(valid))[0], 200)

    def test_saturation_rejects_then_releases_all_slots(self):
        # Occupy all 16 slots with deterministic fixture work, then release it.
        self.dispatcher.gate = threading.Event()
        payload = json.dumps({"model": "cyberglm", "messages": []})
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(self.request, "/v1/chat/completions", payload) for _ in range(16)]
                # Observe actual admission rather than relying on sleeps.
                for _ in range(1000):
                    with self.dispatcher.lock:
                        if self.dispatcher.calls == 16:
                            break
                    threading.Event().wait(0.005)
                self.assertEqual(self.dispatcher.calls, 16)
                try:
                    status, _ = self.request("/v1/chat/completions", payload)
                    self.assertEqual(status, 503)
                except (ConnectionResetError, ConnectionAbortedError, http.client.RemoteDisconnected):
                    pass  # A full server may close before sending its 503.
                finally:
                    self.dispatcher.gate.set()
                self.assertTrue(all(f.result()[0] == 200 for f in futures))
            self.assertEqual(self.request("/v1/chat/completions", payload)[0], 200)
        finally:
            self.dispatcher.gate.set()
