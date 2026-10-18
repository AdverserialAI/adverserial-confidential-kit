import socket
import threading
import time
import unittest

from adverserial_gateway.server import BoundedThreadingHTTPServer, Handler


class AdmissionHandler(Handler):
    entered_body_read = threading.Event()

    def _read_body(self, size):
        type(self).entered_body_read.set()
        return super()._read_body(size)


class GatewayAdmissionTests(unittest.TestCase):
    def setUp(self):
        AdmissionHandler.entered_body_read = threading.Event()
        self.server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            AdmissionHandler,
            max_connections=1,
            connection_timeout=1.0,
            body_deadline=0.2,
        )
        self.server.logger = lambda *_args: None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def _connect(self):
        connection = socket.create_connection(self.server.server_address, timeout=1)
        connection.settimeout(2)
        return connection

    @staticmethod
    def _read_response(connection):
        chunks = []
        while True:
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                break
            except ConnectionResetError:
                if chunks:
                    break  # macOS may reset after the terminal rejection response.
                raise
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def test_slow_body_cannot_consume_unbounded_handler_threads(self):
        slow = self._connect()
        self.addCleanup(slow.close)
        slow.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n\r\n"
            b"{"
        )
        self.assertTrue(AdmissionHandler.entered_body_read.wait(timeout=1), "slow request did not enter body read")

        second = self._connect()
        self.addCleanup(second.close)
        second.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = self._read_response(second)
        self.assertTrue(response.startswith(b"HTTP/1.1 503"), response)
        self.assertIn(b"Connection: close", response)

    def test_partial_body_has_a_total_deadline_and_closes_connection(self):
        slow = self._connect()
        self.addCleanup(slow.close)
        slow.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n\r\n"
            b"{"
        )
        started = time.monotonic()
        response = self._read_response(slow)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(response.startswith(b"HTTP/1.1 408"), response)
        self.assertIn(b"Connection: close", response)

    def test_rejected_chunked_body_closes_before_pipelined_bytes_are_reused(self):
        connection = self._connect()
        self.addCleanup(connection.close)
        connection.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        response = self._read_response(connection)
        self.assertTrue(response.startswith(b"HTTP/1.1 400"), response)
        self.assertIn(b"Connection: close", response)
        self.assertNotIn(b'"status":"ok"', response)


if __name__ == "__main__":
    unittest.main()
