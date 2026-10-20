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
            except (ConnectionResetError, ConnectionAbortedError):
                if chunks:
                    break  # macOS/Windows may reset after the terminal rejection response.
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
        try:
            response = self._read_response(second)
        except (ConnectionResetError, ConnectionAbortedError):
            # Admission can reject immediately after accept, before sendall
            # arrives. Windows may reset that socket before delivering the 503.
            # The overload contract permits a close; no second handler is run.
            self.assertFalse(self.server._connection_slots.acquire(blocking=False))
            return
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

    def test_trickling_body_cannot_reset_the_total_deadline(self):
        connection = self._connect()
        self.addCleanup(connection.close)
        connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n")
        stopped = threading.Event()
        def trickle():
            for _ in range(20):
                if stopped.wait(0.04):
                    return
                try:
                    connection.sendall(b" ")
                except OSError:
                    return
        writer = threading.Thread(target=trickle, daemon=True)
        writer.start()
        started = time.monotonic()
        try:
            response = self._read_response(connection)
            self.assertLess(time.monotonic() - started, 0.65)
            self.assertTrue(response.startswith(b"HTTP/1.1 408"), response)
        finally:
            stopped.set()
            writer.join(timeout=1)

    def test_trickling_headers_cannot_hold_the_only_connection_slot(self):
        self.server.connection_timeout = 0.2
        connection = self._connect()
        self.addCleanup(connection.close)
        connection.sendall(b"GET /healthz HTTP/1.1\r\nX-Slow: ")
        stopped = threading.Event()
        def trickle():
            for _ in range(20):
                if stopped.wait(0.04):
                    return
                try:
                    connection.sendall(b"x")
                except OSError:
                    return
        writer = threading.Thread(target=trickle, daemon=True)
        writer.start()
        started = time.monotonic()
        try:
            try:
                self._read_response(connection)
            except (ConnectionResetError, ConnectionAbortedError):
                pass  # Total header expiry closes incomplete requests.
            self.assertLess(time.monotonic() - started, 0.65)
        finally:
            stopped.set()
            writer.join(timeout=1)

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
