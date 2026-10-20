import unittest
from unittest.mock import Mock

from adverserial.session import ReceiptStream, VerifiedSession


class StreamCleanupTests(unittest.TestCase):
    def test_both_dispatch_paths_close_before_the_first_chunk(self):
        for method in ("_stream", "_ehbp_stream"):
            with self.subTest(method=method):
                session = object.__new__(VerifiedSession)
                session._base_path = "/v1"
                session._headers = lambda headers: headers
                connection = Mock()
                connection.getresponse.return_value.status = 200
                connection.getresponse.return_value.getheader.return_value = "00" * 12
                session._connect = lambda: connection
                session._ehbp_identity = Mock()
                stream = getattr(session, method)(b"{}", "nonce", "cyberglm")
                stream.close()
                connection.close.assert_called_once()
                self.assertFalse(stream.receipt_verified)

    def test_close_before_iteration_releases_transport_once(self):
        close = Mock()
        stream = ReceiptStream(close)
        def events():
            try:
                yield {"content": "hello"}
            finally:
                stream._close_transport()
        stream._generator = events()
        stream.close()
        stream.close()
        close.assert_called_once()
        self.assertEqual(list(stream), [])
        self.assertFalse(stream.receipt_verified)

    def test_close_after_first_chunk_releases_transport_once(self):
        close = Mock()
        stream = ReceiptStream(close)
        def events():
            try:
                yield {"content": "hello"}
                yield {"content": "world"}
            finally:
                stream._close_transport()
        stream._generator = events()
        next(stream)
        stream.close()
        close.assert_called_once()
        self.assertFalse(stream.receipt_verified)

    def test_connection_failure_before_stream_exists_closes_transport(self):
        # Exercise both dispatch paths without network or cryptographic mocks
        # affecting any receipt test.
        for method in ("_stream", "_ehbp_stream"):
            with self.subTest(method=method):
                session = object.__new__(VerifiedSession)
                session._base_path = "/v1"
                session._headers = lambda headers: headers
                connection = Mock()
                connection.getresponse.side_effect = OSError("upstream disconnected")
                session._connect = lambda: connection
                session._ehbp_identity = Mock()
                with self.assertRaises(OSError):
                    getattr(session, method)(b"{}", "nonce", "cyberglm")
                connection.close.assert_called_once()
