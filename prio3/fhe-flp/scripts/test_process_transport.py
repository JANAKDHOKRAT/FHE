#!/usr/bin/env python3
"""Regression tests for framing and deadlines; no FHE or crypto claims."""
import os
import struct
import unittest
import train_pine_processes as transport


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.read_fd, False)
        os.set_blocking(self.write_fd, False)
        self.reader = os.fdopen(self.read_fd, "rb", buffering=0)
        self.writer = os.fdopen(self.write_fd, "wb", buffering=0)
        self.old_timeout = transport.TIMEOUT
        transport.TIMEOUT = 0.05

    def tearDown(self):
        transport.TIMEOUT = self.old_timeout
        self.reader.close()
        self.writer.close()

    def test_frame_round_trip(self):
        transport.send(self.writer, 2, b"abc")
        self.assertEqual(transport.receive(self.reader, 2, 3), b"abc")

    def test_oversize_rejected_from_header(self):
        os.write(self.write_fd, transport.MAGIC + bytes([3]) + struct.pack("<Q", 2**64-1))
        with self.assertRaisesRegex(RuntimeError, "oversized"):
            transport.receive(self.reader, 3, 100)

    def test_read_deadline(self):
        with self.assertRaises(TimeoutError):
            transport.read_exact(self.reader, 1)

    def test_write_deadline_when_peer_stops_reading(self):
        while True:
            try:
                os.write(self.write_fd, bytes(4096))
            except BlockingIOError:
                break
        with self.assertRaises(TimeoutError):
            transport.send(self.writer, 2, bytes(100000))

    def test_trailing_bytes_and_wrong_role_are_rejected(self):
        frame = transport.MAGIC + bytes([2]) + struct.pack("<Q", 3) + b"abc"
        self.assertEqual(transport.unframe(frame, 2), b"abc")
        for raw, kind in ((frame+b"x", 2), (frame, 3), (frame[:-1], 2)):
            with self.assertRaises(RuntimeError):
                transport.unframe(raw, kind)


if __name__ == "__main__":
    unittest.main()
