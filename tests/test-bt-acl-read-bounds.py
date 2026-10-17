# SPDX-License-Identifier: GPL-3.0-only AND MS-PL
# Project-authored test portions: GPL-3.0-only.
# Assertion source excerpts from bt/src/io.c, io.h, driver.h and Fdo.c: MS-PL.
# Copyright (c) Microsoft Corporation All Rights Reserved
# See LICENSE and bt/LICENSE-MS-PL.txt for the license texts.
# Provided without warranty. See LICENSE for the license text.
# Additional permission: BLUETOOTH-LINKING-EXCEPTION.txt.

"""Source-level regression checks for the Bluetooth H4 read bounds."""

import argparse
import hashlib
import json
import re
import unittest
from pathlib import Path

from test_support import output_dir, write_text

ROOT = Path(__file__).resolve().parents[1]
BT_ROOT = ROOT / 'bt'
IO_C = (BT_ROOT / "src" / "io.c").read_text(encoding="utf-8-sig")
IO_H = (BT_ROOT / "src" / "io.h").read_text(encoding="utf-8-sig")
DRIVER_H = (BT_ROOT / "src" / "driver.h").read_text(encoding="utf-8-sig")
FDO_C = (BT_ROOT / "src" / "Fdo.c").read_text(encoding="utf-8-sig")
DEVICE_C = (BT_ROOT / "src" / "device.c").read_text(encoding="utf-8-sig")


class H4AclReadBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start = IO_C.index("ReadH4PacketReassemble(")
        cls.reassembly = IO_C[start:]
        header_start = cls.reassembly.index("case GET_PKT_HEADER:")
        payload_start = cls.reassembly.index("case GET_PKT_PAYLOAD:", header_start)
        cls.header_case = cls.reassembly[header_start:payload_start]
        discard_start = cls.reassembly.index("case GET_PKT_DISCARD_PAYLOAD:", payload_start)
        discard_end = cls.reassembly.index("default:", discard_start)
        cls.discard_case = cls.reassembly[discard_start:discard_end]

        formatter_start = IO_C.index("NTSTATUS\nReadH4Packet(")
        cls.formatter = IO_C[formatter_start:]
        scheduler_start = IO_C.index("ReadNext:")
        scheduler_end = IO_C.index("\nExit:", scheduler_start)
        cls.scheduler = IO_C[scheduler_start:scheduler_end]

    def test_acl_limit_is_checked_on_complete_header_before_payload_state(self):
        complete_header = self.header_case.index(
            "if (_ReadContext->BytesReadNextSegment == 3 && BytesRemained)"
        )
        guard = self.header_case.index(
            "if (_ReadContext->H4Packet.Packet.AclData.DataLength > "
            "HCI_MAX_ACL_PAYLOAD_SIZE)"
        )
        discard = self.header_case.index(
            "ReadSegmentStateSet(_ReadContext, GET_PKT_DISCARD_PAYLOAD);",
            guard,
        )
        normal_payload = self.header_case.index(
            "ReadSegmentStateSet(_ReadContext, GET_PKT_PAYLOAD);",
            guard,
        )
        self.assertLess(complete_header, guard)
        self.assertLess(guard, discard)
        self.assertLess(discard, normal_payload)
        self.assertIn(
            "_ReadContext->BytesToRead4FullPacket =\n"
            "                            _ReadContext->H4Packet.Packet.AclData.DataLength;",
            self.header_case[discard:normal_payload],
        )

    def test_oversized_payload_is_drained_without_copy_and_resyncs_at_boundary(self):
        self.assertIn("BytesToRead = BytesRemained;", self.discard_case)
        self.assertIn(
            "BytesToRead = _ReadContext->BytesToRead4FullPacket;",
            self.discard_case,
        )
        self.assertIn(
            "_ReadContext->BytesToRead4FullPacket -= BytesToRead;",
            self.discard_case,
        )
        self.assertIn(
            "if (_ReadContext->BytesToRead4FullPacket == 0)",
            self.discard_case,
        )
        self.assertIn(
            "ReadSegmentStateSet(_ReadContext, GET_PKT_TYPE);",
            self.discard_case,
        )
        self.assertNotIn("RtlCopyMemory", self.discard_case)

    def test_scheduler_and_formatter_never_advertise_more_than_capacity(self):
        self.assertIn(
            "ReadContext->BytesToRead4FullPacket > sizeof(FdoExtension->ReadBuffer)",
            self.scheduler,
        )
        self.assertIn(
            "BytesToRead = sizeof(FdoExtension->ReadBuffer);",
            self.scheduler,
        )
        capacity_guard = self.formatter.index(
            "if (0 == _BufferLen || _BufferLen > _BufferCapacity)"
        )
        assign = self.formatter.index("WdfMemoryAssignBuffer", capacity_guard)
        self.assertLess(capacity_guard, assign)
        self.assertIn("Status = STATUS_INVALID_PARAMETER;", self.formatter[capacity_guard:assign])
        self.assertIn("_Pre_writable_byte_size_(_BufferCapacity)", DRIVER_H)

    def test_all_active_read_callers_declare_their_actual_buffer_capacity(self):
        self.assertEqual(FDO_C.count("sizeof(FdoExtension->ReadBuffer),"), 2)
        self.assertEqual(DEVICE_C.count("sizeof(extension->ReadBuffer),"), 1)
        self.assertRegex(
            IO_C,
            r"ReadH4Packet\(ReadContext,\s*FdoExtension->ReadRequest,\s*"
            r"FdoExtension->ReadMemory,\s*FdoExtension->ReadBuffer,\s*"
            r"sizeof\(FdoExtension->ReadBuffer\),\s*BytesToRead\);",
        )

    def test_configured_acl_boundary_keeps_1021_and_rejects_oversized_values(self):
        acl_match = re.search(
            r"#define\s+HCI_MAX_ACL_PAYLOAD_SIZE\s+\((\d+)\)",
            IO_H,
        )
        header_match = re.search(
            r"#define\s+HCI_ACL_HEADER_SIZE\s+\((\d+)\)",
            IO_H,
        )
        capacity_match = re.search(
            r"#define\s+MAX_H4_HCI_PACKET_SIZE\s+"
            r"\(1\+HCI_ACL_HEADER_SIZE\s*\+\s*HCI_MAX_ACL_PAYLOAD_SIZE\)",
            IO_H,
        )
        self.assertIsNotNone(acl_match)
        self.assertIsNotNone(header_match)
        self.assertIsNotNone(capacity_match)

        maximum = int(acl_match.group(1))
        capacity = 1 + int(header_match.group(1)) + maximum
        self.assertEqual(maximum, 1021)
        self.assertEqual(capacity, 1026)

        self.assertFalse(1021 > maximum)
        for length in (1022, 1026, 1027, 65535):
            self.assertTrue(length > maximum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('bt-acl-read-bounds'))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(H4AclReadBoundsTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sources = ('bt/src/io.c', 'bt/src/io.h', 'bt/src/driver.h', 'bt/src/Fdo.c', 'bt/src/device.c')
    receipt = dict(passed=result.wasSuccessful(), checks=result.testsRun, board_tested=False,
                   source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
                   test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
