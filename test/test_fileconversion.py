"""test_fileconversion.py
======================
Unit tests for multi-format conversion (CSV, JSON, JSONL, XML) in fileconversion.py.
"""

import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

import fileconversion


class TestMultiFormatConversion(unittest.TestCase):
    def setUp(self):
        self.sample_record = {
            "RecordID": "23315",
            "TimeCreated": "2026-05-07T09:02:54.000000Z",
            "EventID": "1000",
            "Level": "2",
            "LevelName": "Error",
            "Channel": "Application",
            "Provider": ".NET Runtime",
            "ProviderGuid": "{728cc307-8765-4136-a76f-3d4ca019c6ec}",
            "EventSourceName": ".NET Runtime",
            "Task": "0",
            "Opcode": "0",
            "Keywords": "0x80000000000000",
            "Computer": "DESKTOP-AULEN0J",
            "UserID": "S-1-5-18",
            "ProcessID": "4120",
            "ThreadID": "2916",
            "Version": "0",
            "ActivityID": "",
            "RelatedActivityID": "",
            "Qualifiers": "0",
            "EventData": json.dumps({
                "Data": "Category: Microsoft.EntityFrameworkCore.Database.Connection\r\nEventId: 20004\r\n\r\nAn error occurred using the connection to database 'autoTaskService' on server 'tcp://localhost:9195'."
            }),
            "UserData": "",
            "Message": "Application error event",
        }

    def test_record_to_xml(self):
        xml_str = fileconversion.record_to_xml(self.sample_record)
        self.assertIn('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">', xml_str)
        self.assertIn('<EventRecordID>23315</EventRecordID>', xml_str)
        self.assertIn('<EventID>1000</EventID>', xml_str)
        self.assertIn('Name=".NET Runtime"', xml_str)
        self.assertIn('<Channel>Application</Channel>', xml_str)
        self.assertIn('<Computer>DESKTOP-AULEN0J</Computer>', xml_str)
        self.assertIn('Microsoft.EntityFrameworkCore', xml_str)

        # Verify it parses as valid XML
        root = ET.fromstring(xml_str)
        self.assertEqual(root.tag, "{http://schemas.microsoft.com/win/2004/08/events/event}Event")

    def test_records_to_xml(self):
        records = [self.sample_record, dict(self.sample_record, RecordID="23316")]
        full_xml = fileconversion.records_to_xml(records)
        self.assertTrue(full_xml.startswith('<?xml version="1.0" encoding="utf-8"?>'))
        root = ET.fromstring(full_xml)
        self.assertEqual(root.tag, "Events")
        events = root.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Event")
        self.assertEqual(len(events), 2)

    def test_resolve_output_path(self):
        # CSV
        p_csv = fileconversion.resolve_output_path("test.evtx", "out_dir", output_format="csv")
        self.assertTrue(p_csv.endswith(".csv"))

        # JSON
        p_json = fileconversion.resolve_output_path("test.evtx", "out_dir", output_format="json")
        self.assertTrue(p_json.endswith(".json"))

        # JSONL
        p_jsonl = fileconversion.resolve_output_path("test.evtx", "out_dir", output_format="jsonl")
        self.assertTrue(p_jsonl.endswith(".jsonl"))

        # XML
        p_xml = fileconversion.resolve_output_path("test.evtx", "out_dir", output_format="xml")
        self.assertTrue(p_xml.endswith(".xml"))

    def test_real_evtx_conversion_formats(self):
        sample_evtx = "/Users/nandikasharma/Desktop/Original Data/evtx/Application.evtx"
        if not os.path.exists(sample_evtx):
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            # Test JSON conversion
            res_json = fileconversion.convert(sample_evtx, output_dir=tmpdir, output_format="json")
            self.assertTrue(res_json[0]["success"])
            self.assertTrue(os.path.exists(res_json[0]["output_file"]))
            self.assertTrue(res_json[0]["output_file"].endswith(".json"))

            # Test XML conversion
            res_xml = fileconversion.convert(sample_evtx, output_dir=tmpdir, output_format="xml")
            self.assertTrue(res_xml[0]["success"])
            self.assertTrue(os.path.exists(res_xml[0]["output_file"]))
            self.assertTrue(res_xml[0]["output_file"].endswith(".xml"))

            # Test CSV conversion
            res_csv = fileconversion.convert(sample_evtx, output_dir=tmpdir, output_format="csv")
            self.assertTrue(res_csv[0]["success"])
            self.assertTrue(os.path.exists(res_csv[0]["output_file"]))
            self.assertTrue(res_csv[0]["output_file"].endswith(".csv"))
            self.assertEqual(res_json[0]["record_count"], res_csv[0]["record_count"])
            self.assertEqual(res_xml[0]["record_count"], res_csv[0]["record_count"])


if __name__ == "__main__":
    unittest.main()
