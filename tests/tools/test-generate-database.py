#!/usr/bin/env python3
"""
Regression tests for generate-database-from-schema.py.

The generator used to match on the last path segment only, so any property
ending in "enabled", "port", "address", ... was credited to whichever parser
read that key first. These tests pin down the path-aware behaviour.

Usage:
    python3 test-generate-database.py
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "generate_database", HERE / "generate-database-from-schema.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

FIXTURE = r'''
static int cfg_poe_parse(cJSON *poe)
{
	cJSON *e = cJSON_GetObjectItemCaseSensitive(poe, "admin-mode");
	return 0;
}

static int
cfg_ethernet_parse(cJSON *ethernet,
		   struct plat_cfg *cfg) {
	cJSON *eth;
	cJSON_ArrayForEach(eth, ethernet) {
		bool on = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(eth, "enabled"));
		if (cfg_poe_parse(cJSON_GetObjectItemCaseSensitive(eth, "poe")))
			return -1;
	}
	return 0;
}

static int cfg_services_parse(cJSON *services)
{
	/* cJSON_GetObjectItemCaseSensitive(s, "telnet") is not read */
	cJSON *s = cJSON_GetObjectItemCaseSensitive(services, "ssh");
	cJSON *port = cJSON_GetObjectItemCaseSensitive(s,
							"port");
	const char *msg = "{ not a brace }";
	return 0;
}

static const struct table tbl[] = { { 1, 2 } };

TEST_STATIC struct plat_cfg * cfg_parse(cJSON *config)
{
	cfg_ethernet_parse(cJSON_GetObjectItemCaseSensitive(config, "ethernet"), cfg);
	cfg_services_parse(cJSON_GetObjectItemCaseSensitive(config, "services"));
	return cfg;
}
'''


class SourceIndexTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        src = Path(cls.tmp.name) / "proto.c"
        src.write_text(FIXTURE)
        cls.index = gen.SourceIndex(src)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def found(self, path):
        return self.index.find_property(path)[1]

    def test_functions_detected_regardless_of_header_layout(self):
        for name in ("cfg_poe_parse", "cfg_ethernet_parse",
                     "cfg_services_parse", "cfg_parse"):
            self.assertIn(name, self.index.functions)
        self.assertNotIn("tbl", self.index.functions)

    def test_full_chain_is_found(self):
        self.assertEqual(self.found("ethernet[].enabled"), "cfg_ethernet_parse")
        self.assertEqual(self.found("services.ssh.port"), "cfg_services_parse")

    def test_parent_read_in_caller(self):
        self.assertEqual(self.found("ethernet[].poe.admin-mode"), "cfg_poe_parse")

    def test_same_leaf_under_other_parent_is_not_found(self):
        self.assertIsNone(self.found("switch.rt-events.poe-status.enabled"))
        self.assertIsNone(self.found("services.rtty.port"))
        self.assertIsNone(self.found("ethernet[].bpdu-guard.enabled"))

    def test_keys_in_comments_are_ignored(self):
        self.assertIsNone(self.found("services.telnet"))


class DatabaseEntryTest(unittest.TestCase):

    def test_unimplemented_is_not_reported_as_configured(self):
        entry = gen.generate_database_entry("switch.pim.ssm-ranges[].mask", None, None, "proto.c")
        self.assertIn("PROP_IGNORED", entry)
        entry = gen.generate_database_entry("ethernet[].speed", 1136, "cfg_ethernet_parse", "proto.c")
        self.assertIn("PROP_CONFIGURED", entry)


class ProtoCTest(unittest.TestCase):
    """Known answers against the real proto.c."""

    @classmethod
    def setUpClass(cls):
        cls.index = gen.SourceIndex(HERE / "../../src/ucentral-client/proto.c")

    def test_every_literal_key_read_is_inside_a_function(self):
        text = gen.strip_comments(
            (HERE / "../../src/ucentral-client/proto.c").read_text())
        total = len(gen.GET_ITEM_RE.findall(text))
        indexed = sum(len(lines) for keys in self.index.reads.values()
                      for lines in keys.values())
        self.assertEqual(total, indexed)

    def test_known_parsed(self):
        for path in ("ethernet[].enabled", "ethernet[].poe.admin-mode",
                     "switch.loop-detection.instances[].enabled",
                     "switch.port-isolation.sessions[].uplink.interface-list[]"):
            self.assertIsNotNone(self.index.find_property(path)[0], path)

    def test_known_not_parsed(self):
        for path in ("switch.rt-events.poe-status.enabled",
                     "interfaces[].ipv4.multicast.pim.enable",
                     "switch.pim.ssm-ranges[].address",
                     "services.https.enable",
                     "services.rtty.port"):
            self.assertIsNone(self.index.find_property(path)[0], path)


if __name__ == "__main__":
    unittest.main()
