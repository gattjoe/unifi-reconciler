import unittest
from unittest.mock import MagicMock
from unifi_reconciler.client import UniFiClient, merge_desired_into_v2
from unifi_reconciler.config import Config
from unifi_reconciler.model import Action, Protocol
from unifi_reconciler.normalized import NormalizedPolicy

class TestUniFiClientIntegration(unittest.TestCase):
    def setUp(self):
        # Mock configuration
        self.cfg = Config(
            host="mock.unifi.local",
            timeout=10,
            ca_fingerprint="fake_fingerprint",
            site="default",
            username="admin",
            password="password",
            insecure_tls=False,
            admin_zones=("Internal",),
            admin_networks=(),
            admin_dst_zones=("Gateway",),
            github_token="",
            github_repo="",
            github_rules_path="rules",
            github_base_branch="main",
        )
        # Mock the urllib3 PoolManager to avoid actual network calls
        self.mock_http = MagicMock()
        # Mocking the request method to return a mock response
        # We'll set this up per test case
        
    def test_policy_to_wire_v2_read_modify_write(self):
        """Verify the JSON construction for v2 read-modify-write updates."""
        UniFiClient(self.cfg, http=self.mock_http)

        # 1. Mock a raw live policy from the UDM (v2 flavor)
        # Note the "matching_target": "IP" and "network_ids" which we want to preserve
        raw_live = {
            "name": "Live Rule",
            "enabled": True,
            "action": "ALLOW",
            "index": 10,
            "protocol": "tcp",
            "logging": False,
            "description": "Live description",
            "source": {
                "zone_id": "zone_1",
                "ips": ["1.1.1.1"],
                "matching_target": "IP",
                "network_ids": ["net_1"]
            },
            "destination": {
                "zone_id": "zone_2",
                "ips": ["2.2.2.2"],
                "matching_target": "IP",
                "network_ids": ["net_2"]
            },
            "_id": "rule_999",
            "schedule": "...", # Field to preserve
            "ip_version": "4"    # Field to preserve
        }
        
        # 2. Define the desired state (partial update).
        # The live rule is IP-target, so src/dst_networks must be empty — the test
        # verifies that network_ids from the live body are preserved by the
        # read-modify-write even though the model does not own them.
        desired = NormalizedPolicy(
            name="Updated Name",
            enabled=True,
            action=Action.ALLOW,
            index=11,
            src_zone="zone_1",
            dst_zone="zone_2",
            protocol=Protocol.TCP,
            logging=True,
            description="New description",
            src_ips=("1.1.1.1",),
            dst_ips=("2.2.2.2",),
            src_networks=(),
            dst_networks=(),
            policy_id="rule_999",
            predefined=False
        )
        
        zones = {"zone_1": "zone_1", "zone_2": "zone_2"}
        networks = {"net_1": "net_1", "net_2": "net_2"}
        
        merged = merge_desired_into_v2(raw_live, desired, zones, networks)

        self.assertEqual(merged["name"], "Updated Name")
        self.assertEqual(merged["index"], 11)
        self.assertEqual(merged["logging"], True)
        # v2-only fields preserved by read-modify-write
        self.assertEqual(merged["schedule"], "...")
        self.assertEqual(merged["ip_version"], "4")
        self.assertEqual(merged["source"]["matching_target"], "IP")
        self.assertEqual(merged["source"]["network_ids"], ["net_1"])

if __name__ == "__main__":
    unittest.main()
