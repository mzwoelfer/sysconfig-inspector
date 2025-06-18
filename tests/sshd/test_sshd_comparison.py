import os
import unittest
from sysconfig_inspector.sshd import SSHDInspector
from tests.sshd.test_sshd import BaseSshInspectorTest

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")
# --- TEST COMPARES ---
class TestSSHDInspectorComparison(BaseSshInspectorTest):
    def test_compare_to_same(self):
        """
        Tests compare_to with basic global SSHD settings
        """
        actual_config_content = """
        Port 22
        """
        self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=actual_config_content
        )

        external_sshd_config = {
            "Port": 22       
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=self.sshd_config_path,
        )
        comparison_result = sshd_inspector.compare_to(external_sshd_config)

        self.assertEqual(sshd_inspector.matching_config, external_sshd_config)

    def test_compare_different_values(self):
        actual_config_content = """
        UseDNS no
        """
        self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=actual_config_content
        )

        target_sshd_config = {
            "LogLevel": "INFO"         
        }
        
        sshd_inspector = SSHDInspector(
            sshd_config_path=self.sshd_config_path,
        )
        sshd_inspector.compare_to(target_sshd_config)

        self.assertEqual(sshd_inspector.matching_config, {})
        self.assertEqual(sshd_inspector.missing_from_actual, {
            "LogLevel": "INFO"
        })
        self.assertEqual(sshd_inspector.extra_in_actual, {
            "UseDNS": False 
        })

    def test_compare_non_matching_values(self):
        actual_config_content = """
        UseDNS no
        """
        self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=actual_config_content
        )

        target_sshd_config = {
            "UseDNS": True
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=self.sshd_config_path,
        )
        sshd_inspector.compare_to(target_sshd_config)

        self.assertEqual(sshd_inspector.matching_config, {}) 
        self.assertEqual(sshd_inspector.missing_from_actual, {
            "UseDNS": True
        })
        self.assertEqual(sshd_inspector.extra_in_actual, {
            "UseDNS": False 
        })

    def test_compare_same_match_block(self):
        sshd_content = """
            Match address 8.8.8.8/8,9.9.9.9/8
            PubKeyAuthentication yes
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        target_sshd_config = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": True
                    }
                }
            ]
        }


        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)


        self.assertEqual(sshd_inspector.matching_config, target_sshd_config)
        self.assertEqual(sshd_inspector.missing_from_actual, {})
        self.assertEqual(sshd_inspector.extra_in_actual, {})


    def test_match_only_in_actual_config(self):
        sshd_content = """
            Match address 8.8.8.8/8,9.9.9.9/8
            PubKeyAuthentication no
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        target_sshd_config = {}

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)


        self.assertEqual(sshd_inspector.matching_config, {}) 
        self.assertEqual(sshd_inspector.missing_from_actual, {})
        self.assertEqual(sshd_inspector.extra_in_actual, 
        {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": False
                    }
                }
            ]
        })


    def test_match_only_in_target_config(self):
        sshd_content = """
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        target_sshd_config = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": False
                    }
                }
            ]
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)


        self.assertEqual(sshd_inspector.matching_config, {}) 
        self.assertEqual(sshd_inspector.missing_from_actual, target_sshd_config)
        self.assertEqual(sshd_inspector.extra_in_actual, {})

    def test_compare_match_block_with_different_values(self):
        sshd_content = """
            Match address 8.8.8.8/8,9.9.9.9/8
            PubKeyAuthentication no
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        target_sshd_config = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": True
                    }
                }
            ]
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)


        self.assertEqual(sshd_inspector.matching_config, {}) 
        self.assertEqual(sshd_inspector.missing_from_actual, target_sshd_config)
        self.assertEqual(sshd_inspector.extra_in_actual, 
        {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": False
                    }
                }
            ]
        })

    def test_compare_different_match_blocks(self):
        sshd_content = """
            Match User testuser
            PermitRootLogin no
            PasswordAuthentication yes
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        target_sshd_config = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": True
                    }
                }
            ]
        }


        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)


        self.assertEqual(sshd_inspector.matching_config, {})
        self.assertEqual(sshd_inspector.missing_from_actual, target_sshd_config)
        # TODO: answer question: should use sshd_inspector.actual_config instead of long dictionary?
        self.assertEqual(sshd_inspector.extra_in_actual, 
        {
            "Match": [
                {
                    "User testuser": {
                        "PermitRootLogin": False,
                        "PasswordAuthentication": True,
                    }
                }
            ]
        })
