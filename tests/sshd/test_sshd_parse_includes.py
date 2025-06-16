import os
import unittest
from sysconfig_inspector.sshd import SSHDInspector
from tests.sshd.test_sshd import BaseSshInspectorTest

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")
# --- TEST INCLUDES FUNCTIONALITY ---
@unittest.skip("Skipping includes functionality... for now")
class TestIncludesFunctionality(BaseSshInspectorTest):
    def test_includes_configuration_correctly(self):
        """
        Include /etc/ssh/sshd_config.d/*.conf
        First items mentioned take precedence
        """
        main_config_content = f"""
            Include {self.included_sshd_dir_path}/*.conf
            PubkeyAuthentication yes
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=main_config_content
        )

        included_file_content = """
            PubkeyAuthentication no
        """
        additional_test_file = self.create_test_file(
            '/etc/ssh/sshd_config.d/00-custom.conf',
            contents=included_file_content
        )

        expected_output = {
            "Include": f"{self.included_sshd_dir_path}/*.conf",
            "PubkeyAuthentication" : False,
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

    def test_includes_match_block_correctly(self):
        """
        Parse included match block and add to sshd config
        """
        included_match_content = """
            Match User testuser
                PermitRootLogin no
                PasswordAuthentication yes
        """
        included_file_path = self.create_test_file(
            '/etc/ssh/sshd_config.d/50-match-user.conf', 
            contents=included_match_content
        )

        main_config_content = f"""
            Port 22
            Include {self.included_sshd_dir_path}/*.conf 
            HostKey /etc/ssh/ssh_host_rsa_key
        """
        main_sshd_config_path = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=main_config_content
        )


        expected_output = {
            "Port": 22,
            "HostKey": "/etc/ssh/ssh_host_rsa_key",
            "Include": f"{self.included_sshd_dir_path}/*.conf", 
            "Match": [
                {
                    "criterium": "User testuser",
                    "settings": {
                        "PermitRootLogin": False,
                        "PasswordAuthentication": True
                    }
                }
            ]
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=main_sshd_config_path
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)
