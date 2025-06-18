import os
import unittest
from sysconfig_inspector.sshd import SSHDInspector
from tests.sshd.test_sshd import BaseSshInspectorTest

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")
# --- TEST INCLUDES FUNCTIONALITY ---
class TestIncludesFunctionality(BaseSshInspectorTest):
    def test_does_not_include_configuration(self):
        """
        Do not include /etc/ssh/sshd_config.d/*.conf
        Just read a normal key-value
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
            "PubkeyAuthentication" : True,
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)
