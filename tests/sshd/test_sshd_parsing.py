import os
import unittest
from sysconfig_inspector.sshd import SSHDInspector
from tests.sshd.test_sshd import BaseSshInspectorTest

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")
# --- SSHD PARSING ---
class TestParsing(BaseSshInspectorTest):
    def test_parse_boolean_sshd_config(self):
        sshd_content = """
            PasswordAuthentication no
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "PasswordAuthentication": False
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

    def test_parse_cast_integer_sshd_config(self):
        sshd_content = """
            Port 22
        """

        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "Port": 22
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)


    def test_parse_single_word_directive(self):
        """
        Tests that a directive with no explicit value is parsed.
        Returns None.
        """
        sshd_content = """
            UsePAM
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "UsePAM": None
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

    def test_subsystem_is_parsed_correctly(self):
        """
        Subsystem       sftp    /usr/lib/openssh/sftp-server
        """
        sshd_content = """
            Subsystem sftp /usr/lib/openssh/sftp-server
        """

        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "Subsystem sftp": "/usr/lib/openssh/sftp-server"
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)


    def test_acceptenv_is_parsed_correctly(self):
        """
        AcceptEnv LANG LC_*
        """
        sshd_content = """
            AcceptEnv LANG LC_*
        """

        sshd_config = self.create_test_file(
            self.sshd_config_path,
            contents=sshd_content
        )

        expected_output = {
            "AcceptEnv": "LANG LC_*"
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)



    def test_parse_match_blocks(self):
        sshd_content = """
            Match address 8.8.8.8/8,9.9.9.9/8
                ClientAliveCountMax 0
        """

        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                            "ClientAliveCountMax": 0
                    }
                }
            ]
        }

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

    def test_parse_multiple_match_blocks(self):
        sshd_content = """
            Match address 8.8.8.8/8,9.9.9.9/8
            PubKeyAuthentication yes
            Match User admin
            X11Forwarding yes
        """

        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )


        expected_output = {
            "Match": [
                {
                    "address 8.8.8.8/8,9.9.9.9/8": {
                        "PubKeyAuthentication": True
                    }
                },
                {
                    "User admin": {
                            "X11Forwarding": True
                    }
                }
            ]
        }


        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

