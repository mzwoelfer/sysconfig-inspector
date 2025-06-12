import tempfile
import os
import shutil
import unittest
import logging
from sysconfig_inspector.ssh import SSHInspector

logging.basicConfig(level=logging.DEBUG)
_ssh_inspector_logger = logging.getLogger('sysconfig_inspector.ssh')

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")

class BaseSshInspectorTest(unittest.TestCase):
    """
    Base class for SSH Inspector tests.
    Provides a temporary filesystem and 
    helper functions for creating test files.
    """
    def setUp(self):
        """
        Sets up a temporary directory for test SSH config files.
        """
        self.temp_dir = tempfile.mkdtemp()
        self._create_base_sshd_config_directories()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_base_sshd_config_directories(self):
        """
        Creates a temporary directory structure for SSH tests.
        e.g /tmp/ID/etc/ssh/
        """
        self.sshd_config_path = self._build_temp_path('/etc/ssh/sshd_config')
        self.ssh_config_path = self._build_temp_path('/etc/ssh/ssh_config')
        self.included_sshd_dir_path = self._build_temp_path('/etc/ssh/sshd_config.d')

        os.makedirs(os.path.dirname(self.sshd_config_path), exist_ok=True)
        os.makedirs(self.included_sshd_dir_path, exist_ok=True)

    def _build_temp_path(self, relative_path: str) -> str:
        """
        COnstructs a full, absolute path within the temporary directory.
        Removes leading slash from relative_path (e.g. /etc/ssh/sshd_config --> etc/ssh/sshd_config)
        """
        return os.path.join(self.temp_dir, relative_path.lstrip('/'))

    def create_test_file(self, relative_path: str, contents: str = "") -> str:
        """
        Creates a file in the temporary directory.
        Can contain a string.
        Relative_path should be like '/etc/ssh/sshd_config'.
        """
        full_path = self._build_temp_path(relative_path)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, 'w', encoding='utf-8') as file:
            file.write(contents)
        return full_path


class TestSSHInspector(BaseSshInspectorTest):
    """
    Tests for basic SSHInspector initialization and file path discovery.
    """

    def test_ssh_class_init(self):
        ssh_inspector = SSHInspector()

        self.assertIsInstance(ssh_inspector, SSHInspector)

    def test_find_default_sshd_config_file(self):
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config'
        )

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config)

        self.assertEqual(ssh_inspector.config_file_paths, [sshd_config])

    def test_find_default_ssh_config_file(self):
        ssh_config = self.create_test_file(
            '/etc/ssh/ssh_config'
        )

        ssh_inspector = SSHInspector(
            ssh_config_path=ssh_config,
            sshd_config_path="")

        self.assertEqual(ssh_inspector.config_file_paths, [ssh_config])


class TestSSHInspectorParser(BaseSshInspectorTest):
    """Test parsing SSHD directives"""
    def test_sshd_config_file_unreadable(self):
        """
        Tests when sshd_config file exists but is unreadable (IOError).
        Expects an empty config and an ERROR log message.
        """
        unreadable_file_path = self._build_temp_path(
            '/etc/ssh/unreadable_sshd_config'
        )
        os.makedirs(unreadable_file_path, exist_ok=True)


        with self.assertLogs('sysconfig_inspector.ssh', level='ERROR') as cm:
            ssh_inspector = SSHInspector(
                ssh_config_path="",
                sshd_config_path=unreadable_file_path
            )
            
            self.assertIn(f"ERROR: Could not read file '{unreadable_file_path}':", cm.output[0])


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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
                        "ClientAliveCountMax": 0
                    }
                }
            ]
        }

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

    def test_multiple_match_blocks(self):
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
                        "PubKeyAuthentication": True
                    }
                },
                {
                    "criterium": "User admin",
                    "settings": {
                        "X11Forwarding": True
                    }
                }
            ]
        }


        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

    def test_includes_match_block_correctly(self):
        """
        Tests that a Match block in an included file is correctly parsed and added to the sshd config
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

        ssh_inspector = SSHInspector(
            ssh_config_path="", 
            sshd_config_path=main_sshd_config_path
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)


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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)


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

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

    def test_integration_large_combined_sshd_config(self):
        """
        Integration test one big sshd config
        """
        sshd_content = """
            Port 22
            PermitRootLogin no
            PubKeyAuthentication no
            Subsystem sftp /usr/sftp-path
            X11Forwarding no
            Match user dummy-user
            ChrootDirectory /home/user/dummy
            Match address 8.8.8.8/8,9.9.9.9/8
            PubKeyAuthentication yes
            ClientAliveCountMax 3
        """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            contents=sshd_content
        )

        expected_output = {
            "Port": 22,
            "PermitRootLogin": False,
            "PubKeyAuthentication": False,
            "Subsystem sftp": "/usr/sftp-path",
            "X11Forwarding": False,
            "Match": [
                {
                    "criterium": "user dummy-user",
                    "settings": {
                        "ChrootDirectory": "/home/user/dummy",
                    }

                },
                {
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
                        "PubKeyAuthentication": True,
                        "ClientAliveCountMax": 3
                    }
                }
            ]
        }

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

class TestSSHInspectorComparison(BaseSshInspectorTest):
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

        ssh_inspector = SSHInspector(
            sshd_config_path=self.sshd_config_path,
            ssh_config_path="")

        external_sshd_config = {
            "Port": 22       
        }

        comparison_result = ssh_inspector.compare_to(external_sshd_config)

        self.assertEqual(ssh_inspector.matching_config, external_sshd_config)
