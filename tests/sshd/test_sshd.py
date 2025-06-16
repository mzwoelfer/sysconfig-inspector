import tempfile
import os
import shutil
import unittest
import logging
from sysconfig_inspector.sshd import SSHDInspector

logging.basicConfig(level=logging.DEBUG)
_sshd_inspector_logger = logging.getLogger('sysconfig_inspector.sshd')

print(f"DEBUG_TEST: Effective User ID (euid): {os.geteuid()}")


# --- HELPER CLASS FOR TESTING ---
class BaseSshInspectorTest(unittest.TestCase):
    """
    Base class for SSHD Inspector tests.
    Provides a temporary filesystem and 
    helper functions for creating test files.
    """
    def setUp(self):
        """
        Sets up a temporary directory for test SSHD config files.
        """
        self.temp_dir = tempfile.mkdtemp()
        self._create_base_sshd_config_directories()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_base_sshd_config_directories(self):
        """
        Creates a temporary directory structure for SSHD tests.
        e.g /tmp/ID/etc/ssh/
        """
        self.sshd_config_path = self._build_temp_path('/etc/ssh/sshd_config')
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


# --- BASIC SSHINSPECTOR TESTS ---
class TestSSHDInspector(BaseSshInspectorTest):
    """
    Tests for basic SSHDInspector initialization and file path discovery.
    """

    def test_ssh_class_init(self):
        sshd_inspector = SSHDInspector()

        self.assertIsInstance(sshd_inspector, SSHDInspector)

    def test_find_default_sshd_config_file(self):
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config'
        )

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config)

        self.assertEqual(sshd_inspector.config_file_paths, [sshd_config])


# --- TEST FILE SYSTEM OPERATIONS ---
class TestFileReadOperations(BaseSshInspectorTest):
    def test_sshd_config_not_found(self):
        """
        Tests file not found.
        """
        unreadable_file_path = self._build_temp_path(
            '/etc/ssh/non_existant_sshd_config'
        )

        with self.assertLogs(_sshd_inspector_logger, level='ERROR') as cm:
            sshd_inspector = SSHDInspector(
                sshd_config_path=unreadable_file_path
            )

            self.assertIn("not read file", cm.output[0])

    def test_sshd_config_file_unreadable(self):
        """
        Tests when sshd_config file exists but is unreadable (IOError).
        Expects an empty config and an ERROR log message.
        """
        unreadable_file_path = self._build_temp_path(
            '/etc/ssh/unreadable_sshd_config'
        )
        os.makedirs(unreadable_file_path, exist_ok=True)

        with self.assertLogs(_sshd_inspector_logger, level='ERROR') as cm:
            sshd_inspector = SSHDInspector(
                sshd_config_path=unreadable_file_path
            )

            self.assertIn(f"ERROR: Could not read file '{unreadable_file_path}':", cm.output[0])




# --- INTEGRATION TEST WITH WHOLE FILES ---
class TestIntegrationTest(BaseSshInspectorTest):
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

        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

    def test_large_compare_to_functionality(self):
        self.maxDiff = None

        included_dir_path = self.included_sshd_dir_path

        actual_main_content = f"""
            Include {included_dir_path}/*.conf
            Port 22
            PubKeyAuthentication yes
            LogLevel INFO

            PermitRootLogin prohibit-password
            AllowTcpForwarding yes

            Match User admin
                PermitRootLogin yes
                X11Forwarding no
            Match Address 192.168.1.0/24
                ClientAliveInterval 60
                MaxAuthTries 3
            """
        sshd_config = self.create_test_file(
            '/etc/ssh/sshd_config',
            actual_main_content
        )

        # --- EXPECTED PARSED ACTUAL CONFIG ---
        target_sshd_config = {
            "Include": f"{included_dir_path}/*.conf",
            "Port": 22,
            "PubKeyAuthentication": True, 
            "LogLevel": "INFO",
            "Match": [
                {
                    "criterium": "User admin",
                    "settings": {
                        "PermitRootLogin": False, 
                        "AllowAgentForwarding": True 
                    }
                },
                {
                    "criterium": "Address 192.168.1.0/24",
                    "settings": {
                        "ClientAliveInterval": 60,
                        "MaxAuthTries": 3
                    }
                },
                {
                    "criterium": "Group developers",
                    "settings": {
                        "ForceCommand": "/usr/bin/git-shell"
                    }
                }
            ],
            "Compression": True,
            "ClientAliveInterval": 60, 
            "MaxAuthTries": 5, 
        }

        # --- INITIALIZE COMPARISON RESULTS ---
        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )
        sshd_inspector.compare_to(target_sshd_config)

        # --- COMPARISON RESULTS ---
        matching_config = {
            "Include": f"{included_dir_path}/*.conf",
            "Port": 22, 
            "PubKeyAuthentication": True, 
            "LogLevel": "INFO",
            "Match": [
                {
                    "criterium": "Address 192.168.1.0/24",
                    "settings": {
                        "ClientAliveInterval": 60,
                        "MaxAuthTries": 3
                    }
                }
            ]
        }

        missing_from_actual = {
            "Compression": True,
            "ClientAliveInterval": 60, 
            "MaxAuthTries": 5, 
            "Match": [
                {
                    "criterium": "User admin",
                    "settings": {
                        "PermitRootLogin": False, 
                        "AllowAgentForwarding": True 
                    }
                },
                {
                    "criterium": "Group developers", 
                    "settings": {
                        "ForceCommand": "/usr/bin/git-shell"
                    }
                }
            ]
        }

        extra_in_actual = {
            "PermitRootLogin": "prohibit-password", 
            "AllowTcpForwarding": True, 
            "Match": [
                {
                    "criterium": "User admin",
                    "settings": {
                        "PermitRootLogin": True,
                        "X11Forwarding": False
                    }
                },
            ]
        }

        self.assertCountEqual(sshd_inspector.matching_config, matching_config)
        self.assertCountEqual(sshd_inspector.missing_from_actual, missing_from_actual)
        self.assertCountEqual(sshd_inspector.extra_in_actual, extra_in_actual)

