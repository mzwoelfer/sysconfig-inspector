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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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


        sshd_inspector = SSHDInspector(
            sshd_config_path=sshd_config
        )

        self.assertEqual(sshd_inspector.sshd_config, expected_output)

# --- TEST INCLUDES FUNCTIONALITY ---
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "address 8.8.8.8/8,9.9.9.9/8",
                    "settings": {
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
                    "criterium": "User testuser",
                    "settings": {
                        "PermitRootLogin": False,
                        "PasswordAuthentication": True,
                    }
                }
            ]
        })

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

