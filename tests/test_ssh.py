import tempfile
import os
import shutil
import unittest
from sysconfig_inspector.ssh import SSHInspector

def create_test_file(temp_dir: str, relative_path: str, contents: str = ""):
    """Creates a file with content in a temporary directory structure relative to temp_dir.
    relative_path should be like '/etc/ssh/sshd_config'.
    """
    full_path = os.path.join(temp_dir, relative_path.lstrip(os.sep))

    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    with open(full_path, 'w', encoding='utf-8') as file:
        file.write(contents)
    return full_path


class BaseSshInspectorTest(unittest.TestCase):
    """Base class for SSH Inspector tests, providing a temporary filesystem."""
    def define_temporary_paths_for_SSH_configs(self):
        """
        Creates temporary dummy ssh paths inside the temp directory
        """
        self.sshd_config_path = os.path.join(self.temp_dir, 'etc', 'ssh', 'sshd_config')
        self.ssh_config_path = os.path.join(self.temp_dir, 'etc', 'ssh', 'ssh_config')

    def create_temporary_directory(self, temp_dir: str):
        # Creates /tmp/ID/etc/ssh
        os.makedirs(os.path.dirname(temp_dir), exist_ok=True) 


    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
        self.define_temporary_paths_for_SSH_configs()
        self.create_temporary_directory(self.sshd_config_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


class TestSSHInspector(BaseSshInspectorTest):
    def test_ssh_class_init(self):
        ssh_inspector = SSHInspector()
        self.assertIsInstance(ssh_inspector, SSHInspector)

    def test_find_default_sshd_config_file(self):
        sshd_config = create_test_file(self.temp_dir, '/etc/ssh/sshd_config')

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config)

        self.assertEqual(ssh_inspector.config_file_paths, [sshd_config])

    def test_find_default_ssh_config_file(self):
        ssh_config = create_test_file(self.temp_dir, '/etc/ssh/ssh_config')

        ssh_inspector = SSHInspector(
            ssh_config_path=ssh_config,
            sshd_config_path="")

        self.assertEqual(ssh_inspector.config_file_paths, [ssh_config])


class TestSSHInspectorParser(BaseSshInspectorTest):
    """Test SSH parser"""
    def test_parse_boolean_sshd_config(self):
        sshd_config = create_test_file(
            self.temp_dir, 
            '/etc/ssh/sshd_config',
            contents="""
                PasswordAuthentication no
            """)

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        expected = {
            "PasswordAuthentication": False
        }

        self.assertEqual(ssh_inspector.sshd_config, expected)

    def test_parse_cast_integer_sshd_config(self):
        sshd_config = create_test_file(
            self.temp_dir, 
            '/etc/ssh/sshd_config',
            contents="""
                Port 22
            """)

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        expected = {
            "Port": 22
        }

        self.assertEqual(ssh_inspector.sshd_config, expected)

    def test_parse_match_blocks(self):
        sshd_config = create_test_file(
            self.temp_dir, 
            '/etc/ssh/sshd_config',
            contents="""
                Match address 8.8.8.8/8,9.9.9.9/8
                    ClientAliveCountMax 0
            """)

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
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

        self.assertEqual(ssh_inspector.sshd_config, expected_output)

    def test_multiple_match_blocks(self):
        sshd_config = create_test_file(
            self.temp_dir, 
            '/etc/ssh/sshd_config',
            contents="""
                Match address 8.8.8.8/8,9.9.9.9/8
                PubKeyAuthentication yes
                Match User admin
                X11Forwarding yes
            """)

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
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

        self.assertEqual(ssh_inspector.sshd_config, expected_output)



    def test_subsystem_is_parsed_correctly(self):
        """
        Parse Subsystem in SSHD config
        Subsystem       sftp    /usr/lib/openssh/sftp-server
        """
        sshd_config = create_test_file(
            self.temp_dir, 
            '/etc/ssh/sshd_config',
            contents="""
                Subsystem sftp /usr/lib/openssh/sftp-server
            """)

        ssh_inspector = SSHInspector(
            ssh_config_path="",
            sshd_config_path=sshd_config
        )

        expected_output = {
            "Subsystem sftp": "/usr/lib/openssh/sftp-server"
        }

        self.assertEqual(ssh_inspector.sshd_config, expected_output)


    def test_acceptenv_is_parsed_correctly(self):
        """
        AcceptEnv LANG LC_*

        """

    def test_includes_configuration_correctly(self):
        """
        Include /etc/ssh/ssh_config.d/*.conf
        Include /etc/ssh/sshd_config.d/*.conf
        """
