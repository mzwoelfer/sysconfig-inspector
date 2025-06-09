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

    def test_find_default_ssh_config_file(self):
        temp_sshd_config = create_test_file(self.temp_dir, '/etc/ssh/sshd_config')

        ssh_inspector = SSHInspector(sshd_config_path=self.sshd_config_path)

        self.assertEqual(ssh_inspector.config_file_paths, [temp_sshd_config])
