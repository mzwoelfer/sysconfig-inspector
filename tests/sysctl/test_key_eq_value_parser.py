import unittest
import os
import tempfile
import shutil
from typing import Dict, Any

from sysconfig_inspector.sysctl import SysctlInspector

class BaseSysctlInspectorTest(unittest.TestCase):
    """
    Base class for sysctl Inspector tests.
    Provides a temporary filesystem and 
    helper functions for creating test files.
    """
    def setUp(self):
        """
        Setup temporary filesystem for tests
        """
        self.temp_dir = tempfile.mkdtemp()
        self._create_sysctl_config_directories()


    def _create_sysctl_config_directories(self):
        """
        Creates a temporary directory structure for sysctl tests.
        - /tmp/ID/etc/sysctl.conf
        - /tmp/ID/etc/sysctl.d/
        """
        self.sysctl_config_path = self._build_temp_path('/etc/sysctl.conf')
        self.included_sysctl_dir_path = self._build_temp_path('/etc/sysctl.d')

        os.makedirs(os.path.dirname(self.sysctl_config_path), exist_ok=True)
        os.makedirs(self.included_sysctl_dir_path, exist_ok=True)


    def create_test_file(self, relative_path: str, contents: str = "") -> str:
        """
        Creates a file in the temporary directory.
        Can contain a string.
        Relative_path should be like '/etc/sysctl.conf'.
        """
        full_path = self._build_temp_path(relative_path)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, 'w', encoding='utf-8') as file:
            file.write(contents)
        return full_path

    def _build_temp_path(self, relative_path: str) -> str:
        """
        COnstructs a full, absolute path within the temporary directory.
        Removes leading slash from relative_path (e.g. /etc/sysctl.conf --> etc/sysctl.conf)
        """
        return os.path.join(self.temp_dir, relative_path.lstrip('/'))

    def tearDown(self):
        """
        Removes temporary testing directory after each test
        """
        shutil.rmtree(self.temp_dir)


class TestSysctlInsepctor(BaseSysctlInspectorTest):
    def test_sysctl_class_init(self):
        sysctl_inspector = SysctlInspector()

        self.assertIsInstance(sysctl_inspector, SysctlInspector)

    def test_find_default_sysctl_config_file(self):
        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf'
        )

        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=""
        )

        self.assertEqual(sysctl_inspector.config_file_paths, [sysctl_config])

class TestParsing(BaseSysctlInspectorTest):
    def test_parse_sysctl_config(self):
        sysctl_content = """
        net.ipv4.ip_unprivileged_port_start=80
        """
        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        expected_output = {
            f"{sysctl_config}": {
                "net.ipv4.ip_unprivileged_port_start": "80"
            }
        }

        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=""
        )

        self.assertEqual(sysctl_inspector.sysctl_config, expected_output)

    def test_ignore_hashtag_comments(self):
        sysctl_content = """
        # net.ipv4.ip_unprivileged_port_start=80
        """

        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        expected_output = {
            f"{sysctl_config}": {}
        }

        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=""
        )

        self.assertEqual(sysctl_inspector.sysctl_config, expected_output)

    def test_ignore_semicolon_comments(self):
        sysctl_content = """
        ; net.ipv4.ip_unprivileged_port_start=80
        """

        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        expected_output = {
            f"{sysctl_config}": {}
        }

        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=""
        )

        self.assertEqual(sysctl_inspector.sysctl_config, expected_output)

    def test_read_multiple_files(self):
        sysctl_content = """
        net.ipv4.ip_unprivileged_port_start=80
        """
        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        included_sysctl_content = """
        net.ipv4.ip_nonlocal_bind=1
        """
        included_sysctl_config = self.create_test_file(
            '/etc/sysctl.d/99-web.conf',
            contents=included_sysctl_content
        )

        expected_output = {
            f"{sysctl_config}": {
                "net.ipv4.ip_unprivileged_port_start": "80"
            },
            f"{included_sysctl_config}": {
                "net.ipv4.ip_nonlocal_bind": "1"
            }
        }

        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=self.included_sysctl_dir_path
        )

        self.assertEqual(sysctl_inspector.sysctl_config, expected_output)

class TestComparison(BaseSysctlInspectorTest):
    def test_sysctl_comparison_matching(self):
        sysctl_content = """
        net.ipv4.ip_unprivileged_port_start=80
        """
        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        target_config: Dict[str, Dict] = {
            f"{sysctl_config}": {
                "net.ipv4.ip_unprivileged_port_start": "80"
            }
        }

        
        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=""
        )
        sysctl_inspector.compare_to(target_config)

        self.assertEqual(sysctl_inspector.matching, target_config)


    def test_sysctl_multiple_files_matching(self):
        sysctl_content = """
        net.ipv4.ip_unprivileged_port_start=80
        kernel.pid_max = 4194304
        """
        sysctl_config = self.create_test_file(
            '/etc/sysctl.conf',
            contents=sysctl_content
        )

        included_content = """
        vm.swappiness = 10
        """
        included_config = self.create_test_file(
            '/etc/sysctl.d/10-test.conf',
            contents=included_content
        )

        target_config: Dict[str, Dict] = {
            f"{sysctl_config}": {
                "net.ipv4.ip_unprivileged_port_start": "80",
                "kernel.pid_max": "4194304"
            },
            f"{included_config}": {
                "vm.swappiness": "10"
            }
        }
        
        sysctl_inspector = SysctlInspector(
            sysctl_config_path=sysctl_config,
            sysctl_d_directory=self.included_sysctl_dir_path
        )
        sysctl_inspector.compare_to(target_config)

        self.assertEqual(sysctl_inspector.matching, target_config)

    def test_sysctl_compare_extra_in_actual(self):
        """
        net.ipv4.ip_forward = 1       
        kernel.pid_max = 2097152     
        fs.file-max = 6815744       
        net.ipv4.tcp_syncookies = 0
        """
        pass

    def test_sysctl_compare_multiple_extra_in_actual(self):
        pass

    def test_sysctl_compare_missing_in_actual(self):
        pass

    def test_sysctl_compare_multiple_missing_in_actual(self):
        pass

