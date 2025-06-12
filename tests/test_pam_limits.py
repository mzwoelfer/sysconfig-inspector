import unittest
import stat
import tempfile
import os
import shutil
import logging
from sysconfig_inspector.pam_limits import PamLimits

def create_test_file(base_temp_dir: str, file_relative_path: str, contents: str = ""):
    """Create a file with content in a temporary directory structure.
    file_relative_path should be like '/etc/security/limits.conf'
    """
    full_path = os.path.join(base_temp_dir, file_relative_path.lstrip(os.sep))
    
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    with open(full_path, 'w', encoding='utf-8') as f:
        f.write(contents)
    return full_path 

class BasePamLimitsTest(unittest.TestCase):
    """Base class for tests that need a temporary filesystem."""
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
        self.temp_limits_conf_path = os.path.join(self.temp_dir, 'etc', 'security', 'limits.conf')
        self.temp_limits_d_dir = os.path.join(self.temp_dir, 'etc', 'security', 'limits.d')
        self.temp_limits_d_path_pattern = os.path.join(self.temp_limits_d_dir, '*.conf')

        # Create /etc/security and /etc/security/limits.d paths
        os.makedirs(os.path.dirname(self.temp_limits_conf_path), exist_ok=True) 
        os.makedirs(self.temp_limits_d_dir, exist_ok=True)

    def tearDown(self):
        """Clean up the temporary directory after each test"""
        shutil.rmtree(self.temp_dir)


class TestPamLimits(BasePamLimitsTest):
    def test_init(self):
        pam_limits = PamLimits()
        self.assertIsInstance(pam_limits, PamLimits)


    def test_find_default_config_file(self):
        conf_file_path = create_test_file(self.temp_dir, '/etc/security/limits.conf')

        pam_limits = PamLimits(limits_conf_path=self.temp_limits_conf_path,
                               limits_d_path=self.temp_limits_d_path_pattern)
        files = pam_limits.config_file_paths

        self.assertEqual(files, [conf_file_path])


    def test_find_config_file_paths_in_subdirectory(self):
        d_file_path = create_test_file(self.temp_dir, '/etc/security/limits.d/10-test.conf')

        pam_limits = PamLimits(limits_conf_path=self.temp_limits_conf_path,
                               limits_d_path=self.temp_limits_d_path_pattern)
        files = pam_limits.config_file_paths

        self.assertEqual(files, [d_file_path])


    def test_default_and_supplementary_config_files_exist_combined(self):
        conf_file_path = create_test_file(self.temp_dir, '/etc/security/limits.conf')
        d_file_path = create_test_file(self.temp_dir, '/etc/security/limits.d/10-test.conf')

        pam_limits = PamLimits(limits_conf_path=self.temp_limits_conf_path,
                               limits_d_path=self.temp_limits_d_path_pattern)
        files = pam_limits.config_file_paths

        expected_output = [
            conf_file_path,
            d_file_path
        ]
        self.assertEqual(files, expected_output)


class TestPamLimitsParser(BasePamLimitsTest):
    """Test Parser functionality of class"""
    def test_read_limits_config(self):
        limits_config = create_test_file(self.temp_dir, '/etc/security/limits.conf', contents="""
            # Comment line
            * soft core 0
            @admin hard nofile 10240
        """)

        pam_limits = PamLimits(limits_conf_path=limits_config,
                               limits_d_path=self.temp_limits_d_path_pattern)
        pam_limits.actual_limits_config

        expected = [
            {
                "file": limits_config,
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": limits_config,
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]
        self.assertEqual(pam_limits.actual_limits_config, expected)

    def test_read_multiple_configs(self):
        supplementary_limits_config = create_test_file(self.temp_dir,
            '/etc/security/limits.d/10-test.conf', 
            contents="""
                # Comment line
                * soft core 0
                @admin hard nofile 10240
            """)
        limits_config = create_test_file(self.temp_dir,
            '/etc/security/limits.conf', 
            contents="""
                *               soft    core            0
                root            hard    core            100000
                *               hard    nofile          512
                @student        hard    nproc           20
                @faculty        soft    nproc           20
                @faculty        hard    nproc           50
                ftp             hard    nproc           0
                @student        -       maxlogins       4
                @student        -       nonewprivs      1
                :123            hard    cpu             5000
                @500:           soft    cpu             10000
                600:700         hard    locks           10
            """)

        pam_limits = PamLimits(limits_conf_path=limits_config,
                               limits_d_path=self.temp_limits_d_path_pattern)
        actual_config = pam_limits.actual_limits_config

        expected_output = [
            {
                "file": limits_config,
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0
            },
            {
                "file": limits_config,
                "domain": "root",
                "limit_type": "hard",
                "limit_item": "core",
                "value": 100000
            },
            {
                "file": limits_config,
                "domain": "*",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 512
            },
            {
                "file": limits_config,
                "domain": "@student",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 20
            },
            {
                "file": limits_config,
                "domain": "@faculty",
                "limit_type": "soft",
                "limit_item": "nproc",
                "value": 20
            },
            {
                "file": limits_config,
                "domain": "@faculty",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 50
            },
            {
                "file": limits_config,
                "domain": "ftp",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 0
            },
            {
                "file": limits_config,
                "domain": "@student",
                "limit_type": "-",
                "limit_item": "maxlogins",
                "value": 4
            },
            {
                "file": limits_config,
                "domain": "@student",
                "limit_type": "-",
                "limit_item": "nonewprivs",
                "value": 1
            },
            {
                "file": limits_config,
                "domain": ":123",
                "limit_type": "hard",
                "limit_item": "cpu",
                "value": 5000
            },
            {
                "file": limits_config,
                "domain": "@500:",
                "limit_type": "soft",
                "limit_item": "cpu",
                "value": 10000
            },
            {
                "file": limits_config,
                "domain": "600:700",
                "limit_type": "hard",
                "limit_item": "locks",
                "value": 10
            },
            {
                "file": supplementary_limits_config,
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": supplementary_limits_config,
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]

        self.assertEqual(actual_config, expected_output)


class TestLimitsComparator(BasePamLimitsTest):
    def test_limits_compare_to(self):
        limits_config = create_test_file(self.temp_dir,
            '/etc/security/limits.conf', 
            contents="""
                # Comment line
                * soft core 0
                @admin hard nofile 10240
            """)

        external_pam_limits = [
            {
                "file": limits_config,
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": limits_config,
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]

        pam_limits = PamLimits(limits_conf_path=self.temp_limits_conf_path,
                               limits_d_path=self.temp_limits_d_path_pattern)
        pam_limits.compare_to(external_pam_limits)

        self.assertEqual(pam_limits.matching_limits, external_pam_limits)


    def test_malformed_lines_return_empty_list(self):
        """
        Malformed Limits lines return empty list
        """
        limits_content = """
            user soft core
        """
        limits_file_path = create_test_file(self.temp_dir, '/etc/security/limits.conf', contents=limits_content)

        pam_limits = PamLimits(limits_conf_path=limits_file_path,
                               limits_d_path=self.temp_limits_d_path_pattern)

        self.assertEqual(pam_limits.actual_limits_config, [])

    def test_malformed_parse_limits_warns(self):
        """
        Tests that _parse_limits_entries logs a WARNING and skips
        lines that do not have the expected number of fields.
        """
        limits_content = """
            user soft core
        """
        limits_file_path = create_test_file(self.temp_dir, '/etc/security/limits.conf', contents=limits_content)

        with self.assertLogs('sysconfig_inspector.pam_limits', level='WARNING') as cm:
            pam_limits = PamLimits(limits_conf_path=limits_file_path,
                                   limits_d_path=self.temp_limits_d_path_pattern)

            self.assertEqual(pam_limits.actual_limits_config, [])
            self.assertIn(f"WARNING", cm.output[0])
            self.assertIn(f"Line 'user soft core' in '{limits_file_path}'", cm.output[0])


    def test_parse_limits_non_integer_value(self):
        """
        Test non integer values.
        From the manpage:
        All items support the values -1, unlimited or infinity
        """
        limits_content = """
            @users soft maxlogins unlimited
        """
        limits_file_path = create_test_file(
            self.temp_dir,
            '/etc/security/limits.conf',
            contents=limits_content
        )

        pam_limits = PamLimits(
            limits_conf_path=limits_file_path,
            limits_d_path=self.temp_limits_d_path_pattern
        )
        
        expected_parsed_limits = [
            {
                "file": limits_file_path,
                "domain": "@users",
                "limit_type": "soft",
                "limit_item": "maxlogins",
                "value": "unlimited", 
            },
        ]

        self.assertEqual(pam_limits.actual_limits_config, expected_parsed_limits)


if __name__ == "__main__":
    unittest.main()
