import unittest
from pyfakefs.fake_filesystem_unittest import TestCase
from sysconfig_inspector.pam_limits import PamLimits

class TestPamLimits(TestCase):
    def setUp(self):
        self.setUpPyfakefs()  # initialize fake fs


    def test_init(self):
        pam_limits = PamLimits()
        self.assertIsInstance(pam_limits, PamLimits)


    def test_find_default_limits_config_path(self):
        self.fs.create_file('/etc/security/limits.conf')

        pam_limits = PamLimits()
        files = pam_limits.limits_config_files

        self.assertEqual(files, ['/etc/security/limits.conf'])


    def test_find_limits_config_files_in_subdirectory(self):
        self.fs.create_dir('/etc/security/limits.d')
        self.fs.create_file('/etc/security/limits.d/10-test.conf')

        pam_limits = PamLimits()
        files = pam_limits.limits_config_files

        self.assertEqual(files, ['/etc/security/limits.d/10-test.conf'])


    def test_find_default_and_supplementery_config_files(self):
        self.fs.create_dir('/etc/security/')
        self.fs.create_dir('/etc/security/limits.d')
        self.fs.create_file('/etc/security/limits.d/10-test.conf')
        self.fs.create_file('/etc/security/limits.conf')

        pam_limits = PamLimits()
        files = pam_limits.limits_config_files

        expected_output = [
            '/etc/security/limits.conf',
            '/etc/security/limits.d/10-test.conf'
        ]
        self.assertEqual(files, expected_output)

class TestPamLimitsParser(TestCase):
    """Test Parser functionality of class"""
    def setUp(self):
        self.setUpPyfakefs()  

    def test_read_limits_config(self):
        self.fs.create_file('/etc/security/limits.conf', contents="""
            # Comment line
            * soft core 0
            @admin hard nofile 10240
        """)

        pam_limits = PamLimits()
        pam_limits.actual_config

        expected = [
            {
                "file": "/etc/security/limits.conf",
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]
        self.assertEqual(pam_limits.actual_config, expected)

    def test_read_multiple_configs(self):
        self.fs.create_file(
            '/etc/security/limits.d/10-test.conf', 
            contents="""
                # Comment line
                * soft core 0
                @admin hard nofile 10240
            """)
        self.fs.create_file(
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

        pam_limits = PamLimits()
        actual_config = pam_limits.actual_config

        expected_output = [
            {
                "file": "/etc/security/limits.conf",
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "root",
                "limit_type": "hard",
                "limit_item": "core",
                "value": 100000
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "*",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 512
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@student",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 20
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@faculty",
                "limit_type": "soft",
                "limit_item": "nproc",
                "value": 20
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@faculty",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 50
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "ftp",
                "limit_type": "hard",
                "limit_item": "nproc",
                "value": 0
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@student",
                "limit_type": "-",
                "limit_item": "maxlogins",
                "value": 4
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@student",
                "limit_type": "-",
                "limit_item": "nonewprivs",
                "value": 1
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": ":123",
                "limit_type": "hard",
                "limit_item": "cpu",
                "value": 5000
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@500:",
                "limit_type": "soft",
                "limit_item": "cpu",
                "value": 10000
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "600:700",
                "limit_type": "hard",
                "limit_item": "locks",
                "value": 10
            },
            {
                "file": "/etc/security/limits.d/10-test.conf",
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": "/etc/security/limits.d/10-test.conf",
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]

        self.assertEqual(actual_config, expected_output)


class TestLimitsComparator(TestCase):
    def setUp(self):
        self.setUpPyfakefs()  

    def test_limits_compare_to(self):
        self.fs.create_file(
            '/etc/security/limits.conf', 
            contents="""
                # Comment line
                * soft core 0
                @admin hard nofile 10240
            """)

        external_pam_limits = [
            {
                "file": "/etc/security/limits.conf",
                "domain": "*",
                "limit_type": "soft",
                "limit_item": "core",
                "value": 0,
            },
            {
                "file": "/etc/security/limits.conf",
                "domain": "@admin",
                "limit_type": "hard",
                "limit_item": "nofile",
                "value": 10240,
            }
        ]

        pam_limits = PamLimits()
        pam_limits.compare_to(external_pam_limits)

        self.assertEqual(pam_limits.matching_config, external_pam_limits)


if __name__ == "__main__":
    unittest.main()
