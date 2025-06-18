import unittest
import os
import tempfile
import shutil
from typing import Dict, Any

from sysconfig_inspector.common.config_readers import FileConfigReader
from sysconfig_inspector.common.config_comparators import DictComparator
from sysconfig_inspector.sysctl import SysctlFileReader, SysctlInspector 

class TestSysctlInspectorIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_etc_dir = os.path.join(self.temp_dir, 'etc')
        self.temp_sysctl_conf_path = os.path.join(self.temp_etc_dir, 'sysctl.conf')
        self.temp_sysctld_dir = os.path.join(self.temp_etc_dir, 'sysctl.d')

        os.makedirs(self.temp_sysctld_dir, exist_ok=True) 

        self.file_reader = FileConfigReader()
        self.sysctl_file_reader = SysctlFileReader(self.file_reader)
        self.dict_comparator = DictComparator()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _write_file(self, file_path: str, content: str):
        """Helper to write content to a file, creating parent dirs if needed."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def test_full_sysctl_comparison_perfect_match(self):
        """
        Tests SysctlInspector with real file system interaction for a perfect match.
        """
        self._write_file(self.temp_sysctl_conf_path, """
            # Main sysctl config
            net.ipv4.ip_forward = 1
            kernel.pid_max = 4194304
            fs.file-max = 6815744
        """)
        self._write_file(os.path.join(self.temp_sysctld_dir, '10-network.conf'), """
            # Network specific settings
            net.core.somaxconn = 65536
            net.ipv4.tcp_tw_reuse = yes
        """)
        self._write_file(os.path.join(self.temp_sysctld_dir, '99-custom.conf'), """
            # Custom application settings
            vm.swappiness = 10
        """)

        target_config: Dict[str, Any] = {
            "net.ipv4.ip_forward": 1,
            "kernel.pid_max": 4194304,
            "fs.file-max": 6815744,
            "net.core.somaxconn": 65536,
            "net.ipv4.tcp_tw_reuse": True,
            "vm.swappiness": 10,
            "files": {
                self.temp_sysctl_conf_path: {
                    "net.ipv4.ip_forward": 1,
                    "kernel.pid_max": 4194304,
                    "fs.file-max": 6815744
                },
                os.path.join(self.temp_sysctld_dir, '10-network.conf'): {
                    "net.core.somaxconn": 65536,
                    "net.ipv4.tcp_tw_reuse": True
                },
                os.path.join(self.temp_sysctld_dir, '99-custom.conf'): {
                    "vm.swappiness": 10
                }
            }
        }

        inspector = SysctlInspector(
            sysctl_file_reader=self.sysctl_file_reader,
            config_comparator=self.dict_comparator,
            main_config_path=self.temp_sysctl_conf_path,
            drop_in_dir_path=self.temp_sysctld_dir
        )

        inspector.compare_to(target_config)

        self.assertEqual(inspector.matching_config, {
            "net.ipv4.ip_forward": 1,
            "kernel.pid_max": 4194304,
            "fs.file-max": 6815744,
            "net.core.somaxconn": 65536,
            "net.ipv4.tcp_tw_reuse": True,
            "vm.swappiness": 10
        })
        self.assertEqual(inspector.missing_from_actual, {})
        self.assertEqual(inspector.extra_in_actual, {})

        expected_detailed_results = {
            self.temp_sysctl_conf_path: {
                "matching_config": {
                    "net.ipv4.ip_forward": 1,
                    "kernel.pid_max": 4194304,
                    "fs.file-max": 6815744
                },
                "not_in_actual_config": {},
                "not_in_target_config": {}
            },
            os.path.join(self.temp_sysctld_dir, '10-network.conf'): {
                "matching_config": {
                    "net.core.somaxconn": 65536,
                    "net.ipv4.tcp_tw_reuse": True
                },
                "not_in_actual_config": {},
                "not_in_target_config": {}
            },
            os.path.join(self.temp_sysctld_dir, '99-custom.conf'): {
                "matching_config": {
                    "vm.swappiness": 10
                },
                "not_in_actual_config": {},
                "not_in_target_config": {}
            }
        }
        self.assertEqual(inspector.detailed_comparison_results, expected_detailed_results)

    def test_full_sysctl_comparison_with_differences(self):
        """
        Tests SysctlInspector with real file system interaction for a scenario
        with missing, extra, and differing values.
        """
        self._write_file(self.temp_sysctl_conf_path, """
            net.ipv4.ip_forward = 1       # Matches target
            kernel.pid_max = 2097152      # Differs from target (target wants 4194304)
            fs.file-max = 6815744         # Matches target
            net.ipv4.tcp_syncookies = 0   # Extra in actual (not in target)
        """)
        self._write_file(os.path.join(self.temp_sysctld_dir, '10-network.conf'), """
            net.core.somaxconn = 32768    # Differs from target (target wants 65536)
        """)

        target_config: Dict[str, Any] = {
            "net.ipv4.ip_forward": 1,
            "kernel.pid_max": 4194304, 
            "fs.file-max": 6815744,
            "net.core.somaxconn": 65536, 
            "vm.swappiness": 10, 

            "files": { 
                self.temp_sysctl_conf_path: {
                    "net.ipv4.ip_forward": 1,
                    "kernel.pid_max": 4194304,
                    "fs.file-max": 6815744
                },
                os.path.join(self.temp_sysctld_dir, '10-network.conf'): {
                    "net.core.somaxconn": 65536
                },
                os.path.join(self.temp_sysctld_dir, '99-custom.conf'): { 
                    "vm.swappiness": 10
                }
            }
        }

        inspector = SysctlInspector(
            sysctl_file_reader=self.sysctl_file_reader,
            config_comparator=self.dict_comparator,
            main_config_path=self.temp_sysctl_conf_path,
            drop_in_dir_path=self.temp_sysctld_dir
        )

        inspector.compare_to(target_config)

        self.assertEqual(inspector.matching_config, {
            "net.ipv4.ip_forward": 1,
            "fs.file-max": 6815744 
        })
        self.assertEqual(inspector.missing_from_actual, {
            "kernel.pid_max": 4194304, 
            "net.core.somaxconn": 65536, 
            "vm.swappiness": 10 
        })
        self.assertEqual(inspector.extra_in_actual, {
            "kernel.pid_max": 2097152, 
            "net.ipv4.tcp_syncookies": 0, 
            "net.core.somaxconn": 32768 
        })


        expected_detailed_results = {
            self.temp_sysctl_conf_path: {
                "matching_config": {
                    "net.ipv4.ip_forward": 1,
                    "fs.file-max": 6815744
                },
                "not_in_actual_config": {
                    "kernel.pid_max": 4194304 
                },
                "not_in_target_config": {
                    "kernel.pid_max": 2097152, 
                    "net.ipv4.tcp_syncookies": 0 
                }
            },
            os.path.join(self.temp_sysctld_dir, '10-network.conf'): {
                "matching_config": {},
                "not_in_actual_config": {
                    "net.core.somaxconn": 65536
                },
                "not_in_target_config": {
                    "net.core.somaxconn": 32768
                }
            },
            os.path.join(self.temp_sysctld_dir, '99-custom.conf'): {
                "matching_config": {},
                "not_in_actual_config": {
                    "vm.swappiness": 10
                },
                "not_in_target_config": {}
            }
        }
        self.assertEqual(inspector.detailed_comparison_results, expected_detailed_results)
