from typing import Any, List, Optional, Dict, Tuple
import os

class SysctlInspector:
    """
    Read sysctl config 
    """

    SYSCTL_CONFIG_PATH = '/etc/sysctl.conf'
    SYSCTL_D_DIRECTORY = '/etc/sysctl.d/'

    def __init__(self,
                 sysctl_config_path: Optional[str] = None,
                 sysctl_d_directory: Optional[str] = None):

        self._sysctl_config_path = sysctl_config_path if sysctl_config_path is not None else self.SYSCTL_CONFIG_PATH
        self._sysctl_d_directory = sysctl_d_directory if sysctl_d_directory is not None else self.SYSCTL_D_DIRECTORY

        self._config_file_paths: List[str] = []
        self._sysctl_config: Dict[str, Dict] = {}

        self._config_file_paths = self._discover_config_files()
        self._sysctl_config = self._parse_config_files()

        self.matching = {}
        self.missing_from_actual = {}
        self.extra_in_actual = {}

    @property
    def config_file_paths(self) -> List[str]:
        """List of discovered sysctl config files"""
        return self._config_file_paths

    @property
    def sysctl_config(self) -> Dict[str, Dict]:
        """Dictionary of all sysctl config"""
        return self._sysctl_config

    def _discover_config_files(self) -> None:
        """
        Discovers sysctl configurations files.
        """
        found_files: List[str] = []

        if os.path.isfile(self._sysctl_config_path):
            found_files.append(self._sysctl_config_path)

        sysctl_d_directory = self._sysctl_d_directory
        try:
            sysctl_d_files = os.listdir(sysctl_d_directory)
            for file in sysctl_d_files:
                full_file_path = os.path.join(sysctl_d_directory, file)
                if os.path.isfile(full_file_path):
                    found_files.append(full_file_path)
        except FileNotFoundError as e:
            print("no files in sysctl.d directory", e)

        return found_files

    def _parse_config_files(self) -> Dict[str, Dict]:
        """
        Parses all sysctl config files.
        Returns Dict: 
        {
            "/etc/sysctl.conf": {
                key: value,
                key: value,
                ...
            },
            "/etc/sysctl.d/10.conf: {
                key: value,
                ...
            }
        }
        """
        actual_config_dict = {}

        for file_path in self._config_file_paths:
            sysctl_config = SysctlConfig(file_path)
            actual_config_dict[file_path] = sysctl_config.sysctl_config

        return actual_config_dict

    def compare_to(self, target_config: Dict[str, Dict]):
        """
        Compares the target config against the read config from the system
        """

        all_filenames = sorted(
            set(self._sysctl_config.keys()) | set(target_config.keys())
        )

        for filename in all_filenames:
            actual = self.sysctl_config.get(filename, {})
            target = target_config.get(filename, {})

            matching, missing_in_actual, extra_in_actual = self._compare(actual, target)

            self.matching[filename] = matching
            self.missing_from_actual[filename] = missing_in_actual
            self.extra_in_actual[filename] = extra_in_actual


    def _compare(self, actual_config: Dict[str, Dict], target_config: Dict[str, Any]) -> Tuple[Dict[str, Dict], Dict[str, Dict], Dict[str, Dict]]:
        """
        Compares the sysctl config read from the system with a given Dictionary in the same format
        """
        matching_config: Dict[str, Any] = {}
        missing_from_actual: Dict[str, Any] = {}
        extra_in_actual: Dict[str, Any] = {}

        # --- Missing and Matching in target ---
        for key, target_value in target_config.items():
            if key not in actual_config:
                missing_from_actual[key] = target_value
            elif actual_config[key] != target_value:
                missing_from_actual[key] = target_value
            else:
                matching_config[key] = target_value

        # --- Extra in actual ---
        for key, actual_value in actual_config.items():
            if key not in target_config:
                extra_in_actual[key] = actual_value
            elif target_config[key] != actual_value and key not in missing_from_actual:
                extra_in_actual[key] = actual_value

        return matching_config, missing_from_actual, extra_in_actual
            





class SysctlConfig:
    """
    Reads a sysctl file.
    Returns a single sysctl config as Dictionary
    """
    def __init__(self,
                 sysctl_config_path: str):

        self.sysctl_config_path = sysctl_config_path

        self._file_reader = FileConfigReader()
        self.sysctl_config = self._parse_file()

    def _parse_file(self) -> Dict[str, str]:
        """
        Parses sysctl config file.
        Returns a dictionary of lines in file, without comments
        """
        file_path = self.sysctl_config_path
        raw_lines = self._file_reader.read_lines(file_path)
        cleansed_lines = self._cleanse_lines(raw_lines)
        parsed_sysctl_config = self._parse_config_lines(cleansed_lines)

        return parsed_sysctl_config

    def _cleanse_lines(self, raw_lines: List[str]) -> List[str]:
        """
        Removes comments and empty lines from sysctl config file
        """
        cleansed_lines = []

        lines = [line for line in raw_lines if line.strip()]
        for line in lines:
            work_line = line.strip()
            if work_line.startswith('#'):
                continue
            if work_line.startswith(';'):
                continue
            cleansed_lines.append(work_line)

        return cleansed_lines

    def _parse_config_lines(self, cleansed_lines: str) -> Dict[str, str]:
        parsed_config = {}

        for line in cleansed_lines:
            line = line.rstrip()
            splitline = line.split('=', maxsplit=1)
            if len(splitline) > 1:
                key = splitline[0].strip()
                value = splitline[1].strip()
                parsed_config[key] = value

        return parsed_config

    def compare_to(self, target_config: Dict[str, Any]) -> Tuple[Dict[str, Dict], Dict[str, Dict], Dict[str, Dict]]:
        """
        Compares the sysctl config read from the system with a given Dictionary in the same format
        """
        matching_config: Dict[str, Any] = {}
        missing_from_actual: Dict[str, Any] = {}
        extra_in_actual: Dict[str, Any] = {}

        # --- Missing and Matching in target ---
        for key, target_value in target_config.items():
            if key not in actual_config:
                missing_from_actual[key] = target_value
            elif actual_config[key] != target_value:
                missing_from_actual[key] = target_value
            else:
                matching_config[key] = target_value

        # --- Extra in actual ---
        for key, actual_value in actual_config.items():
            if key not in target_config:
                extra_in_actual[key] = actual_value
            elif target_config[key] != actual_value and key not in missing_from_actual:
                extra_in_actual[key] = actual_value

        return matching_config, missing_from_actual, extra_in_actual

class FileConfigReader:
    """
    Reads files from file system
    """
    def read_lines(self, file_path: str) -> List[str]:
        """
        Reads lines from a given file path.
        Return an empty list if the file is not found or cannot be read.
        """
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.readlines()
