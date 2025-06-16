import os
import glob
import logging
from typing import Any, Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class SSHDInspector():
    """
    Parses and inspects SSHD (sshd_config) configuration files.
    """

    # --- CONSTANTS ---
    SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'

    def __init__(self, 
                 sshd_config_path: Optional[str] = None):
        """
        Initializes the SSHInspector with specified or default configuration paths.

        ARGS:
            sshd_config_path (str, optional): sshd_config file
        """
        self._file_reader = FileConfigReader()
        self._comparator = SSHDConfigComparator()

        self._sshd_config_path = sshd_config_path if sshd_config_path is not None else self.SSHD_CONFIG_PATH
        self._config_file_paths: List[str] = []
        self._sshd_config: Dict [str, Any] = {}

        self._discover_and_load_configs()

        self.matching_config: Dict[str, Any] = {}
        self.missing_from_actual: Dict[str, Any] = {}
        self.extra_in_actual: Dict[str, Any] = {}

    @property
    def config_file_paths(self) -> List[str]:
        """List of discovered SSH config files"""
        return self._config_file_paths

    @property
    def sshd_config(self) -> Dict[str, Any]:
        """Parsed SSHD config as dictionary"""
        return self._sshd_config

    def compare_to(self, target_sshd_config: Dict[str, Any]) -> None:
        """
        Compares external sshd config with actual config.
        Populates:
            self.matching_config
            self.missing_from_actual
            self.extra_in_actual
        Compares the actual parsed sshd_config with a target_sshd_config.
        """
        self.matching_config, self.missing_from_actual, self.extra_in_actual = self._comparator.compare(self.sshd_config, target_sshd_config)


    # --- CORE CONFIG LOADING ---
    def _discover_and_load_configs(self) -> None:
        """
        Discovers SSHD config files and loadsthe sshd_config.
        """
        self._discover_config_files()
        self._load_and_parse_sshd_config()
    
    def _discover_config_files(self) -> None:
        """
        Discovers SSHD configurations files.
        """
        found_files: List[str] = []

        if os.path.isfile(self._sshd_config_path):
            found_files.append(self._sshd_config_path)

        self._config_file_paths = found_files

    def _load_and_parse_sshd_config(self) -> None:
        """
        Reads, cleanses and parses the main SSHD config file.
        """

        raw_lines = self._file_reader.read_lines(self._sshd_config_path)
        sanitized_lines = SSHDConfigCleaner.cleanse_lines(raw_lines)
        self._sshd_config = self._parse_sshd_config_lines(sanitized_lines)


    # --- PARSING LOGIC ---
    def _parse_sshd_config_lines(self, config_lines: List[str]) -> Dict[str, Any]:
        """
        Parses a list of sanitized sshd_config lines. 
        Applies "First value wins".

        Return a dictionary.
        """
        parsed_config: Dict[str, Any] = {}
        match_blocks: List[Dict[str, Any]] = []

        current_match_criteria: Optional[str] = None
        current_match_lines: List[str] = []

        for line in config_lines:
            directive_type = self._get_directive_type(line)

            if directive_type == 'match':
                if current_match_criteria:
                    block = self._build_match_block(current_match_criteria, current_match_lines)
                    match_blocks.append(block)

                current_match_criteria = self._extract_match_criteria(line)
                current_match_lines = []
                continue

            if current_match_criteria is not None:
                current_match_lines.append(line)
                continue

            self._handle_global_directive(line, parsed_config)

            
        if current_match_criteria:
            match_blocks.append(self._build_match_block(current_match_criteria, current_match_lines))

        if match_blocks:
            parsed_config["Match"] = match_blocks

        return parsed_config

    def _get_directive_type(self, line: str) -> str:
        """Determines the type of sshd directive based on the first word of the line.
        """
        first_word = line.lower().split(None, 1)[0] if line.strip() else ''
        if first_word == 'match':
            return 'match'
        if first_word == 'include':
            return 'include'
        return 'other'

    def _extract_match_criteria(self, line: str) -> str:
        """Extracts the criteria string from a 'Match' line"""
        parts = line.split(None, 1)
        current_match_criteria = parts[1].strip()

        return current_match_criteria


    def _handle_global_directive(self, line: str, parsed_config: Dict[str, Any]) -> None:
        """
        Parses a sshd config line.
        """
        key, value = self._parse_directive_line(line)
        if key and key not in parsed_config:
            parsed_config[key] = value

    def _parse_included_files(self, pattern: str) -> Dict[str, Any]:
        """
        Reads and parses configuration from files matching a given glob pattern.
        Handles nested 'Include' directives through recursion.
        """
        combined_included_config: Dict[str, Any] = {}

        for file_path in glob.glob(pattern):
            raw_lines = self._file_reader.read_lines(file_path)
            sanitized_lines = SSHDConfigCleaner.cleanse_lines(raw_lines)
            
            parsed_file_config = self._parse_sshd_config_lines(sanitized_lines)

            if "Match" in parsed_file_config:
                included_matches = parsed_file_config.pop("Match")
                if "Match" not in combined_included_config:
                    combined_included_config["Match"] = []
                combined_included_config["Match"].extend(included_matches)

            for key, value in parsed_file_config.items():
                if key not in combined_included_config:
                    combined_included_config[key] = value

        return combined_included_config

    def _parse_directive_line(self, line: str) -> Tuple[str, Any]:
        """
        Parses a generic SSH config line (key-value pair).
        Casts integers and booleans.
        "22" --> 22
        (yes/no) --> True/False
        """
        directive = line.lower().split(None, 1)[0]
        if directive == 'subsystem':
            return self._parse_subsystem_line(line)
        if directive == 'acceptenv':
            return self._parse_acceptenv_line(line)

        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value_raw = parts[1].strip().strip('"')

            try:
                value = int(value_raw)
            except ValueError:
                if value_raw.lower() == "yes":
                    value = True
                elif value_raw.lower() == "no":
                    value = False
                else:
                    # keep string: e.g. PermitRootLogin prohibit-password
                    value = value_raw

            return key, value
        elif len(parts) == 1:
            return parts[0].strip(), None

    def _parse_subsystem_line(self, line: str) -> Tuple[str, str]:

        """
        Parses a subsystem line.
        Example: Subsystem sftp /usr/lib/openssh/sftp-server
        Returns: "Subsystem sftp": "/usr/lib/openssh/sftp-server"
        """
        parts = line.split(None, 2)
        if len(parts) == 3:
            key = f"{parts[0]} {parts[1]}"
            value = parts[2].strip()
            return key, value

    def _parse_acceptenv_line(self, line: str) -> Tuple[str, str]:

        """
        Parses a AcceptEnv line.
        Example: AcceptEnv LANG LC_*
        Returns: "AcceptEnv": "LANG LC_*"
        """
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            return key, value

    def _build_match_block(self, criteria: str, config_lines: List[str]) -> Dict:
        """
        Prases configuration lines iwthin a Matchblock.
        """
        settings = {}

        for line in config_lines:
            key, value = self._parse_directive_line(line)
            if key:
                settings[key] = value
        
        match_block = {
            "criterium": criteria,
            "settings": settings
        }

        return match_block


class FileConfigReader:
    """
    Reads files from file system
    """
    def read_lines(self, file_path: str) -> List[str]:
        """
        Reads lines from a given file path.
        Return an empty list if the file is not found or cannot be read.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.readlines()
        except IOError as e:
            logger.error(f"ERROR: Could not read file '{file_path}': {e}")
            return []

class SSHDConfigCleaner:
    @staticmethod
    def cleanse_lines(raw_lines: List[str]) -> List[str]:
        """
        Removes empty lines and comments from a list of raw config lines.
        """

        lines = [line for line in raw_lines if line.strip()]
        lines = [line for line in lines if not line.strip().startswith("#")]

        return lines


class SSHDConfigComparator:
    def compare(self, actual_config: Dict[str, Any], target_sshd_config: Dict[str, Any]) -> Tuple[Dict, Dict, Dict]:
        """
        Compare 2 parsed SSHD configuration dictionaries
        """
        matching_config = {}
        missing_from_actual = {}
        extra_in_actual = {}

        for target_key, target_value in target_sshd_config.items():
            if target_key == "Match": 
                continue 

            if target_key in actual_config:
                if actual_config[target_key] == target_value:
                    matching_config[target_key] = target_value
                else:
                    missing_from_actual[target_key] = target_value
                    extra_in_actual[target_key] = actual_config[target_key]
            else:
                missing_from_actual[target_key] = target_value

        for actual_key, actual_value in actual_config.items():
            if actual_key == "Match": 
                continue 

            if actual_key not in target_sshd_config:
                extra_in_actual[actual_key] = actual_value

        actual_matches = actual_config.get("Match", [])
        target_matches = target_sshd_config.get("Match", [])

        matched_blocks, missing_blocks, extra_blocks = self._compare_match_block_lists(actual_matches, target_matches)

        if matched_blocks != []:
            matching_config["Match"] = matched_blocks
        if missing_blocks != []:
            missing_from_actual["Match"] = missing_blocks
        if extra_blocks != []:
            extra_in_actual["Match"] = extra_blocks
        
        return matching_config, missing_from_actual, extra_in_actual


    def _compare_match_block_lists(self, actual_matches: List[Dict], target_matches: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        matched_match_blocks = []
        missing_match_blocks = []
        extra_match_blocks = []

        actual_matches_map = {block["criterium"]: block["settings"] for block in actual_matches}
        target_matches_map = {block["criterium"]: block["settings"] for block in target_matches}

        all_criteria = set(actual_matches_map.keys()) | set(target_matches_map.keys())

        for criterium in all_criteria:
            actual_settings = actual_matches_map.get(criterium)
            target_settings = target_matches_map.get(criterium)

            current_missing_settings = {}
            current_extra_settings = {}
            current_matched_settings = {}

            all_settings_keys = set(actual_settings.keys() if actual_settings else []) | \
                                    set(target_settings.keys() if target_settings else [])

            for setting_key in all_settings_keys:
                actual_setting_value = actual_settings.get(setting_key) if actual_settings else None
                target_setting_value = target_settings.get(setting_key) if target_settings else None

                if actual_setting_value == target_setting_value:
                    if actual_setting_value is not None:
                        current_matched_settings[setting_key] = actual_setting_value
                else:
                    if target_setting_value is not None:
                        current_missing_settings[setting_key] = target_setting_value
                    if actual_setting_value is not None:
                        current_extra_settings[setting_key] = actual_setting_value

            if current_matched_settings:
                matched_match_blocks.append({"criterium": criterium, "settings": current_matched_settings})
            
            if current_missing_settings:
                missing_match_blocks.append({"criterium": criterium, "settings": current_missing_settings})
            
            if current_extra_settings:
                extra_match_blocks.append({"criterium": criterium, "settings": current_extra_settings})

        return matched_match_blocks, missing_match_blocks, extra_match_blocks

