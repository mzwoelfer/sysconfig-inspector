import glob
import os
from typing import List, Dict, Any, Union, Optional

class PamLimits:
    """
    Inspect and compare PAM limits config

    Discovers and parses currently configured PAM limits.
    Can compare against a target configuration
    """

    DEFAULT_LIMITS_CONF_PATH = '/etc/security/limits.conf'
    DEFAULT_LIMITS_D_PATH = '/etc/security/limits.d/*.conf'
    EXPECTED_LIMITS_FIELDS = 4 # domain, type, item, value

    def __init__(self, limits_conf_path: Optional[str] = None, limits_d_path: Optional[str] = None):
        """
        Initialize PamLimits instance.
        Discovers and parses the system's PAM limits configuration files.
        """
        self._limits_conf_path = limits_conf_path if limits_conf_path is not None else self.DEFAULT_LIMITS_CONF_PATH
        self._limits_d_path = limits_d_path if limits_d_path is not None else self.DEFAULT_LIMITS_D_PATH

        self.config_file_paths: List[str] = self._discover_config_files()
        
        self.actual_limits_config: List[Dict[str, Any]] = self._parse_all_config_files()
        
        self.matching_limits: List[Dict[str, Any]] = []
        self.missing_from_actual: List[Dict[str, Any]] = []
        self.extra_in_actual: List[Dict[str, Any]] = []

    def compare_to(self, target_limits_data: List[Dict[str, Any]]):
        """
        Compare PAM limits configuration with a provided target configuration.

        The target configuration is expected as a list of dictionaries.

        Populates 'matching_limits', 'missing_from_actual', and 'extra_in_actual' lists.

        Args:
            target_limits_data (List[Dict[str, Any]]): List of dictionaries,
                                                        each representing a target limit entry.
        """
        # Convert lists of dicts to sets of frozensets for efficient comparison
        # This is necessary because dicts are not hashable by default.
        actual_limits_set = {frozenset(d.items()) for d in self.actual_limits_config}
        target_limits_set = {frozenset(d.items()) for d in target_limits_data}

        matching_frozenset = actual_limits_set & target_limits_set
        missing_frozenset = target_limits_set - actual_limits_set
        extra_frozenset = actual_limits_set - target_limits_set

        # Convert frozensets back to lists of dictionaries
        self.matching_limits = self._sort_limits_data([dict(fs) for fs in matching_frozenset])
        self.missing_from_actual = self._sort_limits_data([dict(fs) for fs in missing_frozenset])
        self.extra_in_actual = self._sort_limits_data([dict(fs) for fs in extra_frozenset])

    def _discover_config_files(self) -> List[str]:
        """
        Discover all PAM limits configuration files on the system.

        Returns:
            list: List of absolute file paths to the discovered configuration files.
        """
        found_files: List[str] = []
        if os.path.isfile(self._limits_conf_path):
            found_files.append(self._limits_conf_path)
            
        found_files.extend(glob.glob(self._limits_d_path))
        return found_files

    def _parse_all_config_files(self) -> List[Dict[str, Any]]:
        """
        Parses all discovered PAM limits configuration files.

        Returns:
            List[Dict[str, Any]]: List of dictionaries, each representing a parsed limit entry.
        """
        all_parsed_limits: List[Dict[str, Any]] = []
        for file_path in self.config_file_paths:
            raw_lines = self._read_file_content(file_path)
            clean_lines = self._cleanse_config_lines(raw_lines)
            parsed_entries = self._parse_limits_entries(clean_lines, file_path)
            all_parsed_limits.extend(parsed_entries)
        return all_parsed_limits

    def _parse_limits_entries(self, sanitized_lines: List[str], filename: str) -> List[Dict[str, Any]]:
        """
        Parses PAM limits entries from a list of sanitized lines.

        Args:
            sanitized_lines (list): List of cleaned strings, each representing
                                    a PAM limit rule.
            filename (str): Name of the file from which these lines were read.

        Returns:
            List[Dict[str, Any]]: List of dictionaries, each representing a parsed limit entry.
        """
        parsed_entries: List[Dict[str, Any]] = []
        for line in sanitized_lines:
            parts = line.split(None, self.EXPECTED_LIMITS_FIELDS)
            
            if len(parts) != self.EXPECTED_LIMITS_FIELDS:
                print(f"WARNING: Line '{line}' in '{filename}' does not match expected format. Skipping.")
                continue

            domain, limit_type, limit_item, raw_value = parts

            try:
                value: Union[int, str] = int(raw_value)
            except ValueError:
                value = raw_value  # Keep as string if not an integer

            parsed_entries.append({
                "file": filename,
                "domain": domain,
                "limit_type": limit_type,
                "limit_item": limit_item,
                "value": value,
            })
        return parsed_entries

    def _cleanse_config_lines(self, config_lines: List[str]) -> List[str]:
        """
        Remove comments and empty lines from a list of raw configuration lines.

        Args:
            config_lines (list): List of raw strings read from a configuration file.

        Returns:
            list: List of strings without comments and empty lines.
        """
        clean_lines: List[str] = []
        for line in config_lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue
            clean_lines.append(stripped_line)
        return clean_lines

    def _read_file_content(self, path: str) -> List[str]:
        """
        Reads lines from a config file.

        Args:
            path (str): The absolute path to the file.

        Returns:
            list: A list of strings, where each string is a line from the file.
            
        Raises:
            IOError: If the file cannot be read.
        """
        try:
            with open(path, 'rt', encoding='utf-8') as f:
                return f.readlines()
        except IOError as e:
            print(f"ERROR: Could not read file '{path}': {e}")
            return []

    def _sort_limits_data(self, limits_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts PAM limits list.

        Args:
            limits_list (List[Dict[str, Any]]): List of dictionaries.

        Returns:
            List[Dict[str, Any]]: The sorted list of dictionaries.
        """
        # Use .get() with default empty string for robustness, as dicts don't guarantee keys
        return sorted(limits_list, key=lambda x: (
            x.get('file', ''),
            x.get('domain', ''),
            x.get('limit_item', ''),
            x.get('limit_type', '')
        ))
