import glob
import os
from dataclasses import dataclass, asdict
from typing import Union, List, Dict, Any, Optional

@dataclass(frozen=True)
class PamLimitEntry:
    """a PAM limits configuration entry."""
    file: str
    domain: str
    limit_type: str
    limit_item: str
    value: Union[int, str]

class PamLimits:
    """
    Inspect and compare PAM limits config

    Discovers and parses configured PAM limits.
    Can compare against a target configuration
    """

    DEFAULT_LIMITS_CONF_PATH = '/etc/security/limits.conf'
    DEFAULT_LIMITS_D_PATH = '/etc/security/limits.d/*.conf'
    EXPECTED_LIMITS_FIELDS = 4 # domain, type, item, value

    def __init__(self):
        """
        Initialize PamLimits instance.
        Discovers and parses the system's PAM limits configuration files.
        """
        self.config_file_paths: List[str] = self._discover_config_files()
        
        # Internal storage - PamLimitEntry objects
        self._actual_limits_data_internal: List[PamLimitEntry] = self._parse_all_config_files()
        
        self._matching_limits_internal: List[PamLimitEntry] = []
        self._missing_from_actual_internal: List[PamLimitEntry] = []
        self._extra_in_actual_internal: List[PamLimitEntry] = []

    @property
    def actual_limits_config(self) -> List[Dict[str, Any]]:
        return [asdict(entry) for entry in self._actual_limits_data_internal]

    @property
    def matching_limits(self) -> List[Dict[str, Any]]:
        return [asdict(entry) for entry in self._matching_limits_internal]

    @property
    def missing_from_actual(self) -> List[Dict[str, Any]]:
        return [asdict(entry) for entry in self._missing_from_actual_internal]

    @property
    def extra_in_actual(self) -> List[Dict[str, Any]]:
        """
        List of extra PAM limit entries in actual config as dictionaries.
        """
        return [asdict(entry) for entry in self._extra_in_actual_internal]

    def compare_to(self, target_limits_data_dicts: List[Dict[str, Any]]):
        """
        Compare PAM limits config with a target configuration.
        Target config is a list of dicitonaries, resembling the PamLimitEntry.

        Populates internal 'matching_limits', 'missing_from_actual', and 'extra_in_actual' lists.
        """
        target_limits_entries = self._convert_dicts_to_pam_limit_entries(target_limits_data_dicts)

        actual_limits_set = set(self._actual_limits_data_internal)
        target_limits_set = set(target_limits_entries)

        matching_set = actual_limits_set & target_limits_set
        missing_set = target_limits_set - actual_limits_set
        extra_set = actual_limits_set - target_limits_set

        self._matching_limits_internal = self._sort_limits_data(list(matching_set))
        self._missing_from_actual_internal = self._sort_limits_data(list(missing_set))
        self._extra_in_actual_internal = self._sort_limits_data(list(extra_set))

    def _discover_config_files(self) -> List[str]:
        """
        Discover PAM limits configuration files on the system.

        Returns:
            list: List of absolute file paths to configuration files.
        """
        found_files: List[str] = []
        if os.path.isfile(self.DEFAULT_LIMITS_CONF_PATH):
            found_files.append(self.DEFAULT_LIMITS_CONF_PATH)
            
        found_files.extend(glob.glob(self.DEFAULT_LIMITS_D_PATH))
        return found_files

    def _parse_all_config_files(self) -> List[PamLimitEntry]:
        """
        Parse discovered PAM limits configuration files.

        Returns:
            List[PamLimitEntry]: List of PamLimitEntry objects.
        """
        all_parsed_limits: List[PamLimitEntry] = []
        for file_path in self.config_file_paths:
            raw_lines = self._read_file_content(file_path)
            clean_lines = self._cleanse_config_lines(raw_lines)
            parsed_entries = self._parse_limits_entries(clean_lines, file_path)
            all_parsed_limits.extend(parsed_entries)
        return all_parsed_limits

    def _parse_limits_entries(self, sanitized_lines: List[str], filename: str) -> List[PamLimitEntry]:
        """
        Parses PAM limits entries from a list of sanitized lines.

        Returns:
            List[PamLimitEntry]: List of PamLimitEntry objects.
        """
        parsed_entries: List[PamLimitEntry] = []
        for line in sanitized_lines:
            parts = line.split(None, self.EXPECTED_LIMITS_FIELDS)
            
            if len(parts) != self.EXPECTED_LIMITS_FIELDS:
                print(f"WARNING: Line '{line}' in '{filename}' does not match expected format. Skipping.")
                continue

            domain, limit_type, limit_item, raw_value = parts

            try:
                value: Union[int, str] = int(raw_value)
            except ValueError:
                value = raw_value  

            parsed_entries.append(PamLimitEntry(
                file=filename,
                domain=domain,
                limit_type=limit_type,
                limit_item=limit_item,
                value=value,
            ))
        return parsed_entries

    def _cleanse_config_lines(self, config_lines: List[str]) -> List[str]:
        """
        Remove comments and empty lines from a list of raw configuration lines.
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

        Raises:
            IOError: If the file cannot be read.
        """
        try:
            with open(path, 'rt', encoding='utf-8') as f:
                return f.readlines()
        except IOError as e:
            print(f"ERROR: Could not read file '{path}': {e}")
            return []

    def _sort_limits_data(self, limits_list: List[PamLimitEntry]) -> List[PamLimitEntry]:
        """
        Sorts PAM limits list.
        """
        return sorted(limits_list, key=lambda x: (
            x.file,
            x.domain,
            x.limit_item,
            x.limit_type
        ))

    @staticmethod
    def _convert_dicts_to_pam_limit_entries(data_dicts: List[Dict[str, Any]]) -> List[PamLimitEntry]:
        """
        Converts a list of dictionaries into a list of PamLimitEntry objects.
        """
        converted_entries: List[PamLimitEntry] = []
        for d in data_dicts:
            try:
                value: Union[int, str]
                try:
                    value = int(d['value'])
                except (ValueError, TypeError): 
                    value = str(d['value']) 

                converted_entries.append(PamLimitEntry(
                    file=d['file'],
                    domain=d['domain'],
                    limit_type=d['limit_type'],
                    limit_item=d['limit_item'],
                    value=value
                ))
            except KeyError as e:
                print(f"WARNING: Dictionary is missing expected key for PamLimitEntry: {e}. Skipping entry: {d}")
            except Exception as e:
                print(f"WARNING: Could not convert dictionary to PamLimitEntry. Error: {e}. Skipping entry: {d}")
        return converted_entries
