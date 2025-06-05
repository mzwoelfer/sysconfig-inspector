import glob
import os
from dataclasses import dataclass, asdict # Import asdict
from typing import Union, List, Dict # Import Dict for dictionary type hints

@dataclass(frozen=True)
class PamLimitEntry:
    """Represents a single PAM limits configuration entry."""
    file: str
    domain: str
    limit_type: str
    limit_item: str
    value: Union[int, str]

class PamLimits:
    """
    Inspect and compare PAM limits config

    Discovers and parses currently configured PAM limits.
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
        self.config_file_paths = self._discover_config_files()
        self.actual_limits_config: List[PamLimitEntry] = self._parse_all_config_files()
        
        # These lists will hold dictionaries after comparison
        self.matching_limits: List[Dict[str, Union[str, int]]] = []
        self.missing_from_actual: List[Dict[str, Union[str, int]]] = []
        self.extra_in_actual: List[Dict[str, Union[str, int]]] = []

    def compare_to(self, target_limits_data: List[PamLimitEntry]):
        """
        Compare PAM limits configuration with a provided target configuration.

        Populates 'matching_limits', 'missing_from_actual', and 'extra_in_actual' lists
        with dictionary representations of the limits.

        Args:
            target_limits_data (List[PamLimitEntry]): List of PamLimitEntry objects.
        """
        # Since PamLimitEntry is a frozen dataclass, it's hashable and comparable by value,
        # so we can directly convert lists to sets for efficient comparison.
        actual_limits_set = set(self.actual_limits_config)
        target_limits_set = set(target_limits_data)

        matching_set = actual_limits_set & target_limits_set
        missing_set = target_limits_set - actual_limits_set
        extra_set = actual_limits_set - target_limits_set

        # Convert PamLimitEntry objects back to dictionaries before assigning
        # to the public result attributes.
        self.matching_limits = self._sort_limits_data_to_dicts(list(matching_set))
        self.missing_from_actual = self._sort_limits_data_to_dicts(list(missing_set))
        self.extra_in_actual = self._sort_limits_data_to_dicts(list(extra_set))

    def _discover_config_files(self) -> List[str]:
        """
        Discover all PAM limits configuration files on the system.

        Returns:
            list: List of absolute file paths to the discovered configuration files.
        """
        found_files: List[str] = []
        if os.path.isfile(self.DEFAULT_LIMITS_CONF_PATH):
            found_files.append(self.DEFAULT_LIMITS_CONF_PATH)
            
        found_files.extend(glob.glob(self.DEFAULT_LIMITS_D_PATH))
        return found_files

    def _parse_all_config_files(self) -> List[PamLimitEntry]:
        """
        Parses all discovered PAM limits configuration files.

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

        Args:
            sanitized_lines (list): List of cleaned strings, each representing
                                    a PAM limit rule.
            filename (str): Name of the file from which these lines were read.

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
                value = raw_value  # Keep as string if not an integer

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

    def _sort_limits_data(self, limits_list: List[PamLimitEntry]) -> List[PamLimitEntry]:
        """
        Sorts PAM limits list. This helper remains for internal sorting of PamLimitEntry objects.

        Args:
            limits_list (List[PamLimitEntry]): List of PamLimitEntry objects.

        Returns:
            List[PamLimitEntry]: The sorted list of PamLimitEntry objects.
        """
        return sorted(limits_list, key=lambda x: (
            x.file,
            x.domain,
            x.limit_item,
            x.limit_type
        ))

    def _sort_limits_data_to_dicts(self, limits_list: List[PamLimitEntry]) -> List[Dict[str, Union[str, int]]]:
        """
        Sort PAM limits list.
        Convert PamLimitEntry to dictionaries.

        Args:
            limits_list (List[PamLimitEntry]): List of PamLimitEntry objects.

        Returns:
            List[Dict[str, Union[str, int]]]: The sorted list of dictionaries.
        """
        sorted_entries = self._sort_limits_data(limits_list) 
        return [asdict(entry) for entry in sorted_entries] 
