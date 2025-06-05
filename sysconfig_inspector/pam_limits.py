import glob
import os

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
        self.actual_limits_config = self._parse_all_config_files()
        
        self.matching_limits = []
        self.missing_from_actual = []
        self.extra_in_actual = []

    def compare_to(self, target_limits_data):
        """
        Compare PAM limits configuration with a provided target configuration.

        Populates 'matching_limits', 'missing_from_actual', and 'extra_in_actual' lists.

        Args:
            target_limits_data (list of dict): A list of dictionaries. Each
                                               dictionary is a limit entry and has the keys:
                                               'file', 'domain', 'limit_type', 'limit_item', 'value'.
        """
        actual_limits_set = {frozenset(d.items()) for d in self.actual_limits_config}
        target_limits_set = {frozenset(d.items()) for d in target_limits_data}

        matching_frozenset = actual_limits_set & target_limits_set
        missing_frozenset = target_limits_set - actual_limits_set
        extra_frozenset = actual_limits_set - target_limits_set

        self.matching_limits = self._sort_limits_data([dict(fs) for fs in matching_frozenset])
        self.missing_from_actual = self._sort_limits_data([dict(fs) for fs in missing_frozenset])
        self.extra_in_actual = self._sort_limits_data([dict(fs) for fs in extra_frozenset])

    def _discover_config_files(self):
        """
        Discover all PAM limits configuration files on the system.

        Returns:
            list: List of absolute file paths to the discovered configuration files.
        """
        found_files = []
        if os.path.isfile(self.DEFAULT_LIMITS_CONF_PATH):
            found_files.append(self.DEFAULT_LIMITS_CONF_PATH)
        
        found_files.extend(glob.glob(self.DEFAULT_LIMITS_D_PATH))
        return found_files

    def _parse_all_config_files(self):
        """
        Parses all discovered PAM limits configuration files.

        Returns:
            all_parsed_limits (list of dict): A list of dictionaries. Each
                                               dictionary is a limit entry and has the keys:
                                               'file', 'domain', 'limit_type', 'limit_item', 'value'.
        """
        all_parsed_limits = []
        for file_path in self.config_file_paths:
            raw_lines = self._read_file_content(file_path)
            clean_lines = self._cleanse_config_lines(raw_lines)
            parsed_entries = self._parse_limits_entries(clean_lines, file_path)
            all_parsed_limits.extend(parsed_entries)
        return all_parsed_limits

    def _parse_limits_entries(self, sanitized_lines, filename):
        """
        Parses PAM limits entries from a list of sanitized lines.

        Args:
            sanitized_lines (list): List of cleaned strings, each representing
                                    a PAM limit rule.
            filename (str): Name of the file from which these lines were read.

        Returns:
            list: A list of dictionaries, each representing a parsed limit entry.
        """
        parsed_entries = []
        for line in sanitized_lines:
            parts = line.split(None, self.EXPECTED_LIMITS_FIELDS) # Split at most 4 times
            
            if len(parts) != self.EXPECTED_LIMITS_FIELDS:
                print(f"WARNING: Line '{line}' in '{filename}' does not match expected format. Skipping.")
                continue

            domain, limit_type, limit_item, raw_value = parts

            try:
                value = int(raw_value)
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

    def _cleanse_config_lines(self, config_lines):
        """
        Remove comments and empty lines from a list of raw configuration lines.

        Args:
            config_lines (list): List of raw strings read from a configuration file.

        Returns:
            list: List of strings without comments and empty lines.
        """
        clean_lines = []
        for line in config_lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue
            clean_lines.append(stripped_line)
        return clean_lines

    def _read_file_content(self, path):
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

    def _sort_limits_data(self, limits_list):
        """
        Sorts PAM limits list.

        Args:
            sorted_limits_data (list of dict): A list of dictionaries. Each
                                               dictionary is a limit entry and has the keys:
                                               'file', 'domain', 'limit_type', 'limit_item', 'value'.

        Returns:
            list: The sorted list of dictionaries.
        """
        return sorted(limits_list, key=lambda x: (
            x.get('file', ''), 
            x.get('domain', ''),
            x.get('limit_item', ''),
            x.get('limit_type', '')
        ))
