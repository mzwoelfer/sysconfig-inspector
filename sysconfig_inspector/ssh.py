import os
import glob
from typing import Any, Dict, List, Tuple, Optional


class SSHInspector():
    """
    Parses and inspects SSH (sshd_config) configuration files.
    Applies standard SSH configuration rules.
    E.g. "First value wins" - for duplicates and additive "Match" blocks.
    """

    # --- CONSTANTS ---
    SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'
    SSH_CONFIG_PATH = '/etc/ssh/ssh_config'

    def __init__(self, 
                 sshd_config_path: Optional[str] = None,
                 ssh_config_path: Optional[str] = None):
        """
        Initializes the SSHInspector with specified or default configuration paths.

        ARGS:
            sshd_config_path (str, optional): sshd_config file
            ssh_config_path (str, optional): ssh_config
        """

        self._sshd_config_path = sshd_config_path if sshd_config_path is not None else self.SSHD_CONFIG_PATH
        self._ssh_config_path = ssh_config_path if ssh_config_path is not None else self.SSH_CONFIG_PATH
        self._config_file_paths: List[str] = []
        self._sshd_config: Dict [str, Any] = {}

        self._discover_and_load_configs()

    @property
    def config_file_paths(self) -> List[str]:
        """List of discovered SSH config files"""
        return self._config_file_paths

    @property
    def sshd_config(self) -> Dict[str, Any]:
        """Parsed SSHD config as dictionary"""
        return self._sshd_config

    # --- CORE CONFIG LOADING ---

    def _discover_and_load_configs(self) -> None:
        """
        Discovers SSH(D) config files and loadsthe sshd_config.
        """
        self._discover_config_files()
        self._load_and_parse_sshd_config()
    
    def _discover_config_files(self) -> None:
        """
        Discovers SSH(D) configurations files.
        """
        found_files: List[str] = []

        if os.path.isfile(self._sshd_config_path):
            found_files.append(self._sshd_config_path)

        if os.path.isfile(self._ssh_config_path):
            found_files.append(self._ssh_config_path)

        self._config_file_paths = found_files

    def _load_and_parse_sshd_config(self) -> None:
        """
        Reads, cleanses and parses the main SSHD config file.
        """

        raw_lines = self._read_file(self._sshd_config_path)
        sanitized_lines = self._cleanse_config_lines(raw_lines)
        self._sshd_config = self._parse_sshd_config_lines(sanitized_lines)


    # --- FILE HANDLING HELPERS ---
    def _read_file(self, file_path: str) -> List[str]:
        """
        Reads lines from a given file path.
        Return an empty list if the file is not found or cannot be read.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.readlines()
        except FileNotFoundError:
            print(f"WARNING: Config file not found: '{file_path}'. Skipping")
            return []
        except IOError as e:
            print(f"ERROR: Could not read file '{file_path}': {e}")
            return []

    @staticmethod
    def _cleanse_config_lines(raw_lines: List[str]) -> List[str]:
        """
        Removes empty lines and comments from a list of raw config lines.
        """

        lines = [line for line in raw_lines if line.strip()]
        lines = [line for line in lines if not line.strip().startswith("#")]

        return lines


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
                    match_blocks.append(self._build_match_block(current_match_criteria, current_match_lines))

                parts = line.split(None, 1)
                if len(parts) > 1:
                    current_match_criteria = parts[1].strip()
                else:
                    current_match_criteria = ""

                current_match_lines = []
                continue

            if current_match_criteria is not None:
                current_match_lines.append(line)
                continue

            if directive_type == 'include':
                self._handle_include_directive(line, parsed_config, match_blocks)
                continue


            key, value = self._parse_directive_line(line)
            if key and key not in parsed_config:
                parsed_config[key] = value
            
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

    def _handle_include_directive(self, line: str, parsed_config: Dict[str, Any], match_blocks: List[Dict[str, Any]]) -> None:
        parts = line.split(None, 1)
        if len(parts) > 1:
            include_pattern = parts[1].strip()
        else:
            include_pattern = ""

        # 'Include' directive can only appear once in the top-level config 
        if "Include" not in parsed_config:
            parsed_config["Include"] = include_pattern

        included_data = self._parse_included_files(include_pattern)

        if "Match" in included_data:
            match_blocks.extend(included_data.pop("Match"))

        for key, value in included_data.items():
            if key not in parsed_config:
                parsed_config[key] = value

    def _parse_included_files(self, pattern: str) -> Dict[str, Any]:
        """
        Reads and parses configuration from files matching a given glob pattern.
        Handles nested 'Include' directives through recursion.
        """
        combined_included_config: Dict[str, Any] = {}

        for file_path in glob.glob(pattern):
            if not os.path.isfile(file_path):
                print(f"WARNING: Skipping non-file path in include pattern: '{file_path}'")
                continue

            raw_lines = self._read_file(file_path)
            sanitized_lines = self._cleanse_config_lines(raw_lines)
            
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

    def _parse_directive_line(self, line: str) -> Tuple[ſtr, Any]:
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
                value: Any = int(value_raw)
            except ValueError:
                if value_raw.lower() == "yes":
                    value = True
                elif value_raw.lower() == "no":
                    value = False
                else:
                    value = value_raw
            return key, value
        elif len(parts) == 1:
            return parts[0].strip(), True
        return "",""

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
        return "", "" 

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
        return "", "" 

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
