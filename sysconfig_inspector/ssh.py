import os
from typing import Any, Dict, List, Optional


class SSHInspector():
    SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'
    SSH_CONFIG_PATH = '/etc/ssh/ssh_config'

    def __init__(self, 
                 sshd_config_path: Optional[str] = None,
                 ssh_config_path: Optional[str] = None):
        self._sshd_config_path = sshd_config_path if sshd_config_path is not None else self.SSHD_CONFIG_PATH
        self._ssh_config_path = ssh_config_path if ssh_config_path is not None else self.SSH_CONFIG_PATH
        self._config_file_paths: List[str] = []
        self._sshd_config = {}

        self._discover_config_files()
        self._load_sshd_config()

    @property
    def config_file_paths(self) -> List[str]:
        return self._config_file_paths

    @property
    def sshd_config(self) -> Dict[str, Any]:
        return self._sshd_config


    def _load_sshd_config(self) -> None:
        """
        Load SSHD config from path and parse it
        """
        sshd_config_lines = self._read_config_file(self._sshd_config_path)
        sanitized_lines = self._cleanse_config_lines(sshd_config_lines)
        sshd_config = self._parse_sshd_config_lines(sanitized_lines)

        self._sshd_config = sshd_config

    @staticmethod
    def _read_config_file(file_path: str):
        """
        Reads config file from given path
        """
        sshd_config_lines = []

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                sshd_config_lines = file.readlines()
        except FileNotFoundError as e:
            print(f"ERROR: File not found: '{file_path}': {e}")

        return sshd_config_lines

    @staticmethod
    def _cleanse_config_lines(raw_config_lines: List[str]) -> List[str]:
        """
        Removes empty lines and comments
        """

        lines = [line for line in raw_config_lines if line.strip()]
        lines = [line for line in lines if not line.strip().startswith("#")]

        return lines



    def _parse_sshd_config_lines(self, config_lines: List[str]) -> Dict[str, Any]:
        """
        Parses a list of raw sshd_config strings.
        Return a dictionary.
        Only parsing logic. Therefore static
        """
        sshd_config = {}
        matches = []

        current_match = None
        match_lines = []

        for line in config_lines:
            line = line.strip()
            if line.lower().startswith('subsystem'):
                splitted_subsystem = line.split(None, 2)
                key = f"{splitted_subsystem[0]} {splitted_subsystem[1]}"
                value = splitted_subsystem[2]
                sshd_config[key] = value
                continue

            if line.lower().startswith('match '):
                if current_match:
                    matches.append(self._build_match_block(current_match, match_lines))
                current_match = line[6:].strip()
                match_lines = []
            else:
                if current_match is not None:
                    match_lines.append(line)
                else:
                    key, value = self._parse_key_value_line(line)
                    sshd_config[key] = value

        if current_match:
            matches.append(self._build_match_block(current_match, match_lines))
            sshd_config["Match"] = matches

        return sshd_config

    def _parse_key_value_line(self, line: str) -> (str,str):
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip().strip('"')
            try:
                value = int(value)
            except ValueError:
                if value.lower() == "yes":
                    value = True
                elif value.lower() == "no":
                    value = False
        else:
            key = parts[0].strip()
            value = True
        return key, value

    def _build_match_block(self, criteria: str, config_lines: List[str]) -> Dict:
        settings = {}

        for line in config_lines:
            key, value = self._parse_key_value_line(line)
            settings[key] = value

        match_block = {
            "criterium": criteria,
            "settings": settings
        }

        return match_block

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
