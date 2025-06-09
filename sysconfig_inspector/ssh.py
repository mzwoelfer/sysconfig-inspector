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

    @staticmethod
    def _parse_sshd_config_lines(config_lines: List[str]) -> Dict[str, Any]:
        """
        Parses a list of raw sshd_config strings.
        Return a dictionary.
        Only parsing logic. Therefore static
        """
        sshd_config = {}

        for line in config_lines:
            line = line.strip()
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1]
            try:
                value = int(value)
            except ValueError:
                if value.lower() == "yes":
                    value = True
                elif value.lower() == "no":
                    value = False

            sshd_config[key] = value

        return sshd_config

    @staticmethod
    def _cleanse_config_lines(raw_config_lines: List[str]) -> List[str]:
        """
        Removes empty lines and comments
        """

        lines = [line for line in raw_config_lines if line.strip()]
        lines = [line for line in lines if not line.strip().startswith("#")]

        return lines

    def _load_sshd_config(self) -> None:
        """
        Parses SSHD config
        """

        sshd_config = {}

        try:
            with open(self._sshd_config_path, 'r', encoding='utf-8') as file:
                sshd_config_lines = file.readlines()
        except FileNotFoundError:
            return

        sanitized_lines = self._cleanse_config_lines(sshd_config_lines)
        sshd_config = self._parse_sshd_config_lines(sanitized_lines)

        self._sshd_config = sshd_config

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
