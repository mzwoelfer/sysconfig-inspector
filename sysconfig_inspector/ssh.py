import os
from typing import List, Optional


class SSHInspector():
    SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'
    SSH_CONFIG_PATH = '/etc/ssh/ssh_config'

    def __init__(self, 
                 sshd_config_path: Optional[str] = None):
        self._sshd_config_path = sshd_config_path if sshd_config_path is not None else self.SSHD_CONFIG_PATH
        self._config_file_paths: List[str] = []
        self._discover_config_files()

    @property
    def config_file_paths(self) -> List[str]:
        return self._config_file_paths


    def _discover_config_files(self) -> None:
        """
        Discovers SSH configurations files.
        """
        found_files: List[str] = []

        if os.path.isfile(self._sshd_config_path):
            found_files.append(self._sshd_config_path)

        self._config_file_paths = found_files
