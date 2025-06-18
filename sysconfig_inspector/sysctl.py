from typing import List

class KeyEqualValueParser:
    def __init__(self, lines: List[str]):
        self._parsed_lines = {}
        self.parse_lines(lines)

        return

    @property
    def parsed_lines(self):
        return self._parsed_lines

    def _parse_lines(self, config_lines: List[str]) -> None:
        """
        Process a list of configuration lines into _parsed_lines.
        """
        for line in config_lines:
            key, value = self._parse_line(line)
            if key and key not in self._parsed_data: 
                self._parsed_data[key] = value
            elif key and key in self._parsed_data:
                logger.debug(f"Duplicate key '{key}' found. Keeping first value: '{self._parsed_data[key]}'. Discarding: '{value}'.")
