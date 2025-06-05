import glob 
import os

class PamLimits:
    def __init__(self):
        self.limits_config_files = self.discover_limits_config()
        self.actual_config = self.parse_config()
        self.target_config = []
        self.matching_config = []
        self.not_in_actual_config = []
        self.not_in_target_config = []

    def compare_to(self, config_lines):
        actual_config = { frozenset(d.items()) for d in self.actual_config }
        target_config = { frozenset(d.items()) for d in config_lines }

        not_in_actual_config_frozenset = target_config - actual_config
        not_in_target_config_frozenset = actual_config - target_config
        correct_config_frozenset = actual_config & target_config

        correct_config = [ dict(fs) for fs in correct_config_frozenset ]
        not_in_actual_config = [ dict(fs) for fs in not_in_actual_config_frozenset ]
        not_in_target_config = [ dict(fs) for fs in not_in_target_config_frozenset ]

        # sort lists
        self.matching_config = sorted(correct_config, key=lambda x: (['file'], x['domain'], x['limit_item'], x['limit_type']))
        self.not_in_actual_config = sorted(not_in_actual_config, key=lambda x: (['file'], x['domain'], x['limit_item'], x['limit_type']))
        self.not_in_target_config = sorted(not_in_target_config, key=lambda x: (['file'], x['domain'], x['limit_item'], x['limit_type']))
        

    def discover_limits_config(self):
        files = []
        limits_conf = '/etc/security/limits.conf'
        if os.path.isfile(limits_conf):
            files.append(limits_conf)
        files.extend(glob.glob('/etc/security/limits.d/*.conf'))
        return files


    def parse_config(self):
        actual_config = []

        for filename in self.limits_config_files:
            lines = self._read_file(filename)
            sanitized_config_lines = self._sanitize_config_lines(lines)
            actual_config.extend(self._parse_limits(sanitized_config_lines, filename))

        return actual_config


    def _parse_limits(self, sanitized_lines, filename):
        actual_config = []
        for line in sanitized_lines:
            line_dict = {}
            splitline = line.split(None, 4)
            if len(splitline) != 4:
                print(f"WARNING: line ${splitline} does not match expected format")
            else:
                domain, limit_type, limit_item, raw_value = splitline[0:4]

                try:
                    value = int(raw_value)
                except ValueError:
                    value = raw_value  

                actual_config.append({
                    "file": filename,
                    "domain": domain,
                    "limit_type": limit_type,
                    "limit_item": limit_item,
                    "value": value,
                })
        return actual_config


    def _sanitize_config_lines(self, config_lines):
        sanitized_lines = []
        for line in config_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            sanitized_lines.append(line)

        return sanitized_lines


    def _read_file(self, path):
        with open(path, 'rt') as file:
            lines = file.readlines()

        return lines
