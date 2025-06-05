# Sysconfig Inspector

Python3 toolkit to inspect and compare system configurations. Such as SSH configs, fstab, resolv, hosts, and more.

Modular classes that can read, parse and compare the system configuration against a desired target.

## 🚀 FEATURES
- Parse config files and subfolders
- Compare the system configuration against target settings
- Extendable to other configs like SSH, hosts, fstab, etc.
- Designed for integration into automation workflows (e.g. Ansible)

## USAGE
```PYTHON
from sysconfig_inspector.pam_limits import PamLimits

pam_limits = PamLimits()
pam_limits.compare_to(expected_config)

print("Matching:", pam_limits.matching_config)
print("Missing in actual:", pam_limits.not_on_server)
print("Unexpected in actual:", pam_limits.not_in_expected)
```

## 🏗️ DEVELOPMENT
- Python3.8+
- Use virtual environment for isolation
- Tests use `unittest`

## SETUP
```BASH
python3 -m venv Env
source Env/bin/activate
pip install -r requirements.txt
```

Run tests:
```BASH
python3 -m unittest discover tests
```

## LICENSE
EUPL v1.2

