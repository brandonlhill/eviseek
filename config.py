import os
import sys
import stat
import logging
import configparser
from getpass import getpass

logger = logging.getLogger("__name__")

CONFIG_PATH = os.path.expanduser("~/.eviseek/config.ini")
CONFIG_SECTION_SSH = "ssh"
CONFIG_SECTION_LOCAL = "local"
CONFIG_SECTION_ASSEMBLYLINE = "assemblyline"

REQUIRED_SSH_KEYS = ["host", "port", "username", "password", "remote_host", "remote_port"]
REQUIRED_LOCAL_KEYS = ["db_path", "batch_size"]
REQUIRED_AL_KEYS = ["host", "user", "password", "queue"]

def create_fallback_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    config = configparser.ConfigParser()

    config[CONFIG_SECTION_SSH] = {
        "host": "",
        "port": "22",
        "username": "",
        "password": "",
        "remote_host": "",
        "remote_port": "5001"
    }

    config[CONFIG_SECTION_LOCAL] = {
        "db_path": "alerts.json",
        "batch_size": "10"
    }

    config[CONFIG_SECTION_ASSEMBLYLINE] = {
        "host": "",
        "user": "",
        "password": "",
        "queue": ""
    }

    with open(path, "w") as f:
        config.write(f)

    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    logger.info(f"Created secure fallback config at {path} (permissions 0600)")

def interactive_config():
    print(f"[config.py] Configuring values for {CONFIG_PATH}")
    config = configparser.ConfigParser()
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)

    for section, keys in [
        (CONFIG_SECTION_SSH, REQUIRED_SSH_KEYS),
        (CONFIG_SECTION_LOCAL, REQUIRED_LOCAL_KEYS),
        (CONFIG_SECTION_ASSEMBLYLINE, REQUIRED_AL_KEYS)
    ]:
        if section not in config:
            config[section] = {}

        for key in keys:
            existing = config[section].get(key, "").strip()
            if existing:
                print(f"{key} already set in [{section}].")
                continue

            if "password" in key:
                value = getpass(f"Enter value for {section} key '{key}': ")
            else:
                value = input(f"Enter value for {section} key '{key}': ").strip()

            config[section][key] = value

    with open(CONFIG_PATH, "w") as f:
        config.write(f)

    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    print(f"[config.py] Configuration saved to {CONFIG_PATH} with permissions 0600.")

def load_config():
    config = configparser.ConfigParser()

    if os.path.exists(CONFIG_PATH) and os.path.getsize(CONFIG_PATH) > 0:
        config.read(CONFIG_PATH)
        logger.debug(f"Loaded config from: {CONFIG_PATH}")
    else:
        logger.warning("No configuration found.")
        choice = input(f"Would you like to create a new config at {CONFIG_PATH}? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            interactive_config()
        else:
            logger.error("Aborting. Configuration is missing.")
            sys.exit(1)
        config.read(CONFIG_PATH)

    required_sections = [
        (CONFIG_SECTION_SSH, REQUIRED_SSH_KEYS),
        (CONFIG_SECTION_LOCAL, REQUIRED_LOCAL_KEYS),
        (CONFIG_SECTION_ASSEMBLYLINE, REQUIRED_AL_KEYS)
    ]

    for section, keys in required_sections:
        if section not in config:
            logger.error(f"Missing section [{section}] in {CONFIG_PATH}")
            sys.exit(1)

        missing = [key for key in keys if key not in config[section] or not config[section][key].strip()]
        if missing:
            logger.warning(f"Missing keys in section [{section}]: {', '.join(missing)}")
            choice = input(f"Would you like to fill in the missing fields now? [Y/n]: ").strip().lower()
            if choice in ("", "y", "yes"):
                interactive_config()
                config.read(CONFIG_PATH)
            else:
                logger.error("Aborting. Required configuration is incomplete.")
                sys.exit(1)

    return {
        "ssh": {
            k: config[CONFIG_SECTION_SSH][k] if k not in ("port", "remote_port") else int(config[CONFIG_SECTION_SSH][k])
            for k in REQUIRED_SSH_KEYS
        },
        "local": {
            k: config[CONFIG_SECTION_LOCAL][k] if k != "batch_size" else int(config[CONFIG_SECTION_LOCAL][k])
            for k in REQUIRED_LOCAL_KEYS
        },
        "assemblyline": {
            k: config[CONFIG_SECTION_ASSEMBLYLINE][k]
            for k in REQUIRED_AL_KEYS
        }
    }

if __name__ == "__main__":
    interactive_config()
