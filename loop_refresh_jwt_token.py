#!/usr/bin/env python3

import subprocess
import time
import argparse
import shlex
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

def load_yaml_config(path):
    with open(path, 'r') as file:
        return yaml.safe_load(file)

def build_command(config):
    base_command = [
        "python3", "jwt_api_with_bruno_support.py",
        "--url", config["url"],
        "--user-id", config["user_id"],
        "--fingerprint", config["fingerprint"],
        "--passphrase", config["passphrase"]
    ]
    if config.get("insecure"):
        base_command.append("--insecure")
    if config.get("bruno_format"):
        base_command.append("--bruno-format")
    if config.get("bruno_env_path"):
        base_command += ["--bruno-env-path", config["bruno_env_path"]]
    if config.get("bruno_env_name"):
        base_command += ["--bruno-env-name", config["bruno_env_name"]]
    return base_command

def main():
    parser = argparse.ArgumentParser(description="Run Passbolt JWT script every 5 minutes.")

    # Config file support
    parser.add_argument('--env-file', help="Optional .env file with key=value pairs")
    parser.add_argument('--yaml-config', help="Optional YAML config file")

    # CLI override flags
    parser.add_argument('--url')
    parser.add_argument('--user-id')
    parser.add_argument('--fingerprint')
    parser.add_argument('--passphrase')
    parser.add_argument('--insecure', action='store_true')
    parser.add_argument('--bruno-format', action='store_true')
    parser.add_argument('--bruno-env-path')
    parser.add_argument('--bruno-env-name')
    parser.add_argument('--interval', type=int, default=300, help='Seconds between runs')

    args = parser.parse_args()

    # Load from .env if provided
    if args.env_file:
        load_dotenv(dotenv_path=args.env_file)

    # Load from YAML if provided
    config = {}
    if args.yaml_config:
        config = load_yaml_config(args.yaml_config)
    else:
        config = {}

    # Merge values from CLI args or env vars (CLI takes precedence)
    config["url"] = args.url or os.getenv("URL") or config.get("url")
    config["user_id"] = args.user_id or os.getenv("USER_ID") or config.get("user_id")
    config["fingerprint"] = args.fingerprint or os.getenv("FINGERPRINT") or config.get("fingerprint")
    config["passphrase"] = args.passphrase or os.getenv("PASSPHRASE") or config.get("passphrase")
    config["insecure"] = args.insecure or os.getenv("INSECURE") == "true" or config.get("insecure", False)
    config["bruno_format"] = args.bruno_format or os.getenv("BRUNO_FORMAT") == "true" or config.get("bruno_format", False)
    config["bruno_env_path"] = args.bruno_env_path or os.getenv("BRUNO_ENV_PATH") or config.get("bruno_env_path")
    config["bruno_env_name"] = args.bruno_env_name or os.getenv("BRUNO_ENV_NAME") or config.get("bruno_env_name")

    # Check required fields
    required = ["url", "user_id", "fingerprint", "passphrase"]
    for key in required:
        if not config.get(key):
            raise ValueError(f"Missing required config value: {key}")

    base_command = build_command(config)

    print("🔁 Starting loop. Press Ctrl+C to stop.")

    try:
        while True:
            print(f"\n🚀 Running JWT script at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("Command:", ' '.join(shlex.quote(part) for part in base_command))
            result = subprocess.run(base_command)
            print(f"✅ Done. Sleeping {args.interval} seconds...\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n🛑 Loop stopped by user.")

if __name__ == "__main__":
    main()

