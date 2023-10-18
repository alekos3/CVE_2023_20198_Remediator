__author__ = "Alexios Nersessian"
__email__ = "nersessian@gmail.com"
__version__ = "v1"

import argparse
import getpass
import time
from multiprocessing.pool import ThreadPool
from netmiko import ConnectHandler

"""
    Remediate CVE-2023-20198
    
    Cisco IOS XE Software Web UI Privilege Escalation Vulnerability CVE-2023-20198
    https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z
"""

# Initialize Arg parser
arg_parser = argparse.ArgumentParser(prog=__doc__)

arg_parser.add_argument(
    "-d",
    "--devices",
    required=False,
    type=str,
    default="devices.csv",
    help="File with all IP addresses. Must be a csv file."
)

args = vars(arg_parser.parse_args())


class SshSession:
    def __init__(self, host, username, password, device_type='cisco_ios'):
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.connection = None

    def connect(self):
        try:
            device = {
                'device_type': self.device_type,
                'ip':   self.host,
                'username': self.username,
                'password': self.password,
            }
            self.connection = ConnectHandler(**device)
            return True

        except:
            return False

    def send_configuration(self, configuration_commands):
        if self.connection is None:
            print("No connection established. Use the connect method first.")
            return
        output = self.connection.send_config_set(configuration_commands, read_timeout=60)
        self.connection.send_command("write memory", read_timeout=60)
        return output

    def disconnect(self):
        if self.connection is not None:
            self.connection.disconnect()


def get_devices_from_csv(filename):
    # Open the CSV file
    with open(filename, 'r') as file:
        data = file.read()

    return data.splitlines()


def main(host):
    remediate_commands = ["no ip http server", "no ip http secure-server"]  # Remove vulnerable config

    # 1. Establish connection to host
    print(f"- Connecting to {host}.")
    connection = SshSession(host, username, password)
    status = connection.connect()

    if not status:
        print(f"- {host}: Failed to connect.")
        return

    print(f"- {host}: Sending no ip http server and no ip http secure-server")
    connection.send_configuration(remediate_commands)
    print(f"- {host}: Writing to memory.")

    print(f"{host}: Terminating ssh connection.")
    connection.disconnect()


if __name__ == '__main__':
    username = input("Enter username: ")
    password = getpass.getpass()
    host_list = get_devices_from_csv(args["devices"])[1:]

    # Multi threading
    pool = ThreadPool(5)  # Number of threads, do NOT increase
    pool.map(main, host_list)
    pool.close()  # Close needs to be first before join as per docs, or we will run into memory issue
    pool.join()  # https://docs.python.org/2/library/multiprocessing.html#module-multiprocessing.pool

    print()
    print("Done!")
    print()
