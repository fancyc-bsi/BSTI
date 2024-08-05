from scripts.drone import Drone
import os
import json
import csv
import re
import sys
import time
import xml.etree.ElementTree as XML
import requests, urllib3
from scripts.logging_config import log
requests.packages.urllib3.disable_warnings()


class Nessus:
    def __init__(self, drone, username, password, mode=None, project_name=None, policy_file_path=None, targets_file=None, exclude_file=None, discovery=None):
        # Basic Initializations
        self.drone = Drone(drone, username, password)
        self.alive_hosts = ''
        self.username = username
        self.password = password
        self.url = "https://" + drone + ":8834"
        self.project_name = project_name
        self.auth = {
            "username": username,
            "password": password
        }
        
        # Load policy file if exists
        self.load_policy(policy_file_path)

        self.output_folder = os.getcwd()
        
        # Process targets and exclude files
        self.process_files(targets_file, exclude_file)
        
        # Additional mode-specific initializations
        if mode in ["deploy", "create"]:
            self.drone_ip = self.get_drone_ip()
            if discovery:
                self.alive_hosts = self.discovery_scan()
            else:
                log.warning("Discovery scan was skipped by user")
                
        self.get_auth()
        
        # Execute mode-specific method
        self.execute_mode(mode)

    def load_policy(self, policy_file_path):
        if policy_file_path:
            with open(policy_file_path, 'r') as policy_file:
                self.policy_file = policy_file.read()
                self.policy_file_name = policy_file.name

                # Parse the XML policy file
                tree = XML.parse(self.policy_file_name)
                root = tree.getroot()
                name_element = root.find('./Policy/policyName')
                self.policy_name = name_element.text

    def process_files(self, targets_file, exclude_file):
        self.added_ips = set()
        if targets_file and os.path.exists(targets_file):
            with open(targets_file, 'r') as file:
                self.targets_list = " ".join([line.strip() for line in file if line.strip()])
                
        self.exclude_file = exclude_file.readlines() if exclude_file else None

    def execute_mode(self, mode):
        mode_dispatch = {
            "deploy": self.deploy,
            "create": self.create,
            "launch": self.launch,
            "pause": self.pause,
            "resume": self.resume,
            "monitor": self.monitor,
            "export": self.export
        }

        # Call the appropriate method based on mode
        mode_function = mode_dispatch.get(mode)
        if mode_function:
            mode_function()
        else:
            log.error(f"Invalid mode: {mode}")

    # Auth handlers
    def get_auth(self, verbose=False):
        
        """
        Retrieves API tokens and authentication keys for accessing the API.

        Parameters:
            verbose (bool): Flag indicating whether to log verbose output (default: True).

        Returns:
            None

        Raises:
            Exception: If failed to retrieve API tokens.

        """
        # log.info("Retrieving API tokens")
        try:
            self.token_keys = self.get_tokens()
            self.token_auth = {
                "X-Cookie": f"token={self.token_keys['cookie_token']}",
                "X-API-Token": self.token_keys["api_token"]
            }

            self.api_keys = self.get_api_keys()
            self.api_auth = {
                "X-ApiKeys": "accessKey="+self.api_keys["accessKey"]+"; secretKey="+self.api_keys["secretKey"]
            }

            # if verbose:
            #     log.info("API tokens retrieved successfully.")
        except requests.exceptions.ConnectionError as rc:
            log.error(f"Failed to retrieve API tokens - check your login credentials")
            sys.exit(1)
        except urllib3.exceptions.NewConnectionError as e:
            if verbose:
                log.error(f"Failed to retrieve API tokens - check your login credentials")
                sys.exit(1)

    def get_tokens(self):
        """
        Retrieves API tokens required for authentication.

        Returns:
            dict: Dictionary containing the retrieved API tokens.

        Raises:
            None

        """
        # get X-Cookie token
        tokens = {}
        response = requests.post(self.url + "/session", data=self.auth, verify=False)
        tokens["cookie_token"] = json.loads(response.text)["token"]

        # cheat api restrictions and get X-Api-Token:
        response = requests.get(self.url + "/nessus6.js", verify=False)
        tokens["api_token"] = re.search(r'{key:"getApiToken",value:function\(\){return"(.*)"}},{key', response.text)[1]
        tokens["scan_uuid"] = re.search(r'CUSTOM_SCAN_TEMPLATE="(.*)",this\.CUSTOM_AGENT_TEMPLATE', response.text)[1] # for creating scans later, so we don't need to make this slow request again
        return tokens

    def get_api_keys(self):
        """
        Retrieves the accessKey and secretKey required to interact with the API.

        Returns:
            dict: Dictionary containing the retrieved accessKey and secretKey.

        Raises:
            None

        """
        # get accessKey and secretKey to interact with api		
        response = requests.put(self.url + "/session/keys", headers=self.token_auth, verify=False)
        keys = {
            "accessKey": json.loads(response.text)["accessKey"],
            "secretKey": json.loads(response.text)["secretKey"]
        }
        return keys

    def discovery_scan(self):
        """
        Conducts discovery scans prior to running Nessus, only used in deploy/create modes
        """
        log.info("Running discovery scan")
        try:
            # Run the nmap scan
            self.targets_list = self.targets_list.rstrip(',')
            cmd = f"sudo nmap --exclude {self.drone_ip} -T4 -n -sn {self.targets_list} -PE -PP -PM -PO --min-parallelism 100 --max-parallelism 256 -oG -"
            nmap_output = self.drone.execute(cmd)

            # If the output is in bytes, decode it to a string
            if isinstance(nmap_output, bytes):
                nmap_output = nmap_output.decode('utf-8')

            # Extract IPs that are up
            alive_hosts = [line.split()[1] for line in nmap_output.split("\n") if "Up" in line]
            self.alive_hosts = ','.join(alive_hosts)

            if not self.alive_hosts:
                log.error("No hosts are up! Contact the client or run discovery manually")
                sys.exit(1)

            # Print summary of alive hosts
            log.success("Discovery scan finished for alive hosts")
            self.print_hosts_table(alive_hosts, "Alive Hosts")

            # Find the summary line in the nmap output and extract numbers
            total_ips, alive_count = self.parse_nmap_summary(nmap_output)

            # Calculate the number of down hosts
            dead_count = total_ips - alive_count
            log.info(f"Nmap done: {total_ips} IP addresses ({alive_count} hosts up) scanned")

            if dead_count > 0:
                log.warning(f"{dead_count} hosts could be down. Please review the network configuration and inform the client if necessary.")

            time.sleep(10)
            log.info("Proceeding...")

            return self.alive_hosts

        except Exception as e:
            log.error(f"An error occurred during the discovery scan: {e}")


    def parse_nmap_summary(self, nmap_output):
        """
        Parses the nmap output for the summary line and extracts the total IPs scanned and the number of alive hosts.
        """
        # Look for the summary line using a regular expression
        summary_match = re.search(r"(\d+) IP addresses \((\d+) hosts up\)", nmap_output)
        if summary_match:
            total_ips = int(summary_match.group(1))
            alive_count = int(summary_match.group(2))
            return total_ips, alive_count
        return 0, 0  # In case the summary line is not found or doesn't match the pattern


    def print_hosts_table(self, hosts_list, header):
        """
        Prints a table of hosts with a given header using built-in Python libraries.
        """
        num_columns = 5
        # Split the list into a 2D list for the table rows
        table_data = [hosts_list[i:i + num_columns] for i in range(0, len(hosts_list), num_columns)]

        # Calculate column widths
        column_widths = [0] * num_columns
        for row in table_data:
            for i, cell in enumerate(row):
                column_widths[i] = max(column_widths[i], len(cell))

        # Function to create a row string
        def create_row(row, widths, separator=' | '):
            return separator.join(cell.ljust(width) for cell, width in zip(row, widths))

        # Print the header
        headers = [header] * min(num_columns, len(hosts_list))
        header_line = create_row(headers, column_widths)
        border_line = '+' + '+'.join('-' * (w + 2) for w in column_widths) + '+'

        print(border_line)
        print('| ' + header_line + ' |')
        print(border_line)

        # Print table rows
        for row in table_data:
            print('| ' + create_row(row, column_widths) + ' |')
            print(border_line)


    def get_device_name(self):
        log.info("Getting drone device name")
        cmd = "ip a | awk '/^[0-9]+:/{print $2}' | sed 's/://' | grep -v lo"
        return self.drone.execute(cmd).split("\n")[0]

    def get_ip_address(self, device_name):
        log.info("Getting drone IP")
        cmd = (f'ip a s {device_name} | '
            f'grep -o "inet .* brd" | '
            f'grep -o "[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*"')
        return self.drone.execute(cmd).split("\n")[0]

    def get_existing_ips(self):
        cmd = "sudo cat /opt/nessus/etc/nessus/nessusd.rules"
        existing_rules = self.drone.execute(cmd)
        ip_pattern = re.compile(r'reject (\d+\.\d+\.\d+\.\d+)')
        return ip_pattern.findall(existing_rules)

    def add_ip_to_reject_list(self, ip_address):
        log.info("Adding targets to reject list")
        log.info(f"Adding drone IP {ip_address} to the reject list")
        cmd = f"sudo sed -i 's/^default accept/reject {ip_address}\\ndefault accept/' /opt/nessus/etc/nessus/nessusd.rules"
        self.drone.execute(cmd)

    def get_drone_ip(self, max_retries=3, retry_delay=5):
        for attempt in range(max_retries):
            try:
                drone_device = self.get_device_name()
                self.drone_ip = self.get_ip_address(drone_device)

                if not self.drone_ip:
                    raise Exception("Failed to get drone IP")

                existing_ips = self.get_existing_ips()
                
                if self.drone_ip not in existing_ips:
                    self.added_ips.add(self.drone_ip)
                    self.add_ip_to_reject_list(self.drone_ip)
                else:
                    log.info(f"Drone IP {self.drone_ip} is already in the reject list. Skipping addition.")
                
                return self.drone_ip
            except Exception as e:
                if attempt < max_retries - 1:  # if not on the last attempt
                    log.warning(f"Attempt {attempt + 1} failed to get the drone IP. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    log.error(f"Failed to get the drone IP after {max_retries} attempts: {e}")
                    sys.exit(1)


        
    def exclude_targets(self):
        """
        Adds targets to the reject list.
        """
        try:
            if self.exclude_file:
                log.info("Adding exclude targets to the reject list")
                existing_ips = self.get_existing_ips()
                for exclude_target in self.exclude_file:
                    exclude_target = exclude_target.rstrip()
                    if exclude_target not in self.added_ips and exclude_target not in existing_ips:
                        cmd = f"sudo sed -i 's/^default accept/reject {exclude_target}\\ndefault accept/' /opt/nessus/etc/nessus/nessusd.rules"
                        self.drone.execute(cmd)
                        self.added_ips.add(exclude_target)
            if self.drone_ip in self.added_ips:
                log.info('drone IP already added to reject list')
            else:
                log.info("Exclusion targets added to the reject list in /opt/nessus/etc/nessus/nessusd.rules")
                log.info("Targets added to the reject list successfully.")
        except Exception as e:
            log.error(f"Failed to add targets to the reject list: {e.args[0]}")
            sys.exit()

    def update_settings(self):
        """
    Updates the settings of the Nessus scanner.

    Returns:
        None

    Raises:
        Exception: If the settings cannot be updated.

        """
        log.info("Updating settings")
            # bulletproof standard settings as per policy
        settings = {
            "scan_vulnerability_groups": "no",
            "scan_vulnerability_groups_mixed": "no",
            "port_range": "all",
            "severity_basis": "cvss_v3"
        }

        try:
            # nessus requires settings to be updated one by one
            for name, value in settings.items():
                data = {
                    "setting.0.action": "edit",
                    "setting.0.name": name,
                    "setting.0.value": value
                }
                response = requests.put(self.url + "/settings/advanced", headers=self.api_auth, data=data, verify=False)
                if response.status_code != 200:
                    raise Exception("Could not update settings.")

        except Exception as e:
            log.error(str(e))
            log.error(response.text)
            sys.exit()

    def import_policies(self):
        """
        Imports policies into the Nessus scanner.

        Returns:
            None

        Raises:
            Exception: If the policy file already exists or if the policies cannot be imported.

        """
        log.info("Importing policies")
        try:
            # check if policy file already exists:
            policy_name = self.policy_file_name.rsplit(".", 1)[0]
            if "\\" in policy_name:
                policy_name = policy_name.split("\\")[-1]
            elif "/" in policy_name:
                policy_name = policy_name.split("/")[-1]
            response = requests.get(self.url + "/policies", headers=self.api_auth, verify=False)
            if policy_name in response.text:
                log.warning("Policy file already exists, skipping import")
                return

            # first, upload the policies file to nessus
            file = {
                "Filedata": (self.policy_file_name, self.policy_file)
            }
            response = requests.post(self.url + "/file/upload", headers=self.api_auth, files=file, verify=False)

            # then, retrieve the file and post it to policies
            fileuploaded = json.loads(response.text)["fileuploaded"]
            data = {
                "file": fileuploaded
            }
            response = requests.post(self.url + "/policies/import", headers=self.api_auth, data=data, verify=False)
            log.info("Waiting for policies to be compiled")
            time.sleep(120) # wait for policies to be compiled - 120 seconds should be good enough but may need more depending on how slow the connection is
            if response.status_code == 200:
                log.info("Imported policies")

            else:
                raise Exception("Could not import policies." + response.text)

        except Exception as e:
            log.error(e)
            sys.exit()


    def create_scan(self, launch):
        """
    Creates a new scan in the Nessus scanner.

    Args:
        launch (bool): Indicates whether to launch the scan immediately or not.

    Returns:
        None

    Raises:
        Exception: If the scan name already exists, policy is not found, targets file fails to upload, or scan creation fails.

        """
        log.info("Creating new scan")
        try:
            # check if scan name already exists first:
            if self.get_scan_info() is not None:
                log.error("Scan name already exists")
                return

            project_name = self.project_name

            # get policy id
            policies = json.loads(requests.get(self.url + "/policies", headers=self.api_auth, verify=False).text)["policies"]
            policy = next((p for p in policies if p["name"] == self.policy_name), None)
            if not policy:
                raise Exception(f"No policy found with name {self.policy_name}")
            policy_id = policy["id"]
            if self.alive_hosts:
                file = {
                    "Filedata": ("targets.txt", self.alive_hosts)
                }
            else:
                file = {
                    "Filedata": ("targets.txt", self.targets_list)
                }
            response = requests.post(self.url + "/file/upload", headers=self.api_auth, files=file, verify=False)
            if response.status_code != 200:
                raise Exception("Failed to upload targets file")
            else:
                log.info("Target file uploaded successfully")
                uploaded_filename = json.loads(response.text)["fileuploaded"]
            
            uuid = self.token_keys["scan_uuid"]
            time.sleep(5)

            # send "create scan" request
            data = {
                "uuid": f'{uuid}',
                "settings": {
                    "name": project_name,
                    "policy_id": policy_id,
                    "launch_now": launch,
                    "enabled": False,
                    "scanner_id": "1",
                    "folder_id": 3,
                    "file_targets": uploaded_filename,
                    "description": "No host Discovery\nAll TCP port\nAll Service Discovery\nDefault passwords being tested\nGeneric Web Test\nNo compliance or local Check\nNo DOS plugins\n",
                }
            }
            response = requests.post(self.url + "/scans", headers=self.token_auth, json=data, verify=False)
            
            if response.status_code != 200:
                raise Exception("Failed to create scan", f"Error:" + response.text)
            else:
                log.info("Scan created")

        except Exception as e:
            log.error(str(e))
            sys.exit()



    def get_scan_info(self):
        """
        Retrieves information about a scan from the Nessus scanner.

        Returns:
        dict: Information about the scan if found, otherwise None.

        Raises:
        Exception: If the scan information cannot be retrieved.

        """
        try:
            response = requests.get(self.url + "/scans?folder_id=3", headers=self.token_auth, verify=False)
            scans = json.loads(response.text)["scans"]

            if not scans:
                return

            for scan in scans:
                if scan["name"] == self.project_name:
                    return scan

        except Exception as e:
            log.error(f"Could not get scan info {e}")


    def scan_action(self, action):
        """
    Performs a specified action on a scan in the Nessus scanner.

    Args:
        action (str): The action to perform on the scan.

    Returns:
        None

    Raises:
        Exception: If the scan ID cannot be retrieved or if the scan action fails.

        """
        log.info(f"Sending {action} request to \"{self.project_name}\"")
        try:
            scan_id = self.get_scan_info()["id"]
            response = requests.post(self.url + f"/scans/{scan_id}/{action}", headers=self.token_auth, verify=False)
            if response.status_code == 200:
                log.info(f"Scan {action} completed successfully")
            else:
                raise Exception("Could not complete scan action")

        except Exception:
            log.error("Connection to the drone was lost.")
            sys.exit()

    def monitor_scan(self):
        """
        Monitors the status of a scan in the Nessus scanner.

        Returns:
            None
        """
        log.info("Monitoring scan...")

        status = self.get_scan_info()["status"]
        time_elapsed = 0
        update_interval = 60  # seconds for regular updates
        next_update_time = update_interval

        while status in ["running", "pending", "resuming", "queued"]:
            time.sleep(15)
            time_elapsed += 15
            status = self.get_scan_info()["status"]

            if time_elapsed >= next_update_time:
                log.info(f"Scan status: {status}")
                next_update_time += update_interval

            if time_elapsed == 300:  # Re-authenticate every 5 minutes
                log.info("Re-authenticating")
                self.get_auth(verbose=True)
                time_elapsed = 0  # Reset time_elapsed after re-authentication
                next_update_time = update_interval  # Reset next_update_time after re-authentication

        log.info("Scan finished")
        time.sleep(5)  # small delay before export




    def export_scan(self):
        """
    Exports the scan results to various file formats.
    Yes the tmp.csv file is needed.

    Returns:
        str: The name of the exported scan file.

        """
        try:
            scan_info = self.get_scan_info()
            scan_id = scan_info["id"]
            status = scan_info["status"]
            if status == "running" or status == "pending":
                log.error("Scan still running, waiting for it to finish ...")
                self.monitor_scan()
                
            response = requests.get(self.url + f"/reports/custom/templates", headers=self.token_auth, verify=False)
            templates = json.loads(response.text)
            with open("tmp.csv", "w") as f:
                for template in templates:
                    template_id = template['id']
                    output = f"{template_id},{template['name']}"
                    f.write(output)
                    f.write('\n')

            # Open the file for reading
            with open('tmp.csv', 'r') as f:
                csv_reader = csv.reader(f)
                # Read the file line by line
                for row in csv_reader:
                    if row[1] == 'Detailed Vulnerabilities By Plugin':
                        template_id = row[0]

            os.remove('tmp.csv')   

            # format handlers
            formats = {
                "csv": {
                    "format": "csv",
                    "template_id": "",
                    "reportContents": {
                        "csvColumns": {
                            "id": True,
                            "cve": True,
                            "cvss": True,
                            "risk": True,
                            "hostname": True,
                            "protocol": True,
                            "port": True,
                            "plugin_name": True,
                            "synopsis": True,
                            "description": True,
                            "solution": True,
                            "see_also": True,
                            "plugin_output": True,
                            "stig_severity": True,
                            "cvss3_base_score": True,
                            "cvss_temporal_score": True,
                            "cvss3_temporal_score": True,
                            "risk_factor": True,
                            "references": True,
                            "plugin_information": True,
                            "exploitable_with": True
                        }
                    },
                    "extraFilters": {
                        "host_ids": [],
                        "plugin_ids": []
                    }
                },
                "nessus": {
                    "format": "nessus"
                },
                "html": {
                    "format": "html",
                    "template_id": template_id,
                    "csvColumns": {},
                    "formattingOptions": {},
                    "extraFilters": {
                        "host_ids": [],
                        "plugin_ids": []
                    }
                }
            }

            for k,v in formats.items():
            
                log.info(f"Exporting {k} file")
                # get scan token
                data = v
                response = requests.post(self.url + "/scans/" + str(scan_id) + "/export", headers=self.token_auth, json=data, verify=False)
                if response.status_code != 200:
                    raise Exception(f"Exporting {k} file failed with status code {response.status_code}")
                scan_token = json.loads(response.text)["token"]

                # download file
                while True:
                    response = requests.get(self.url + "/tokens/" + scan_token + "/download", headers=self.token_auth, verify=False)
                    if "not ready" in response.text:
                        time.sleep(5)

                    elif response.status_code == 200:
                        file_path = os.path.join(self.output_folder, self.project_name + f".{k}")
                        open(file_path, "wb").write(response.content)
                        log.info(f"Done. Scan file exported to \"{file_path}\"")
                        break

                    else:
                        raise Exception(f"Downloading {k} file failed with status code {response.status_code}")

            return self.project_name + ".nessus"

        except Exception as e:
            log.error(f"Error exporting report - ensure the project name is correct{e}")
            sys.exit()
                

    # Mode handlers
    def deploy(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(True)
        self.monitor_scan()
        file_path = self.export_scan()


    def create(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(False)

    def launch(self):
        self.scan_action("launch")
        self.monitor_scan()
        scan_file = self.export_scan()

    def monitor(self):
        self.monitor_scan()
        scan_file = self.export_scan()

    def pause(self):
        self.scan_action("pause")

    def resume(self):
        self.scan_action("resume")
        self.monitor_scan()
        scan_file = self.export_scan()

    def preserve(self):
        self.monitor_scan()
        scan_file = self.export_scan()

    def export(self):
        self.export_scan()
