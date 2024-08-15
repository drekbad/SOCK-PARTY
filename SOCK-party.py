import os
import sys
import argparse
import requests
from collections import defaultdict

# Function to fetch data from the ntlmrelayx HTTPAPI
def fetch_data_from_api(api_url):
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        return data
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
def display_unique_counts(true_lines, cache_ips):
    unique_systems = set()
    users = defaultdict(set)

    for entry in true_lines:
        ip = entry[1]
        domain_user = entry[2]
        unique_systems.add(ip)
        users[ip].add(domain_user)

    print(f"Systems: {list(unique_systems)}")  # Debugging information
    print(f"Users: {dict(users)}")  # Debugging information

    print(f"\nNumber of unique \033[1;34msystems\033[0m: \033[1m{len(unique_systems)}\033[0m")
    print(f"Number of unique \033[1;34musers\033[0m: \033[1m{sum(len(u) for u in users.values())}\033[0m")

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
def execute_command(ip, domain_user, command, output_file, grep=None):
    # Placeholder for command execution, needs to be updated with actual commands
    # The command should use subprocess to run
    # Add logic for grep if applicable
    print(f"\033[1m[ SIMULATION ] Running {command} on {ip} ({domain_user})...\033[0m")

# Function to display the main menu
def display_menu(title, options, cache_actions, available_ips, back_option=True):
    print(f"\n\033[1m{title}\033[0m")
    for i, option in enumerate(options, start=1):
        action_name = option.split("[")[0].strip()  # Extract the action name
        if action_name in cache_actions:
            if len(cache_actions[action_name]) == len(available_ips):
                option = f"\033[1;32m[ COMPLETE ]\033[0m {option}"
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
    
    available_ips = set(entry[1] for entry in true_lines)
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
            if target_ips in {'q', 'quit', 'exit', 'back'}:
                return

            # Execute command for each selected IP
            for entry in true_lines:
                ip = entry[1]
                domain_user = entry[2]
                if ip in target_ips or target_ips == 'all':
                    execute_command(ip, domain_user, action_name, args.output_file, args.grep)
                    update_cache(cache_file, action_name, [ip])
            
            # Update the cache indicators
            completed = set(cache_actions.get(action_name, []))
            if len(completed) + len(target_ips) == len(available_ips):
                cache_actions[action_name] = available_ips  # Mark as complete
            else:
                cache_actions[action_name].update(target_ips)
    
    else:
        print("Invalid selection. Please try again.")

def main():
    parser = argparse.ArgumentParser(description="Process ntlmrelayx socks output.")
    parser.add_argument("--input_file", help="Path to the input text file (optional).")
    parser.add_argument("--output_file", help="Path to the output file (optional). If not provided, output will be printed to screen.")
    parser.add_argument("--grep", help="Grep the output of commands.", default=None)
    parser.add_argument("--no-cache", action="store_true", help="Run without using the cache file.")
    parser.add_argument("--port", type=int, default=9090, help="Port for ntlmrelayx HTTPAPI (default: 9090).")
    
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
    display_unique_counts(true_lines, cache_ips)

    # Main menu
    while True:
        categories = ["Enumeration", "Execution", "Credentials", "Persistence"]
        display_menu("Main Menu", categories, cache_actions, set(entry[1] for entry in true_lines), back_option=False)

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
