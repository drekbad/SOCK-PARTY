import os
import sys
import argparse
from collections import defaultdict

# Function to filter the TRUE lines from the input file
def filter_true_lines(file_path):
    true_lines = []
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == 'TRUE':
                ip = parts[1]
                domain_user = parts[2]
                true_lines.append((ip, domain_user))
    return true_lines

# Function to display the unique systems and users count
def display_unique_counts(true_lines, cache_ips):
    unique_systems = set()
    users = defaultdict(set)

    for ip, domain_user in true_lines:
        unique_systems.add(ip)
        users[ip].add(domain_user)

    print(f"Number of unique systems: {len(unique_systems)}")
    print(f"Number of unique users: {sum(len(u) for u in users.values())}")

    if cache_ips:
        print(f"Cache file exists. {len(cache_ips)} unique IPs found in the cache.")

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
        target = input(f"Enter an IP, a comma/space/semicolon separated list of IPs, or 'all': ").strip()
        if target.lower() == 'all':
            return list(available_ips)
        
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
    pass

# Function to display the main menu
def display_menu(title, options, back_option=True):
    print(f"\n\033[1m\033[4m{title}\033[0m")
    for i, option in enumerate(options, start=1):
        print(f"{i}. {option}")
    if back_option:
        print("0. Back")
    print("q. Quit")

# Function to handle the action selection and execution
def handle_action_selection(category, true_lines, cache_file, cache_actions):
    options = {
        "Enumeration": [
            "\033[1m[ DIRECTORY ] Domain info\033[0m",
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
            "[ UNAVAILABLE ] nxc GET",
            "[ UNAVAILABLE ] nxc PUT",
            "[ UNAVAILABLE ] nxc command (cmd.exe) - (WARNING: no shell or interactives, only execution or stdout)",
            "[ UNAVAILABLE ] nxc command (PowerShell) - (WARNING: no shell or interactives, only execution or stdout)",
            "[ UNAVAILABLE ] Disable Windows Defender",
            "[ UNAVAILABLE ] Disable AppLocker",
            "[ UNAVAILABLE ] AMSI Bypass"
        ],
        "Credentials": [
            "Secretsdump",
            "[ UNAVAILABLE ] nxc SAM",
            "[ UNAVAILABLE ] nxc LSA",
            "[ UNAVAILABLE ] nxc LSASS",
            "[ UNAVAILABLE ] nxc nanodump"
        ],
        "Persistence": [
            "\033[1m[ DIRECTORY ] Create local admin\033[0m",
            "[ UNAVAILABLE ] Retrieve remote file (download)",
            "[ UNAVAILABLE ] Send local file (upload)"
        ]
    }
    
    display_menu(category, options[category])

    selection = input("Select an action (or 'q' to quit): ").strip().lower()
    
    if selection == 'q':
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
            if "[ DIRECTORY ]" in action:
                sub_category = action.replace("\033[1m[ DIRECTORY ]", "").strip()
                handle_action_selection(sub_category, true_lines, cache_file, cache_actions)
                return
            
            # Handle actual actions
            action_name = action.split("[")[0].strip()  # Extract the action name
            available_ips = set(ip for ip, _ in true_lines)

            # Select systems to target
            target_ips = select_systems(available_ips)

            # Execute command for each selected IP
            for ip, domain_user in true_lines:
                if ip in target_ips:
                    execute_command(ip, domain_user, action_name, args.output_file, args.grep)
                    update_cache(cache_file, action_name, [ip])
            
            # Update the cache indicators
            completed = set(cache_actions.get(action_name, []))
            if len(completed) == len(available_ips):
                print(f"\033[1;32m[ COMPLETE ] {action_name}\033[0m")
            else:
                print(f"\033[1;33m[ PARTIAL ] {action_name}\033[0m")
    
    else:
        print("Invalid selection. Please try again.")

def main():
    parser = argparse.ArgumentParser(description="Process ntlmrelayx socks output.")
    parser.add_argument("input_file", help="Path to the input text file.")
    parser.add_argument("output_file", help="Path to the output file.")
    parser.add_argument("--grep", help="Grep the output of commands.", default=None)
    parser.add_argument("--no-cache", action="store_true", help="Run without using the cache file.")
    
    args = parser.parse_args()

    # Load and filter the input file
    true_lines = filter_true_lines(args.input_file)

    # Parse or initialize the cache
    cache_file = "cache.txt"
    cache_ips, cache_actions = parse_cache(cache_file) if not args.no_cache else (set(), {})

    # Display system and user information
    display_unique_counts(true_lines, cache_ips)

    # Main menu
    while True:
        categories = ["Enumeration", "Execution", "Credentials", "Persistence"]
        display_menu("Main Menu", categories, back_option=False)

        selection = input("Select a category (or 'q' to quit): ").strip().lower()
        
        if selection == 'q':
            sys.exit()
        
        if selection.isdigit():
            selection = int(selection)
            if 0 < selection <= len(categories):
                handle_action_selection(categories[selection - 1], true_lines, cache_file, cache_actions)
            else:
                print("Invalid selection. Please try again.")
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
