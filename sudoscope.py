import re
from typing import Dict, List, Tuple, Any

SudoEntry = Dict[str, Any]

# Function to read input files (you can extend this to actually read files)
def read_input_files() -> Dict[str, str]:
    # Example: Read a mock sudoers file content for demonstration
    return {
        "/etc/sudoers": """
# Sample sudoers file
# User privilege specification
root    ALL=(ALL) ALL
ubuntu  ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /bin/ls
%admin  ALL=(ALL) ALL
guest   ALL=(ALL) NOPASSWD: /usr/bin/apt-get
sysadmin ALL=(ALL) /usr/bin/apt-get, /usr/bin/reboot
"""
    }

# Function to parse file content
def parse_file_content(input_files: Dict[str, str]) -> List[SudoEntry]:
    parsed_rules: List[SudoEntry] = []

    # Regular expression to parse sudoers file entries
    SUDO_RULE_REGEX = re.compile(r'^\s*([a-zA-Z0-9_%]+)\s+([a-zA-Z0-9_\-]+|ALL)\s*=\s*\((.*?)\)\s+(.*)$')

    for filename, content in input_files.items():
        print(f"Reading file: {filename}")  # Debugging line

        for line_num, line in enumerate(content.splitlines()):
            no_whitespace = line.strip()

            # Skip empty lines and comments
            if not no_whitespace or no_whitespace.startswith('#') or no_whitespace.startswith('Defaults'):
                continue

            # Find match within the regular expression
            found_match = SUDO_RULE_REGEX.search(no_whitespace)

            if found_match:
                try:
                    users, host, run_as_unsplit, commands_unsplit = found_match.groups()

                    # Split user and group (e.g. %admin or user)
                    run_as_user, run_as_group = run_as_unsplit.split(':', 1) if ':' in run_as_unsplit else (run_as_unsplit, 'ALL')

                    # Split commands
                    commands = [cmd.strip() for cmd in commands_unsplit.split(',')]

                    parsed_entry = {
                        "file": filename,
                        "line": line_num + 1,
                        "user_or_group": users,
                        "is_group": users.startswith('%'),
                        "host": host,
                        "runas_user": run_as_user if run_as_user else "ALL",
                        "runas_group": run_as_group if run_as_group else "ALL",
                        "commands": commands,
                        "nopasswd": "NOPASSWD:" in no_whitespace.upper(),
                        "raw_rule": no_whitespace,
                        "dangerous": False,
                        "danger_reason": ""
                    }

                    parsed_rules.append(parsed_entry)

                except Exception as e:
                    print(f" [WARNING] failed to fully parse rule in {filename} line {line_num + 1}: {no_whitespace} (Error: {e})")

    return parsed_rules

# Function to write the findings to an output file
def write_findings_to_file(findings: List[SudoEntry], output_filename: str):
    with open(output_filename, "w") as output_file:
        output_file.write("Sudo Access Findings:\n")
        for entry in findings:
            output_file.write(f"User/Group: {entry['user_or_group']}\n")
            output_file.write(f"Is Group: {entry['is_group']}\n")
            output_file.write(f"Host: {entry['host']}\n")
            output_file.write(f"Run As User: {entry['runas_user']}\n")
            output_file.write(f"Run As Group: {entry['runas_group']}\n")
            output_file.write(f"Commands: {', '.join(entry['commands'])}\n")
            output_file.write(f"NOPASSWD: {'Yes' if entry['nopasswd'] else 'No'}\n")
            output_file.write(f"Dangerous: {'Yes' if entry['dangerous'] else 'No'}\n")
            if entry['dangerous']:
                output_file.write("Reasons:\n")
                output_file.write(f"{entry['danger_reason']}")
            output_file.write(f"Raw Rule: {entry['raw_rule']}\n")
            output_file.write("-" * 40 + "\n")
        print(f"Findings written to {output_filename}")

# Function to display the findings and check for dangerous entries
def display_findings():
    input_files = read_input_files()

    parsed_results = parse_file_content(input_files)

    # List of sensitive or dangerous commands to check
    dangerous_commands = ["shutdown", "reboot", "init", "poweroff", "systemctl", "/usr/bin/sudo"]

    # Perform checks and generate output
    for entry in parsed_results:
        # Default to False for dangerous if no conditions are met
        entry['dangerous'] = False
        entry['danger_reason'] = ""

        # Perform dangerous checks directly here

        # Check for NOPASSWD for ALL commands
        if entry['nopasswd'] and 'ALL' in entry['commands']:
            entry['dangerous'] = True
            entry['danger_reason'] += "Allows running any command without a password (NOPASSWD: ALL). This can lead to privilege escalation without authentication.\n"

        # Run as ALL for both user and group is risky
        if entry['runas_user'] == 'ALL' and entry['runas_group'] == 'ALL':
            entry['dangerous'] = True
            entry['danger_reason'] += "Allows running commands as any user and any group, which can lead to excessive privileges and potential privilege escalation.\n"

        # Check if any command is a dangerous system command
        for cmd in entry['commands']:
            if any(dangerous_command in cmd for dangerous_command in dangerous_commands):
                entry['dangerous'] = True
                entry['danger_reason'] += f"Allows execution of dangerous system command: {cmd}. This can lead to system disruption or privilege escalation.\n"

        # Check for no host restrictions (ALL)
        if entry['host'] == 'ALL':
            entry['dangerous'] = True
            entry['danger_reason'] += "No host restrictions (host: ALL) allow this rule to be applied from any host, making the system vulnerable to remote attacks.\n"

    # Write results to a file
    write_findings_to_file(parsed_results, "sudoscope_findings.txt")

# Main execution
if __name__ == "__main__":
    display_findings()
