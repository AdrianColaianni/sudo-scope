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
ubuntu  ALL=(ALL) NOPASSWD: /usr/bin/apt-get
%admin  ALL=(ALL) ALL
"""
    }

# Function to parse file content
def parse_file_content(input_files: Dict[str, str]) -> List[SudoEntry]:
    parsed_rules: List[SudoEntry] = []

    # Regular expression to parse sudoers file entries
    SUDO_RULE_REGEX = re.compile(r'^\s*([a-zA-Z0-9_%]+)\s+([a-zA-Z0-9_\-]+|ALL)\s*=\s*\((.*?)\)\s+(.*)$')

    for filename, content in input_files.items():
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

                    # Check NOPASSWD flag
                    is_nopasswd = "NOPASSWD:" in no_whitespace.upper()

                    # Clean run_as components
                    run_as_user = run_as_user.replace("NOPASSWD:", "").replace("PASSWD:", "").strip()
                    run_as_group = run_as_group.replace("NOPASSWD:", "").replace("PASSWD:", "").strip()

                    # Add to parsed results
                    parsed_rules.append({
                        "file": filename,
                        "line": line_num + 1,
                        "user_or_group": users,
                        "is_group": users.startswith('%'),
                        "host": host,
                        "runas_user": run_as_user if run_as_user else "ALL",
                        "runas_group": run_as_group if run_as_group else "ALL",
                        "commands": commands,
                        "nopasswd": is_nopasswd,
                        "raw_rule": no_whitespace
                    })
                except Exception as e:
                    print(f" [WARNING] failed to fully parse rule in {filename} line {line_num + 1}: {no_whitespace} (Error: {e})")
    return parsed_rules

# Function to display the findings
def display_findings():
    input_files = read_input_files()

    parsed_results = parse_file_content(input_files)

    if parsed_results:
        print("Sudo Access Findings:")
        for entry in parsed_results:
            print(f"User/Group: {entry['user_or_group']}")
            print(f"Is Group: {entry['is_group']}")
            print(f"Host: {entry['host']}")
            print(f"Run As User: {entry['runas_user']}")
            print(f"Run As Group: {entry['runas_group']}")
            print(f"Commands: {', '.join(entry['commands'])}")
            print(f"NOPASSWD: {'Yes' if entry['nopasswd'] else 'No'}")
            print(f"Raw Rule: {entry['raw_rule']}")
            print("-" * 40)
    else:
        print("No sudo rules found.")

# Main execution
if __name__ == "__main__":
    display_findings()
