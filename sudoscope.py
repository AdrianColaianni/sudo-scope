import re
from typing import Dict, List, Tuple, Any

SudoEntry = Dict[str, Any]


def read_input_files():
    return

def parse_file_content(input_files: Dict[str, str]) -> List[SudoEntry]:
    parsed_rules: List[SudoEntry] = []

    # Expression for parsing the content
    # ^\s*: parse start of line
    # ([a-zA-Z0-9_%]+): parses User/Group
    # \s+: requires spacing
    # (ALL|): parses host
    # \((.*)\): parses Run_As
    # \s+ requires spacing
    # (.*) parses command list
    SUDO_RULE_REGEX = re.compile(r'^\s*([a-zA-Z0-9_%]+)\s+([a-zA-Z0-9_\-]+|ALL)\s*=\s*\((.*?\)\s+(.*)$')
   
    for filename, content in input_files.items():
        for line_num, line in enumerate(content.splitlines()):
            
            # Clean line from white space
            no_whitespace = line.strip()

            # Skip past empty lines and comments
            if not no_whitespace or no_whitespace.startswith('#') or no_whitespace.startswith('Defaults'):
                continue

            # Initialize variable to return
            parsed_results: List[SudoEntry] = []

            # Find match within the regular expression
            found_match = SUDO_RULE_REGEX.search(no_whitespace)

            if found_match:
                try:
                    users, host, run_as_unsplit, commands_unsplit = match.groups()

                    # Split user and group
                    run_as_user, run_as_group = run_as_unsplit.split(':', 1) if ':' in run_as_unsplit else (run_as_unsplit, 'ALL')

                    # Split commands
                    commands = [cmd.strip() for cmd in commands_unsplit.split(',')]

                    # Check NOPASSWD flag
                    is_nopasswd = "NOPASSWD:" in no_whitespace.upper()

                    # Clean run_as components
                    run_as_user = run_as_user.replace("NOPASSWD:", "").replace("PASSWD:", "").strip()
                    run_as_group - run_as_group.replace("NOPASSWD:", "").replace("PASSWD:", "").strip()

                    # Create structure for return value
                    parsed_results.append({
                        "file": filename, 
                        "line": line_num + 1,
                        "user_or_group": users,
                        "is_group": users.startswith('%'),
                        "host": host,
                        "runas_user": run_as_user if run_as_user else "ALL",
                        "runas_grouo": run_as_group if run_as_group else "ALL",
                        "commands": commands,
                        "nopasswd": is_nopasswd,
                        "raw_rule": no_whitespace
                    })

                except Exception as e:
                    print(f" [WARNING] failed to fully parse rule in {filename} line {line_num + 1}: {no_whitespace} (Error: {e})")
   

    return parsed_results

def display_findings(input):
    return

input = read_input_files()
output = parse_file_content(input)
display_findings(output)
