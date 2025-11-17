import re
from typing import override
from colorama import Fore


class SudoEntry:
    def __init__(
        self,
        user: str | None,
        group: str | None,
        runas_user: str,
        runas_group: str,
        host: str,
        cmd: list[str],
        nopasswd: bool,
    ) -> None:
        self.user: str | None = user
        self.group: str | None = group
        self.runas_user: str = runas_user
        self.runas_group: str = runas_group
        self.host: str = host
        self.cmd: list[str] = cmd
        self.nopasswd: bool = nopasswd

    @override
    def __format__(self, format_spec: str, /) -> str:
        ret: str = ""
        if self.user:
            ret += f"{Fore.GREEN}User{Fore.RESET}: {self.user}\n"
        elif self.group:
            ret += f"{Fore.YELLOW}Group{Fore.RESET}: {self.group}\n"
        if self.runas_user != "ALL":
            ret += f"Become user: {self.runas_user}\n"
        if self.runas_group != "ALL":
            ret += f"Become group: {self.runas_group}\n"
        if self.host != "ALL":
            ret += f"Host: {self.host}\n"
        if self.nopasswd:
            ret += Fore.RED + "NOPASSWD\n" + Fore.RESET
        if len(self.cmd) == 1:
            if self.cmd[0] == "ALL":
                ret += Fore.RED + "ALL COMMANDS" + Fore.RESET
            else:
                ret += f"Command: {self.cmd[0]}"
        else:
            ret += f"Commands:{''.join('\n - ' + x for x in self.cmd)}"

        return ret


# Function to read input files (you can extend this to actually read files)
def read_input_files() -> dict[str, str]:
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
def parse_file_content(input: dict[str, str]) -> list[SudoEntry]:
    parsed_rules: list[SudoEntry] = []

    # Regular expression to parse sudoers file entries
    SUDO_RULE_REGEX = re.compile(
        r"^\s*([a-zA-Z0-9_%]+)\s+([a-zA-Z0-9_\-]+|ALL)\s*=\s*\((.*?)\)\s+(.*)$"
    )

    for filename, content in input.items():
        print(f"Reading file: {filename}")  # Debugging line

        for line_num, line in enumerate(content.splitlines()):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue

            # Find match within the regular expression
            found_match = SUDO_RULE_REGEX.search(line)

            if found_match:
                try:
                    users, host, run_as_unsplit, commands_unsplit = found_match.groups()

                    # Split user and group (e.g. %admin or user)
                    run_as_user, run_as_group = (
                        run_as_unsplit.split(":", 1)
                        if ":" in run_as_unsplit
                        else (run_as_unsplit, "ALL")
                    )

                    # Split commands
                    commands = [cmd.strip() for cmd in commands_unsplit.split(",")]

                    # Remove NOPASSWD from first command if present
                    commands[0] = commands[0].removeprefix("NOPASSWD: ")

                    parsed_entry = SudoEntry(
                        user=users if not users.startswith("%") else None,
                        group=users[1:] if users.startswith("%") else None,
                        runas_user=run_as_user if run_as_user else "ALL",
                        runas_group=run_as_group if run_as_group else "ALL",
                        host=host,
                        cmd=commands,
                        nopasswd="NOPASSWD:" in line.upper(),
                    )

                    parsed_rules.append(parsed_entry)

                except Exception as e:
                    print(
                        f" [WARNING] failed to fully parse rule in {filename} line {line_num + 1}: {line} (Error: {e})"
                    )

    return parsed_rules


# Function to display the findings and check for dangerous entries
def display_findings(input: list[SudoEntry]):
    for entry in input:
        print(f"{entry}")
        print("-" * 20)

    output_filename = "sudoscope_findings.txt"
    with open(output_filename, "w") as output_file:
        _ = output_file.write("Sudo Access Findings:\n")
        for entry in input:
            _ = output_file.write(f"{entry}\n")
            _ = output_file.write("-" * 40 + "\n")
        print(f"Findings written to {output_filename}")


# Main execution
if __name__ == "__main__":
    input = read_input_files()
    parsed_results = parse_file_content(input)
    display_findings(parsed_results)
