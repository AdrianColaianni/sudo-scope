import re
from typing import List
from colorama import Fore
import os

# Define the SudoEntry class first
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

# Function to read input files
def read_input_files() -> dict[str, str]:
	file_contents: dict[str, str] = {}

	if os.path.exists("/etc/sudoers"):
    	try:
        	with open("/etc/sudoers", "r") as f:
            	file_contents["/etc/sudoers"] = f.read()
    	except Exception as e:
        	print(f"[WARNING] Could not read /etc/sudoers: {e}")

	sudoers_d = "/etc/sudoers.d"
	if os.path.isdir(sudoers_d):
    	for filename in os.listdir(sudoers_d):
        	path = os.path.join(sudoers_d, filename)
        	if os.path.isfile(path):
            	try:
                	with open(path, "r") as f:
                    	file_contents[path] = f.read()
            	except Exception as e:
                	print(f"[WARNING] Could not read {path}: {e}")

	return file_contents

# Function to parse file content
def parse_file_content(input: dict[str, str]) -> list[SudoEntry]:
	parsed_rules: list[SudoEntry] = []
	SUDO_RULE_REGEX = re.compile(
    	r"^\s*([a-zA-Z0-9_%]+)\s+([a-zA-Z0-9_\-]+|ALL)\s*=\s*\((.*?)\)\s+(.*)$"
	)

	for filename, content in input.items():
    	print(f"Reading file: {filename}")

    	for line_num, line in enumerate(content.splitlines()):
        	line = line.strip()
        	if not line or line.startswith("#") or line.startswith("Defaults"):
            	continue

        	found_match = SUDO_RULE_REGEX.search(line)
        	if found_match:
            	try:
                	users, host, run_as_unsplit, commands_unsplit = found_match.groups()
                	run_as_user, run_as_group = (
                    	run_as_unsplit.split(":", 1)
                    	if ":" in run_as_unsplit
                    	else (run_as_unsplit, "ALL")
                	)
                	commands = [cmd.strip() for cmd in commands_unsplit.split(",")]
                	commands[0] = commands[0].removeprefix("NOPASSWD:").strip()

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
                	print(f" [WARNING] failed to fully parse rule in {filename} line {line_num + 1}: {line} (Error: {e})")

	return parsed_rules

# Function to display sudo findings in HTML
def display_findings_html(input: List[SudoEntry]):
	html_content = """
	<html>
	<head>
    	<title>Sudo Access Findings</title>
    	<style>
        	body { font-family: Arial, sans-serif; margin: 20px; }
        	h1 { color: #333; }
        	.entry { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; }
        	.entry h2 { color: #444; }
        	.entry p { margin: 5px 0; }
        	.danger { color: red; font-weight: bold; }
        	.warning { color: orange; font-weight: bold; }
        	.entry ul { list-style-type: none; padding-left: 20px; }
        	.entry ul li { margin: 5px 0; }
    	</style>
	</head>
	<body>
    	<h1>Sudo Access Findings</h1>
	"""

	for entry in input:
    	html_content += """
    	<div class="entry">
        	<h2>{}</h2>
        	<p><strong>User:</strong> {}</p>
        	<p><strong>Group:</strong> {}</p>
        	<p><strong>Become User:</strong> {}</p>
        	<p><strong>Become Group:</strong> {}</p>
        	<p><strong>Host:</strong> {}</p>
        	<p><strong>Commands:</strong></p>
        	<ul>
    	""".format(
        	"Dangerous Entry" if entry.nopasswd else "Sudo Entry",
        	entry.user or "None",
        	entry.group or "None",
        	entry.runas_user,
        	entry.runas_group,
        	entry.host,
    	)

    	# List the commands
    	for cmd in entry.cmd:
        	html_content += f"<li>{cmd}</li>"

    	# If the entry has "NOPASSWD", mark it as dangerous
    	if entry.nopasswd:
        	html_content += "<p class='danger'>This entry is configured with NOPASSWD.</p>"

    	html_content += "</ul></div>"

	# Close the HTML tags
	html_content += "</body></html>"

	# Write the HTML to a file
	output_filename = "sudoscope_findings.html"
	with open(output_filename, "w") as output_file:
    	output_file.write(html_content)

	print(f"HTML Findings written to {output_filename}")

# Main execution
if __name__ == "__main__":
	input_files = read_input_files()
	parsed_results = parse_file_content(input_files)
	display_findings_html(parsed_results)
