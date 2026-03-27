NET SENTINEL — README
======================

A command-line network and system security analyzer built in Python.
Tools: Host Scanner | Pass Validator | Auth Monitor | Shield Rules

----------------------------------------------------------
REQUIREMENTS
----------------------------------------------------------
- Python 3.7 or higher
- No external libraries needed (uses only built-in modules)

----------------------------------------------------------
QUICK START
----------------------------------------------------------
Step 1: Open VS Code and load your project folder
        

Step 2: Open the integrated terminal

Step 3: Run the full demo
        python net_sentinel.py demo

----------------------------------------------------------
FEATURES & USAGE
----------------------------------------------------------

1. HOST SCANNER
----------------
Scans a target host for active TCP ports within a given range.

Command:
  python net_sentinel.py hostscan <ip> --low <port> --high <port>

Example:
  python net_sentinel.py hostscan 192.168.1.1 --low 1 --high 1024

Output:
  ====================================================
    HOST SCANNER  |  192.168.1.1  |  Ports 1 to 1024
  ====================================================
    >> Port 22     STATUS: ACTIVE   Service: ssh
    >> Port 80     STATUS: ACTIVE   Service: http
    >> Port 443    STATUS: ACTIVE   Service: https
  ====================================================
    Total Active Ports Found: 3


2. PASS VALIDATOR
------------------
Validates password strength against 6 security rules and
gives a security verdict.

Command:
  python net_sentinel.py validate "<password>"

Example:
  python net_sentinel.py validate "N3tS3nt!nel#2024"

Rules Checked:
  - Length at least 12 characters
  - Has uppercase letter (A-Z)
  - Has lowercase letter (a-z)
  - Has numeric digit (0-9)
  - Has special symbol (non-alphanumeric)
  - No dictionary words (pass, admin, root, test, login, etc.)

Verdict Scale:
  6/6 --> VAULT-GRADE
  5/6 --> SECURE
  4/6 --> ACCEPTABLE
  <4  --> INSECURE


3. AUTH MONITOR
----------------
Reads a local authentication log file and detects suspicious
login activity and brute-force attempts.

Command:
  python net_sentinel.py monitor <logfile>

Example:
  python net_sentinel.py monitor auth.log

Note:
  - Create a local auth.log file in your project folder for testing
  - On Linux/Mac: python net_sentinel.py monitor /var/log/auth.log

Detects:
  - Verified successful logins (username + IP address)
  - Failed login attempts (username + IP address)
  - IPs with 5 or more failures flagged as [!!! BRUTE FORCE ALERT]

Sample Output:
  [+] Verified Logins : 1
      john            203.0.113.10

  [-] Login Failures  : 6
  [-] Suspicious IPs  : 1

      192.168.1.55         6 hit(s)  [!!! BRUTE FORCE ALERT]


4. SHIELD RULES (Firewall Generator)
--------------------------------------
Generates iptables firewall rules to block a malicious IP
and whitelist specific ports.

Print rules to terminal:
  python net_sentinel.py shield --block <IP> --open <port1> <port2> ...

Export rules to a file:
  python net_sentinel.py shield --block <IP> --export rules.sh

Examples:
  python net_sentinel.py shield --block 172.16.0.55 --open 22 80 443
  python net_sentinel.py shield --block 172.16.0.55 --export rules.sh

Generated Rules Include:
  - Flush and zero existing iptables rules
  - REJECT rules for blacklisted IP (INPUT + FORWARD chains)
  - ACCEPT rules for whitelisted ports with state matching
  - Default policy: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT


5. DEMO MODE
-------------
Runs all four tools with built-in sample data.

Command:
  python net_sentinel.py demo


----------------------------------------------------------
PROJECT STRUCTURE
----------------------------------------------------------
A28/
  |-- net_sentinel.py      (Main toolkit file)
  |-- auth.log             (Sample log file for testing)
  |-- rules.sh             (Exported shield rules output)
  |-- README_NetSentinel.txt  (This documentation)


----------------------------------------------------------
ALL COMMANDS REFERENCE
----------------------------------------------------------
  python net_sentinel.py demo
  python net_sentinel.py hostscan 192.168.1.1 --low 1 --high 1024
  python net_sentinel.py validate "YourPassword@123"
  python net_sentinel.py monitor auth.log
  python net_sentinel.py shield --block 172.16.0.55 --open 22 80 443
  python net_sentinel.py shield --block 172.16.0.55 --export rules.sh


----------------------------------------------------------
RUNNING IN VS CODE
----------------------------------------------------------
1. Open VS Code
2. File > Open Folder > select your project folder
3. Press Ctrl + ` to open terminal
4. Terminal opens directly in your project folder
5. Run any command above without needing to navigate manually

TIP: Always use VS Code built-in terminal to avoid
     "file not found" or "not recognized" errors.


----------------------------------------------------------
COMMON ERRORS & FIXES
----------------------------------------------------------
Error : No such file or directory
Cause : Terminal not pointing to project folder
Fix   : Use VS Code terminal OR run: cd path\to\your\folder

Error : 'net_sentinel.py' is not recognized
Cause : Missing 'python' prefix
Fix   : Always type --> python net_sentinel.py ...

Error : python not found
Cause : Python not installed or not added to PATH
Fix   : Install Python 3.7+ from https://python.org
        Check "Add Python to PATH" during installation

Error : Cannot locate log file
Cause : auth.log not present in current folder
Fix   : Create a local auth.log file in the same folder


----------------------------------------------------------
TOOL SUMMARY
----------------------------------------------------------
  hostscan  -->  Scans active TCP ports on a target host
  validate  -->  Checks password strength with 6 rules
  monitor   -->  Analyses auth logs for login threats
  shield    -->  Generates iptables firewall shield rules
  demo      -->  Runs full demonstration of all tools



