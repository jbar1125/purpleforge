"""Static metadata for the techniques PurpleForge covers in v1."""

TECHNIQUES = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts against known accounts",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "RDP login from an unusual source host",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Task creation via schtasks.exe or Task Scheduler API",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "New local user account created outside normal provisioning",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "LSASS process accessed by a non-system process",
    },
    "T1547.001": {
        "name": "Boot/Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "description": "Persistence via HKCU or HKLM Run registry keys",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "PowerShell execution with encoded or obfuscated command",
    },
    "T1055.001": {
        "name": "Process Injection: Dynamic-link Library Injection",
        "tactic": "Defense Evasion",
        "description": "Remote thread created in a target process (CreateRemoteThread)",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Windows Defender disabled via registry key modification",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": "Abuse of valid Azure AD / Entra ID credentials — legacy-auth, risky, or anonymized-IP sign-in success",
    },
    "T1114.003": {
        "name": "Email Collection: Email Forwarding Rule",
        "tactic": "Collection",
        "description": "External mail exfiltration via M365 inbox/mailbox forwarding rules (BEC hallmark)",
    },
}
