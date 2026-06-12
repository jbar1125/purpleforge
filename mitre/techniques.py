"""Static metadata for the techniques PurpleForge covers in v1.

prevalence_weight: relative importance of each technique for the weighted
coverage metric. Derived from Red Canary Threat Detection Report (2024) and
MITRE ATT&CK technique frequency data across tracked incident reports.
Higher weight = more commonly seen in real-world intrusions = more critical to cover.
Range: 0.0–1.0. Weights are NOT normalised (CoverageMatrix handles that).
"""

TECHNIQUES = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts against known accounts",
        "prevalence_weight": 0.85,  # perennially top-10; easy to automate at scale
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "RDP login from an unusual source host",
        "prevalence_weight": 0.75,  # dominant lateral movement vector in ransomware ops
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Task creation via schtasks.exe or Task Scheduler API",
        "prevalence_weight": 0.70,  # reliable LOLBin persistence; used by many threat actors
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "New local user account created outside normal provisioning",
        "prevalence_weight": 0.60,  # moderate — often paired with other persistence
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "LSASS process accessed by a non-system process",
        "prevalence_weight": 0.95,  # #1 credential-theft technique; present in nearly all APT ops
    },
    "T1547.001": {
        "name": "Boot/Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "description": "Persistence via HKCU or HKLM Run registry keys",
        "prevalence_weight": 0.65,  # common but often superseded by service/task persistence
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "PowerShell execution with encoded or obfuscated command",
        "prevalence_weight": 0.90,  # #1 execution technique (Red Canary 2024); ubiquitous
    },
    "T1055.001": {
        "name": "Process Injection: Dynamic-link Library Injection",
        "tactic": "Defense Evasion",
        "description": "Remote thread created in a target process (CreateRemoteThread)",
        "prevalence_weight": 0.80,  # core defense-evasion; used by Cobalt Strike, Meterpreter
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Windows Defender disabled via registry key modification",
        "prevalence_weight": 0.65,  # common pre-ransomware step; high signal when seen
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": "Abuse of valid Azure AD / Entra ID credentials — legacy-auth, risky, or anonymized-IP sign-in success",
        "prevalence_weight": 0.70,  # fastest-growing vector as orgs move workloads to cloud
    },
    "T1114.003": {
        "name": "Email Collection: Email Forwarding Rule",
        "tactic": "Collection",
        "description": "External mail exfiltration via M365 inbox/mailbox forwarding rules (BEC hallmark)",
        "prevalence_weight": 0.55,  # BEC-specific; high impact but narrower scope
    },
}
