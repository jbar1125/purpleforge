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
}
