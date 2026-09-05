from config.cvss import CVSS_KEY_MAP

# ===============================
# CVSS SHORT → UI LABEL MAPPING
# ===============================
CVSS_KEY_MAP = {
    "AV": "Attack Vector",
    "AC": "Complexity",
    "PR": "Privileges",
    "UI": "User Interaction",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}

# ---------------------------------------------------------
# 2. LOGIC MAPPINGS
# ---------------------------------------------------------
MITRE_RISK_WEIGHT = {
    "Initial Access": 4,
    "Execution": 4,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 3,
    "Credential Access": 5,
    "Discovery": 2,
    "Lateral Movement": 4,
    "Collection": 2,
    "Command and Control": 5,
    "Exfiltration": 5,
    "Impact": 5,
    "Unknown": 1,
}

MITRE_MAP = {
    "SQLI_TIME_BLIND": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "SQLI_ERROR": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "SQLI_BOOLEAN": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "XSS_REFLECTED": {
        "TID": "T1189",
        "Tactic": "Initial Access",
        "Technique": "Drive-by Compromise",
    },
    "DOM_XSS": {
        "TID": "T1059",
        "Tactic": "Execution",
        "Technique": "Command and Scripting Interpreter",
    },
    "LFI_TRAVERSAL": {
        "TID": "T1083",
        "Tactic": "Discovery",
        "Technique": "File and Directory Discovery",
    },
    "RCE_COMMAND_INJECTION": {
        "TID": "T1059",
        "Tactic": "Execution",
        "Technique": "Command and Scripting Interpreter",
    },
    "WORKFLOW_STATE_BYPASS": {
        "TID": "T1565",
        "Tactic": "Impact",
        "Technique": "Data Manipulation",
    },
    "AUTHZ_ADMIN_ACCESS": {
        "TID": "T1068",
        "Tactic": "Privilege Escalation",
        "Technique": "Exploitation for Privilege Escalation",
    },
    "Generic": {
        "TID": "T0000",
        "Tactic": "Unknown",
        "Technique": "Unknown",
    },
}


PAYLOAD_PRESETS = {
    "SQL Injection": [
        ("' OR '1'='1' --", 15),
        ("' UNION SELECT NULL,NULL --", 20),
        ("admin'--", 10),
    ],
    "XSS": [
        ("<script>alert(1)</script>", 20),
        ('" onmouseover="alert(1)', 15),
        ("<img src=x onerror=alert(1)>", 18),
    ],
    "LFI": [
        ("../../../../etc/passwd", 20),
        ("../etc/passwd%00", 18),
        ("../../../../windows/win.ini", 15),
    ],
    "Generic": [("test123", 5), ("' OR 1=1 --", 8)],
}