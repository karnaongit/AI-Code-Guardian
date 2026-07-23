RULES = {

    "eval": {
        "category": "Code Injection",
        "severity": "Critical",
        "recommendation": "Avoid eval()."
    },

    "exec": {
        "category": "Code Injection",
        "severity": "Critical",
        "recommendation": "Avoid exec()."
    },

    "system": {
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Avoid os.system()."
    },

    "popen": {
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Avoid os.popen()."
    },

    "run": {
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments."
    },

    "call": {
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments."
    },

    "check_output": {
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments."
    },

    "md5": {
        "category": "Weak Cryptography",
        "severity": "Medium",
        "recommendation": "Use bcrypt, Argon2 or SHA-256."
    },

    "sha1": {
        "category": "Weak Cryptography",
        "severity": "Medium",
        "recommendation": "SHA1 is deprecated."
    },

    "loads": {
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Avoid unsafe deserialization."
    },

    "load": {
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Use safe_load()."
    }
}