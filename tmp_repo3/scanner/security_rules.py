RULES = {

    "eval": {
        "title": "Unsafe Evaluation",
        "category": "Code Injection",
        "severity": "Critical",
        "recommendation": "Avoid eval().",
        "cwe": "CWE-94",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing dynamic code from untrusted input allows an attacker to execute arbitrary Python code."
    },

    "exec": {
        "title": "Unsafe Execution",
        "category": "Code Injection",
        "severity": "Critical",
        "recommendation": "Avoid exec().",
        "cwe": "CWE-94",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing dynamic code from untrusted input allows an attacker to execute arbitrary Python code."
    },

    "system": {
        "title": "Command Injection (system)",
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Avoid os.system().",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing OS commands with untrusted input can lead to Command Injection."
    },

    "popen": {
        "title": "Command Injection (popen)",
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Avoid os.popen().",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing OS commands with untrusted input can lead to Command Injection."
    },

    "run": {
        "title": "Subprocess Command Injection",
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments.",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing OS commands with untrusted input can lead to Command Injection."
    },

    "call": {
        "title": "Subprocess Command Injection",
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments.",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing OS commands with untrusted input can lead to Command Injection."
    },

    "check_output": {
        "title": "Subprocess Command Injection",
        "category": "Command Injection",
        "severity": "High",
        "recommendation": "Validate subprocess arguments.",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing OS commands with untrusted input can lead to Command Injection."
    },

    "md5": {
        "title": "Weak Cryptography (MD5)",
        "category": "Weak Cryptography",
        "severity": "Medium",
        "recommendation": "Use bcrypt, Argon2 or SHA-256.",
        "cwe": "CWE-327",
        "owasp": "OWASP A02:2021-Cryptographic Failures",
        "description": "MD5 is a weak hashing algorithm and is vulnerable to collision attacks."
    },

    "sha1": {
        "title": "Weak Cryptography (SHA1)",
        "category": "Weak Cryptography",
        "severity": "Medium",
        "recommendation": "SHA1 is deprecated.",
        "cwe": "CWE-327",
        "owasp": "OWASP A02:2021-Cryptographic Failures",
        "description": "SHA1 is a weak hashing algorithm and is vulnerable to collision attacks."
    },

    "loads": {
        "title": "Unsafe Deserialization (loads)",
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Avoid unsafe deserialization.",
        "cwe": "CWE-502",
        "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
        "description": "Deserializing untrusted data can lead to arbitrary code execution."
    },

    "load": {
        "title": "Unsafe Deserialization (load)",
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Use safe_load().",
        "cwe": "CWE-502",
        "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
        "description": "Deserializing untrusted data can lead to arbitrary code execution."
    },
    
    "pickle": {
        "title": "Unsafe Pickle Deserialization",
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Avoid pickle for untrusted data.",
        "cwe": "CWE-502",
        "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
        "description": "Pickle deserialization of untrusted data can lead to arbitrary code execution."
    },

    "marshal": {
        "title": "Unsafe Marshal Deserialization",
        "category": "Unsafe Deserialization",
        "severity": "High",
        "recommendation": "Avoid marshal for untrusted data.",
        "cwe": "CWE-502",
        "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
        "description": "Marshal deserialization of untrusted data can lead to arbitrary code execution."
    },

    "subprocess": {
        "title": "Command Execution",
        "category": "Command Execution",
        "severity": "Medium",
        "recommendation": "Validate subprocess usage.",
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Executing commands via subprocess might introduce Command Injection if arguments are not validated."
    },

    "telnetlib": {
        "title": "Insecure Protocol (Telnet)",
        "category": "Insecure Protocol",
        "severity": "Medium",
        "recommendation": "Use SSH instead of Telnet.",
        "cwe": "CWE-319",
        "owasp": "OWASP A02:2021-Cryptographic Failures",
        "description": "Telnet transmits data in cleartext."
    },

    "ftplib": {
        "title": "Insecure Protocol (FTP)",
        "category": "Insecure Protocol",
        "severity": "Medium",
        "recommendation": "Prefer SFTP or HTTPS.",
        "cwe": "CWE-319",
        "owasp": "OWASP A02:2021-Cryptographic Failures",
        "description": "FTP transmits data in cleartext."
    },
    
    "HARDCODED_SECRET": {
        "rule_id": "SEC001",
        "title": "Hardcoded Secret",
        "category": "Hardcoded Secret",
        "severity": "High",
        "recommendation": "Move secrets to environment variables or a secret manager.",
        "confidence": 1.0,
        "cwe": "CWE-798",
        "owasp": "OWASP A07:2021-Identification and Authentication Failures",
        "description": "A hardcoded secret was found in the source code."
    },

    "HARDCODED_PASSWORD": {
        "rule_id": "SEC002",
        "title": "Hardcoded Password",
        "category": "Hardcoded Password",
        "severity": "High",
        "recommendation": "Never store passwords in source code.",
        "confidence": 1.0,
        "cwe": "CWE-798",
        "owasp": "OWASP A07:2021-Identification and Authentication Failures",
        "description": "A hardcoded password was found in the source code."
    },

    "HARDCODED_TOKEN": {
        "rule_id": "SEC003",
        "title": "Hardcoded Token",
        "category": "Hardcoded Token",
        "severity": "High",
        "recommendation": "Store tokens in environment variables or a secret manager.",
        "confidence": 1.0,
        "cwe": "CWE-798",
        "owasp": "OWASP A07:2021-Identification and Authentication Failures",
        "description": "A hardcoded token was found in the source code."
    },

    # ==========================================
    # Phase 2: Capability Rules
    # ==========================================
    "CAP_SQL_INJECTION": {
        "rule_id": "CAP-SQLI-01",
        "title": "SQL Injection",
        "category": "SQL Injection",
        "severity": "Critical",
        "recommendation": "Use parameterized queries or an ORM. Avoid concatenating raw SQL strings.",
        "confidence": 0.8,
        "cwe": "CWE-89",
        "owasp": "OWASP A03:2021-Injection",
        "description": "SQL Injection allows an attacker to execute arbitrary SQL queries against the database."
    },

    "CAP_COMMAND_INJECTION": {
        "rule_id": "CAP-CMD-01",
        "title": "Command Injection",
        "category": "Command Injection",
        "severity": "Critical",
        "recommendation": "Avoid passing unsanitized input to OS commands.",
        "confidence": 0.8,
        "cwe": "CWE-78",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Command Injection allows an attacker to execute arbitrary OS commands."
    },

    "CAP_UNSAFE_EVAL": {
        "rule_id": "CAP-EVAL-01",
        "title": "Unsafe Evaluation",
        "category": "Unsafe Evaluation",
        "severity": "High",
        "recommendation": "Do not evaluate or execute dynamic code from untrusted sources.",
        "confidence": 0.9,
        "cwe": "CWE-94",
        "owasp": "OWASP A03:2021-Injection",
        "description": "Evaluating untrusted code dynamically can lead to arbitrary code execution."
    },

    "CAP_PATH_TRAVERSAL": {
        "rule_id": "CAP-PT-01",
        "title": "Path Traversal",
        "category": "Path Traversal",
        "severity": "High",
        "recommendation": "Validate file paths and use safe APIs for file operations. Avoid direct file access with user input.",
        "confidence": 0.8,
        "cwe": "CWE-22",
        "owasp": "OWASP A01:2021-Broken Access Control",
        "description": "Path Traversal allows an attacker to access arbitrary files on the system."
    },

    "CAP_SSRF": {
        "rule_id": "CAP-SSRF-01",
        "title": "Server-Side Request Forgery",
        "category": "Server-Side Request Forgery",
        "severity": "High",
        "recommendation": "Validate and restrict URLs before making outbound HTTP requests.",
        "confidence": 0.8,
        "cwe": "CWE-918",
        "owasp": "OWASP A10:2021-Server-Side Request Forgery",
        "description": "SSRF allows an attacker to make the server send arbitrary HTTP requests."
    },

    "CAP_XXE": {
        "rule_id": "CAP-XXE-01",
        "title": "XML External Entity (XXE)",
        "category": "XML External Entity (XXE)",
        "severity": "High",
        "recommendation": "Disable external entity resolution when parsing XML (e.g., use defusedxml).",
        "confidence": 0.9,
        "cwe": "CWE-611",
        "owasp": "OWASP A05:2021-Security Misconfiguration",
        "description": "XXE allows an attacker to read arbitrary files or execute requests via XML payloads."
    },
    
}
