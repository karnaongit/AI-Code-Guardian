"""
Quantum Readiness Engine — Detector
======================================
Scans source code for uses of quantum-vulnerable cryptographic algorithms.

Patterns cover Java and Python with enough confidence for a regex bridge
(same rationale as the Java security rule engine - full Tree-sitter AST
wiring is a future milestone).

Detected categories
-------------------
- RSA (any key size)
- ECC / ECDSA / ECDH
- DSA / DSS
- Diffie-Hellman
- AES-128 / AES-ECB (weakened, not broken)
- SHA-1 / SHA-256 (Grover weakened)
- MD5 (classically + quantum broken)
- Weak TLS (TLS 1.0, TLS 1.1, SSLv3)
- Weak SSH (ssh-rsa, ecdsa, diffie-hellman-*)
- OpenSSL deprecated API calls
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from guardian.quantum.models import (
    AlgorithmFamily, CryptoUsage, QuantumThreat
)

# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------
# Each entry: (pattern, algorithm_name, family, threat, context)
# Ordered from most-specific to least-specific within each family.

_JAVA_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    # RSA
    (re.compile(r'\bRSA\b|\bRsaKey\b|\bRSAPublicKeySpec\b|\bRSAPrivateKeySpec\b', re.I),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"RSA"', re.I),
     "RSA KeyPairGenerator", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "key generation"),

    # ECC / ECDSA / ECDH
    (re.compile(r'\bEC(?:DSA|DH|KeyPair|PublicKey|PrivateKey|NamedCurveSpec)?\b', re.I),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"EC"', re.I),
     "ECC KeyPairGenerator", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "key generation"),

    # DSA
    (re.compile(r'\bDSA\b|\bDSAPublicKeySpec\b|\bDSAPrivateKeySpec\b', re.I),
     "DSA", AlgorithmFamily.DSA, QuantumThreat.CRITICAL, "signing"),

    # Diffie-Hellman
    (re.compile(r'\bDiffieHellman\b|\bDHPublicKeySpec\b|\bDHPrivateKeySpec\b|\bDHParameterSpec\b'),
     "Diffie-Hellman", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key exchange"),
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"DH"', re.I),
     "Diffie-Hellman KeyPairGenerator", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key generation"),

    # AES-ECB (weak mode) and AES-128
    (re.compile(r'Cipher\.getInstance\(\s*"AES/ECB', re.I),
     "AES/ECB", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption (ECB mode)"),
    (re.compile(r'"AES"\s*,\s*128|AES.*128|128.*AES', re.I),
     "AES-128", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption (key size weakened by Grover)"),

    # SHA-1
    (re.compile(r'\bSHA-?1\b|MessageDigest\.getInstance\(\s*"SHA-?1"', re.I),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),

    # SHA-256 (Grover halves collision resistance)
    (re.compile(r'\bSHA-?256\b|MessageDigest\.getInstance\(\s*"SHA-?256"', re.I),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.HIGH, "hashing"),

    # MD5
    (re.compile(r'\bMD5\b|MessageDigest\.getInstance\(\s*"MD5"', re.I),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),

    # Weak TLS versions
    (re.compile(r'\bSSLv3\b|\bTLSv1\b|\bTLSv1\.1\b|\b"TLSv1"\b|\b"SSLv3"\b', re.I),
     "Weak TLS", AlgorithmFamily.TLS, QuantumThreat.LOW, "transport security"),

    # Old OpenSSL-style names
    (re.compile(r'SunJSSE|SSLContext\.getInstance\(\s*"SSL"', re.I),
     "Legacy SSL", AlgorithmFamily.TLS, QuantumThreat.LOW, "transport security"),
]

_PYTHON_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    # RSA
    (re.compile(r'rsa\.|RSA\.|Crypto\.PublicKey\.RSA|from\s+Cryptodome?.PublicKey\s+import\s+RSA', re.I),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),
    (re.compile(r'rsa\.generate_private_key|rsa\.RSAPublicKey', re.I),
     "RSA (cryptography lib)", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "key generation"),

    # ECC / ECDSA / ECDH
    (re.compile(r'ec\.|ECDSA|ECDH|elliptic_curve|from\s+cryptography\.hazmat.*import\s+\w*EC\w*', re.I),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),

    # DSA
    (re.compile(r'dsa\.|DSA\.|from\s+Cryptodome?.PublicKey\s+import\s+DSA', re.I),
     "DSA", AlgorithmFamily.DSA, QuantumThreat.CRITICAL, "signing"),

    # Diffie-Hellman
    (re.compile(r'dh\.|DHE?\.|diffie.?hellman', re.I),
     "Diffie-Hellman", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key exchange"),

    # AES-128 / ECB mode
    (re.compile(r'AES\.new\([^)]*ECB|modes\.ECB', re.I),
     "AES/ECB", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption (ECB mode)"),
    (re.compile(r'AES.*key_size\s*=\s*16|16.*AES', re.I),
     "AES-128", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption"),

    # SHA-1 / MD5
    (re.compile(r'hashlib\.sha1|SHA1\b|sha1\b', re.I),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'hashlib\.md5|MD5\b|md5\b', re.I),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),

    # SHA-256
    (re.compile(r'hashlib\.sha256|SHA256\b', re.I),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.HIGH, "hashing"),

    # Weak SSL/TLS
    (re.compile(r'ssl\.PROTOCOL_TLS?v?1\b|ssl\.PROTOCOL_SSLv?2\b|ssl\.PROTOCOL_SSLv?3\b', re.I),
     "Weak TLS", AlgorithmFamily.TLS, QuantumThreat.LOW, "transport security"),
    (re.compile(r'paramiko.*sha1|paramiko.*ecdsa|paramiko.*diffie.?hellman', re.I),
     "Weak SSH", AlgorithmFamily.SSH, QuantumThreat.LOW, "SSH configuration"),
]

_SSH_CONFIG_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    (re.compile(r'HostKeyAlgorithms.*ssh-rsa|PubkeyAcceptedAlgorithms.*ssh-rsa', re.I),
     "SSH RSA key", AlgorithmFamily.SSH, QuantumThreat.CRITICAL, "SSH server key"),
    (re.compile(r'KexAlgorithms.*diffie-hellman', re.I),
     "SSH Diffie-Hellman KEX", AlgorithmFamily.SSH, QuantumThreat.CRITICAL, "SSH key exchange"),
    (re.compile(r'Ciphers.*arcfour|Ciphers.*3des', re.I),
     "SSH weak cipher", AlgorithmFamily.SSH, QuantumThreat.MEDIUM, "SSH cipher"),
]


def _get_patterns(
    file_label: str,
) -> list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]]:
    ext = Path(file_label).suffix.lower()
    if ext == ".java":
        return _JAVA_PATTERNS
    if ext in (".py",):
        return _PYTHON_PATTERNS
    if "ssh" in file_label.lower() or file_label.endswith(".conf"):
        return _SSH_CONFIG_PATTERNS
    return _JAVA_PATTERNS + _PYTHON_PATTERNS   # scan all for unknown types


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class QuantumDetector:
    """
    Scans source code and returns a list of `CryptoUsage` objects.
    One CryptoUsage per detected pattern per line.

    Deduplication: identical (file, line, algorithm) triplets are collapsed.
    """

    def scan_text(self, text: str, file_label: str) -> list[CryptoUsage]:
        patterns = _get_patterns(file_label)
        seen: set[str] = set()
        usages: list[CryptoUsage] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, algorithm, family, threat, context in patterns:
                if not pat.search(line):
                    continue
                key = f"{file_label}:{lineno}:{algorithm}"
                if key in seen:
                    continue
                seen.add(key)
                usages.append(CryptoUsage(
                    algorithm=algorithm,
                    family=family,
                    threat_level=threat,
                    file=file_label,
                    line=lineno,
                    snippet=line.strip()[:200],
                    context=context,
                ))
                break  # only first matching pattern per line per file
        return usages

    def scan_file(self, path: Path) -> list[CryptoUsage]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.scan_text(text, str(path))

    def scan_directory(
        self,
        root: Path,
        extensions: Iterable[str] = (".java", ".py", ".conf", ".yaml", ".yml"),
        exclude_dirs: Iterable[str] = ("test", "tests", ".git", "node_modules"),
    ) -> list[CryptoUsage]:
        root = Path(root)
        exclude_dirs = set(exclude_dirs)
        usages: list[CryptoUsage] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fn in filenames:
                if Path(fn).suffix.lower() in set(extensions):
                    fp = Path(dirpath) / fn
                    try:
                        rel = str(fp.relative_to(root))
                    except ValueError:
                        rel = str(fp)
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                    usages.extend(self.scan_text(text, rel))
        return usages
