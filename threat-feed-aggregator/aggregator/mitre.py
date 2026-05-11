"""
MITRE ATT&CK technique tagging.

Two detection paths:
  1. Inline references already present in text (T1234, T1234.001, TA0001)
  2. Keyword-pattern → technique mapping for common threat terminology
"""

import re
from .models import FeedItem

# ── Inline T-number detector ──────────────────────────────────────────────────
# Matches T1234, T1234.001, TA0001
_INLINE_RE = re.compile(r'\b(TA?\d{4}(?:\.\d{3})?)\b')

# ── Keyword → technique mapping ───────────────────────────────────────────────
# Each entry: (compiled regex, [(id, short_name, tactic), ...])
# Order matters: first match per-pattern wins for deduplication.

_MAPPINGS: list[tuple[re.Pattern, list[tuple[str, str, str]]]] = [

    # ── Initial Access ────────────────────────────────────────────────────────
    (re.compile(r'\bphish(?:ing)?\b|\bspear.?phish\b|\blure\b', re.I),
     [("T1566", "Phishing", "Initial Access")]),

    (re.compile(r'\bsupply.?chain\b', re.I),
     [("T1195", "Supply Chain Compromise", "Initial Access")]),

    (re.compile(r'\bexploit.{0,25}(?:public|internet|facing|web.?server|application)\b'
                r'|\bpublic.facing\b', re.I),
     [("T1190", "Exploit Public-Facing App", "Initial Access")]),

    (re.compile(r'\bVPN\b|\bremote.?access\b|\bexternal.?remote\b|\bRDP\b', re.I),
     [("T1133", "External Remote Services", "Initial Access")]),

    (re.compile(r'\bdrive.?by\b|\bwatering.?hole\b', re.I),
     [("T1189", "Drive-by Compromise", "Initial Access")]),

    # ── Execution ─────────────────────────────────────────────────────────────
    (re.compile(r'\bpowershell\b', re.I),
     [("T1059.001", "PowerShell", "Execution")]),

    (re.compile(r'\bVBA\b|\bmacro\b', re.I),
     [("T1059.005", "Visual Basic / Macro", "Execution")]),

    (re.compile(r'\bbash\b|\bshell.?script\b|\bsh.?script\b', re.I),
     [("T1059.004", "Unix Shell", "Execution")]),

    # ── Persistence ───────────────────────────────────────────────────────────
    (re.compile(r'\bwebshell\b|\bweb.?shell\b', re.I),
     [("T1505.003", "Web Shell", "Persistence")]),

    (re.compile(r'\bscheduled.?task\b|\bcron.?job\b|\bat.?job\b', re.I),
     [("T1053", "Scheduled Task/Job", "Persistence")]),

    (re.compile(r'\bbackdoor\b', re.I),
     [("T1547", "Boot/Logon Autostart Execution", "Persistence")]),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    (re.compile(r'\bprivilege.?escal\b|\bpriv.?esc\b|\bLPE\b|\blocal.?privilege\b', re.I),
     [("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")]),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    (re.compile(r'\bobfuscat\b', re.I),
     [("T1027", "Obfuscated Files or Information", "Defense Evasion")]),

    (re.compile(r'\bmasquerad\b|\blolbin\b|\bliving.off.the.land\b|\bLOTL\b', re.I),
     [("T1036", "Masquerading", "Defense Evasion")]),

    (re.compile(r'\bdisable.{0,20}(?:AV|antivirus|defender|EDR|security|detection)\b', re.I),
     [("T1562", "Impair Defenses", "Defense Evasion")]),

    (re.compile(r'\brootkit\b', re.I),
     [("T1014", "Rootkit", "Defense Evasion")]),

    (re.compile(r'\bdll.?hijack\b|\bdll.?side.?load\b', re.I),
     [("T1574.001", "DLL Hijacking", "Defense Evasion")]),

    # ── Credential Access ─────────────────────────────────────────────────────
    (re.compile(r'\bcredential.?dump|\bmimikatz\b|\blsass\b', re.I),
     [("T1003", "OS Credential Dumping", "Credential Access")]),

    (re.compile(r'\bbrute.?force\b|\bpassword.?spray\b|\bcredential.?stuff', re.I),
     [("T1110", "Brute Force", "Credential Access")]),

    (re.compile(r'\bkeylog(?:ger|ging)\b', re.I),
     [("T1056.001", "Keylogging", "Credential Access")]),

    (re.compile(r'\bcookie.?theft\b|\bsteal.{0,10}cookie\b|\bsession.?hijack\b', re.I),
     [("T1539", "Steal Web Session Cookie", "Credential Access")]),

    (re.compile(r'\bMFA.?bypass\b|\bMFA.?fatigue\b|\bOTP.?intercept\b', re.I),
     [("T1621", "MFA Request Generation", "Credential Access")]),

    # ── Discovery ─────────────────────────────────────────────────────────────
    (re.compile(r'\bport.?scan\b|\bnetwork.?scan\b|\bservice.?enumerat\b', re.I),
     [("T1046", "Network Service Discovery", "Discovery")]),

    (re.compile(r'\brecon(?:naissance)?\b|\bfootprint\b|\bosint\b', re.I),
     [("T1592", "Gather Victim Host Information", "Reconnaissance")]),

    # ── Lateral Movement ──────────────────────────────────────────────────────
    (re.compile(r'\blateral.?mov(?:e|ing|ement)\b', re.I),
     [("T1021", "Remote Services", "Lateral Movement")]),

    (re.compile(r'\bpass.the.hash\b|\bPTH\b|\bpass.the.ticket\b|\bPTT\b', re.I),
     [("T1550", "Use Alternate Auth Material", "Lateral Movement")]),

    # ── Collection ────────────────────────────────────────────────────────────
    (re.compile(r'\bemail.?harvest\b|\binbox.?access\b|\bmail.?collection\b', re.I),
     [("T1114", "Email Collection", "Collection")]),

    (re.compile(r'\bscreenshot\b|\bscreen.?capture\b', re.I),
     [("T1113", "Screen Capture", "Collection")]),

    # ── Command and Control ───────────────────────────────────────────────────
    (re.compile(r'\bC2\b|\bC&C\b|\bcommand.and.control\b|\bcobalt.?strike\b'
                r'|\bbeacon(?:ing)?\b|\bimplant\b', re.I),
     [("T1071", "Application Layer Protocol (C2)", "Command and Control")]),

    (re.compile(r'\bDNS.{0,10}tunnel(?:ing)?\b|\bDNS.{0,10}(?:C2|command)\b', re.I),
     [("T1071.004", "DNS C2", "Command and Control")]),

    (re.compile(r'\bfast.?flux\b|\bDGA\b|\bdomain.generat\b', re.I),
     [("T1568", "Dynamic Resolution", "Command and Control")]),

    (re.compile(r'\bprox(?:y|ies).{0,20}(?:traffic|C2|network|tunnel)\b', re.I),
     [("T1090", "Proxy", "Command and Control")]),

    # ── Exfiltration ──────────────────────────────────────────────────────────
    (re.compile(r'\bexfiltrat\b|\bdata.?theft\b|\bdata.?leak\b|\bsteal.{0,10}data\b', re.I),
     [("T1041", "Exfiltration Over C2 Channel", "Exfiltration")]),

    # ── Impact ────────────────────────────────────────────────────────────────
    (re.compile(r'\bransomware\b|\bencrypt.{0,20}(?:file|data|system|disk)\b', re.I),
     [("T1486", "Data Encrypted for Impact", "Impact")]),

    (re.compile(r'\bDDoS\b|\bdenial.of.service\b|\bDoS attack\b', re.I),
     [("T1498", "Network Denial of Service", "Impact")]),

    (re.compile(r'\bwiper\b|\bwipe.{0,10}(?:disk|data|system)\b|\bdestructive\b', re.I),
     [("T1561", "Disk Wipe", "Impact")]),

    (re.compile(r'\bdefacem(?:ent)?\b|\bwebsite.{0,10}defac\b', re.I),
     [("T1491", "Defacement", "Impact")]),
]


def _format_tag(tid: str, name: str, tactic: str) -> str:
    return f"{tid} {name} [{tactic}]"


def tag_mitre(items: list[FeedItem]) -> list[FeedItem]:
    """
    Detect ATT&CK techniques in each item and populate item.mitre_techniques.
    Tags are stored as "T1234 Name [Tactic]" strings.
    """
    for item in items:
        haystack = f"{item.title} {item.summary} {' '.join(item.tags)}"
        found: dict[str, str] = {}   # tid → formatted tag (deduplicates)

        # 1. Inline T-numbers already present in text
        for m in _INLINE_RE.finditer(haystack):
            tid = m.group(1)
            if tid not in found:
                found[tid] = tid   # bare ID when we don't have metadata

        # 2. Keyword-pattern mapping
        for pattern, techniques in _MAPPINGS:
            if pattern.search(haystack):
                for tid, name, tactic in techniques:
                    found[tid] = _format_tag(tid, name, tactic)

        item.mitre_techniques = sorted(found.values())
    return items
