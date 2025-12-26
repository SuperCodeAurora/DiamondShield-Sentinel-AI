import re
import urllib.parse
from .heuristics import TrafficAnalyzer
from .logger import SecurityLogger

class DiamondShield:
    def __init__(self):
        # Initialize components
        self.analyzer = TrafficAnalyzer(use_ai=True, ai_model="llama3")
        self.logger = SecurityLogger()
        
        # --- LEVEL 1: TRAP PATHS (HONEYPOT) ---
        # If anyone touches these, they are 100% a hacker.
        self.honeypots = [
            "/admin.php", "/.env", "/backup.sql", "/config.json", "/wp-login.php"
        ]

        # --- LEVEL 2: ADVANCED SIGNATURES (REGEX) ---
        # Expanded list to catch RCE, LFI, and SQLi
        self.signatures = [
            # SQL Injection
            r"union\s+(all\s+)?select", 
            r"waitfor\s+delay",
            r"information_schema",
            
            # XSS (Cross Site Scripting)
            r"<script[\s\S]*?>",
            r"javascript:",
            r"on\w+\s*=", # onmouseover=, onclick=
            
            # Path Traversal (LFI)
            r"\.\./", 
            r"/etc/passwd", 
            r"/boot/ini",
            
            # Command Injection (RCE)
            r";\s*cat\s+", 
            r"\|\s*whoami", 
            r"\$\(.*\)", # Bash execution
            
            # Metadata Service Attack (Cloud)
            r"169\.254\.169\.254"
        ]

    def _normalize_payload(self, payload: str) -> str:
        """
        Anti-Evasion: Decodes URL encoding and converts to lowercase.
        Example: '%27%20OR%201=1' becomes '' or 1=1'
        """
        # 1. URL Decode (converts %20 to space, etc.)
        decoded = urllib.parse.unquote(payload)
        # 2. Lowercase (makes Case-Insensitive matching easier)
        return decoded.lower()

    def inspect_request(self, ip: str, path: str, payload: str, user_agent: str) -> dict:
        """
        Main inspection pipeline. Returns {'allowed': bool, 'reason': str}
        """
        # 1. HONEYPOT CHECK (Instant Ban)
        if path in self.honeypots:
            self.logger.log_threat(ip, f"Honeypot Triggered: {path}")
            return {"allowed": False, "reason": "Trap Triggered"}

        # 2. RATE LIMITING (Anti-Bot)
        if self.analyzer.is_rate_limited(ip):
            self.logger.log_threat(ip, "High Frequency Bot Detected")
            return {"allowed": False, "reason": "Rate Limit Exceeded"}

        # 3. NORMALIZE INPUT (Strip Disguises)
        clean_payload = self._normalize_payload(payload)
        clean_ua = user_agent.lower()

        # 4. MALICIOUS AGENT CHECK
        if "sqlmap" in clean_ua or "nikto" in clean_ua or "curl" in clean_ua:
            self.logger.log_threat(ip, f"Malicious Tool: {user_agent}")
            return {"allowed": False, "reason": "Blacklisted Agent"}

        # 5. STATIC SIGNATURES (The Arsenal)
        for signature in self.signatures:
            if re.search(signature, clean_payload):
                self.logger.log_threat(ip, f"Signature Match: {signature}")
                return {"allowed": False, "reason": "Malicious Payload Detected"}

        # 6. ENTROPY CHECK (Math)
        if self.analyzer.calculate_entropy(payload) > 4.8 and len(payload) > 50:
             self.logger.log_threat(ip, "High Entropy Payload (Obfuscated Code)")
             return {"allowed": False, "reason": "Suspicious Payload Entropy"}

        # 7. AI SEMANTIC ANALYSIS (The Brain)
        if len(payload) > 15:
            # We send the RAW payload to AI, because AI understands context better than Regex
            print(f"[*] Analyzing payload with AI: {payload[:20]}...")
            ai_result = self.analyzer.check_with_ai(payload)
            if ai_result.get("is_malicious"):
                reason = f"AI Detection: {ai_result.get('reason')}"
                self.logger.log_threat(ip, reason)
                return {"allowed": False, "reason": reason}

        return {"allowed": True, "reason": "Pass"}
