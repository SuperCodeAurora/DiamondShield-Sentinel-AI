import re
from .heuristics import TrafficAnalyzer
from .logger import SecurityLogger

# RENAMED from AegisFirewall to DiamondShield
class DiamondShield:
    def __init__(self):
        # Initialize components
        self.analyzer = TrafficAnalyzer(use_ai=True, ai_model="llama3")
        self.logger = SecurityLogger()
        
        # Legacy static signatures (Regex) for fast blocking
        self.signatures = [
            r"union.*select",          # SQL Injection
            r"<script>",               # XSS
            r"eval\(",                 # RCE Attempt
            r"\.\./",                  # Path Traversal
            r"admin'--",               # Auth Bypass
        ]

    def inspect_request(self, ip: str, payload: str, user_agent: str) -> dict:
        """
        Main inspection pipeline. Returns {'allowed': bool, 'reason': str}
        """
        # 1. Rate Limiting (Anti-Bot)
        if self.analyzer.is_rate_limited(ip):
            self.logger.log_threat(ip, "High Frequency Bot Detected")
            return {"allowed": False, "reason": "Rate Limit Exceeded"}

        # 2. Malicious User-Agent Check
        if "sqlmap" in user_agent.lower() or "bot" in user_agent.lower():
            self.logger.log_threat(ip, f"Malicious User-Agent: {user_agent}")
            return {"allowed": False, "reason": "Blacklisted Agent"}

        # 3. Static Signature Matching (Fast)
        for signature in self.signatures:
            if re.search(signature, payload, re.IGNORECASE):
                self.logger.log_threat(ip, f"Payload Signature Match: {signature}")
                return {"allowed": False, "reason": "Malicious Payload Detected (Regex)"}

        # 4. Entropy Check (Obfuscation Detection)
        if self.analyzer.calculate_entropy(payload) > 4.5 and len(payload) > 50:
             self.logger.log_threat(ip, "High Entropy Payload (Obfuscated Code)")
             return {"allowed": False, "reason": "Suspicious Payload Entropy"}

        # 5. AI Semantic Analysis (Slow but smart)
        if len(payload) > 10:
            print(f"[*] Analyzing payload with AI: {payload[:20]}...")
            ai_result = self.analyzer.check_with_ai(payload)
            if ai_result.get("is_malicious"):
                reason = f"AI Detection: {ai_result.get('reason')}"
                self.logger.log_threat(ip, reason)
                return {"allowed": False, "reason": reason}

        return {"allowed": True, "reason": "Pass"}
