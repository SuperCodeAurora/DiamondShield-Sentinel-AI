import logging

class SecurityLogger:
    def __init__(self):
        # Configure logging to file
        logging.basicConfig(
            filename='threats.log',
            level=logging.WARNING,
            format='%(asctime)s - [BLOCKED] - %(message)s'
        )
    
    def log_threat(self, ip, reason):
        msg = f"Source: {ip} | Reason: {reason}"
        print(f"🛡️  [BLOCKED] {msg}") # Print to console
        logging.warning(msg) # Write to log file
