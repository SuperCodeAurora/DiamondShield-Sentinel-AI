from flask import Flask, request, jsonify
from src.core_firewall import AegisFirewall

app = Flask(__name__)
# Initialize the Firewall Engine
firewall = AegisFirewall()

@app.before_request
def waf_middleware():
    """
    Middleware that intercepts every request before it reaches the endpoint.
    """
    client_ip = request.remote_addr
    # Combine query params, form data, and JSON into a single payload string
    payload = request.args.get('q', '') + str(request.form) + str(request.json)
    user_agent = request.headers.get('User-Agent', '')

    # Send to Firewall
    decision = firewall.inspect_request(client_ip, payload, user_agent)

    if not decision['allowed']:
        # Return 403 Forbidden if blocked
        return jsonify({
            "error": "Request Blocked by Aegis System",
            "reason": decision['reason']
        }), 403

@app.route('/')
def home():
    return "<h1>Secure Corporate Server</h1><p>System Status: Protected</p>"

if __name__ == '__main__':
    print("Initializing Aegis Defense System...")
    app.run(port=5000)
