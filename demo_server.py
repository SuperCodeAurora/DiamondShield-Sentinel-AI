from flask import Flask, request, jsonify
from src import DiamondShield

app = Flask(__name__)
# Initialize the Stronger Firewall Engine
firewall = DiamondShield()

@app.before_request
def waf_middleware():
    """
    Middleware that intercepts every request before it reaches the endpoint.
    """
    client_ip = request.remote_addr
    path = request.path  # We now check the PATH for honeypots
    
    # Combine everything into one analysis block
    payload = request.args.get('q', '') + str(request.form) + str(request.json)
    user_agent = request.headers.get('User-Agent', '')

    # Send to Firewall (Now includes PATH)
    decision = firewall.inspect_request(client_ip, path, payload, user_agent)

    if not decision['allowed']:
        return jsonify({
            "error": "Request Blocked by DiamondShield",
            "reason": decision['reason']
        }), 403

@app.route('/')
def home():
    return "<h1>Secure Server Online</h1><p>DiamondShield v2.0 is Active.</p>"

# FAKE ADMIN PAGE (The Trap is handled by the Firewall logic, but we need the route exists)
@app.route('/admin.php')
def fake_admin():
    return "Access Denied", 403

if __name__ == '__main__':
    print(f"🛡️  DiamondShield-Sentinel-AI (Hardened) Initialized...")
    app.run(port=5000)
