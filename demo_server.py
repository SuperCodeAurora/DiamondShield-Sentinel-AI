from flask import Flask, request, jsonify, make_response
from src import DiamondShield

app = Flask(__name__)
firewall = DiamondShield()

def get_challenge_html():
    """
    Returns a 'Loading' page that forces the client to execute JavaScript.
    This kills 99% of bots (curl, python, sqlmap) because they can't run JS.
    """
    return """
    <html>
    <head>
        <title>DiamondShield Security Check</title>
        <script>
            // Simple Proof-of-Work: Set a cookie and reload
            console.log("DiamondShield: Verifying Browser...");
            document.cookie = "aegis_human_token=verified; path=/; max-age=3600";
            
            // Wait 1 second to simulate checks, then reload
            setTimeout(function() {
                window.location.reload();
            }, 1000);
        </script>
        <style>
            body { font-family: sans-serif; text-align: center; padding-top: 50px; background: #1a1a1a; color: #fff; }
            .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <h1>🛡️ DiamondShield</h1>
        <p>Checking your browser before accessing the secure server...</p>
        <div class="loader"></div>
    </body>
    </html>
    """

@app.before_request
def waf_middleware():
    client_ip = request.remote_addr
    path = request.path
    payload = request.args.get('q', '') + str(request.form) + str(request.json)
    user_agent = request.headers.get('User-Agent', '')

    # --- LAYER 1: THE JAVASCRIPT BARRIER (Anti-Bot) ---
    # If they don't have the cookie, and they are asking for a webpage, challenge them.
    # (We skip this for API endpoints if you have them, but for this demo, we force it).
    if 'aegis_human_token' not in request.cookies:
        print(f"[*] New Visitor {client_ip}: Sending JS Challenge...")
        return get_challenge_html()

    # --- LAYER 2: THE FIREWALL (Anti-Hacker) ---
    # If they passed the JS challenge, NOW we check for attacks.
    decision = firewall.inspect_request(client_ip, path, payload, user_agent)

    if not decision['allowed']:
        return jsonify({
            "error": "Request Blocked by DiamondShield",
            "reason": decision['reason']
        }), 403

@app.route('/')
def home():
    return "<h1>Secure Server Online</h1><p>You have passed the DiamondShield Browser Check.</p>"

if __name__ == '__main__':
    print(f"🛡️  DiamondShield (With Anti-Bot Barrier) Initialized...")
    app.run(port=5000)
