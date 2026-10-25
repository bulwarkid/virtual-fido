import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = "test/www"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def main():
    if not os.path.exists(DIRECTORY):
        os.makedirs(DIRECTORY)
    
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Virtual FIDO Test Page</title>
</head>
<body>
    <h1>Virtual FIDO Test</h1>
    <input type="text" id="username" placeholder="username">
    <button id="register">Register</button>
    <button id="login">Login</button>
    <div id="status"></div>

    <script>
        const status = document.getElementById('status');
        
        document.getElementById('register').onclick = async () => {
            status.innerText = "Registering...";
            try {
                const challenge = new Uint8Array(32);
                window.crypto.getRandomValues(challenge);
                const userID = new Uint8Array(16);
                window.crypto.getRandomValues(userID);
                
                const options = {
                    publicKey: {
                        challenge: challenge,
                        rp: { name: "Virtual FIDO Test", id: "localhost" },
                        user: {
                            id: userID,
                            name: document.getElementById('username').value,
                            displayName: "Test User"
                        },
                        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                        timeout: 60000,
                        attestation: "direct"
                    }
                };
                
                const credential = await navigator.credentials.create(options);
                console.log("Registration Success:", credential);
                status.innerText = "Registration Successful";
                // Store credential ID for login
                window.lastCredentialId = credential.rawId;
            } catch (err) {
                console.error("Registration Error:", err);
                status.innerText = "Registration Failed: " + err;
            }
        };

        document.getElementById('login').onclick = async () => {
            status.innerText = "Logging in...";
            try {
                const challenge = new Uint8Array(32);
                window.crypto.getRandomValues(challenge);
                
                const options = {
                    publicKey: {
                        challenge: challenge,
                        timeout: 60000,
                        rpId: "localhost",
                        allowCredentials: window.lastCredentialId ? [{
                            id: window.lastCredentialId,
                            type: "public-key"
                        }] : []
                    }
                };
                
                const assertion = await navigator.credentials.get(options);
                console.log("Login Success:", assertion);
                status.innerText = "Login Successful";
            } catch (err) {
                console.error("Login Error:", err);
                status.innerText = "Login Failed: " + err;
            }
        };
    </script>
</body>
</html>
"""
    with open(os.path.join(DIRECTORY, "index.html"), "w") as f:
        f.write(html_content)

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
