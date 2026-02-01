from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import os


class MTLSHTTPServer(HTTPServer):
    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        try:
            # handshake happens lazily, force it now
            newsocket.do_handshake()
            return newsocket, fromaddr
        except ssl.SSLError as e:
            print("TLS handshake failed from", fromaddr, "error:", e)
            newsocket.close()
            raise


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        cert = self.connection.getpeercert()
        print("Client cert:", cert)
        self.send_response(200)
        self.end_headers()
        # return mock json jwt
        mock_json = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aeyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.wfile.write(
            b"{\"access_token\": \"" + mock_json.encode('utf-8') + b"\"}")


httpd = MTLSHTTPServer(('0.0.0.0', 7576), Handler)

ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
ctx.load_verify_locations(cafile="ca.crt")

httpd.socket = ctx.wrap_socket(
    httpd.socket, server_side=True, do_handshake_on_connect=False)

print("CWD:", os.getcwd())
print("mTLS server running on https://localhost:7576")
httpd.serve_forever()
