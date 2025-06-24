from http.server import HTTPServer, BaseHTTPRequestHandler

class WarningPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            with open('warning_page_demo.html', 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            html_content = f"<h1>Phishing Blocked</h1><p>Could not load warning page: {e}</p>"
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 80), WarningPageHandler)
    print("Warning page server running on port 80")
    server.serve_forever()