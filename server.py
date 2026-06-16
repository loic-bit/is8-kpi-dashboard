import http.server, os, mimetypes

TOKEN = os.environ.get('AIRTABLE_TOKEN', '')
PORT = int(os.environ.get('PORT', 8080))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]
        if path in ('/', '/index.html', ''):
            with open('index.html', 'rb') as f:
                html = f.read().decode('utf-8')
            html = html.replace('</head>', f'<script>window.__AT__="{TOKEN}";</script></head>', 1)
            body = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass

if __name__ == '__main__':
    print(f'Dashboard serving on port {PORT}')
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
