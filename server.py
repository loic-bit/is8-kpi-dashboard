import http.server, os, json, urllib.request, urllib.error

TOKEN = os.environ.get('AIRTABLE_TOKEN', '')
PORT = int(os.environ.get('PORT', 8080))
BASE_ID = 'apppAaY1mCbpmXSGd'

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]

        if path == '/health':
            token_set = bool(TOKEN)
            masked = (TOKEN[:8] + '...' + TOKEN[-6:]) if len(TOKEN) > 14 else ('set' if TOKEN else 'MISSING')
            payload = {'token_set': token_set, 'token_preview': masked}

            if token_set:
                try:
                    req = urllib.request.Request(
                        f'https://api.airtable.com/v0/{BASE_ID}/tblRt7VOLkoT5KPEO?maxRecords=1',
                        headers={'Authorization': f'Bearer {TOKEN}'}
                    )
                    with urllib.request.urlopen(req, timeout=8) as r:
                        data = json.loads(r.read())
                        payload['airtable'] = 'ok'
                        payload['records_sample'] = len(data.get('records', []))
                except urllib.error.HTTPError as e:
                    payload['airtable'] = f'HTTP {e.code}'
                except Exception as e:
                    payload['airtable'] = f'error: {e}'

            body = json.dumps(payload, indent=2).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path in ('/', '/index.html', ''):
            with open('index.html', 'rb') as f:
                html = f.read().decode('utf-8')
            idx = html.rfind('</head>')
            if idx != -1:
                inject = f'<script>window.__AT__="{TOKEN}";</script>'
                html = html[:idx] + inject + '</head>' + html[idx+7:]
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
