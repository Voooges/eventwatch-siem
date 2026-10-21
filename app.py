"""Local-only EventWatch dashboard. Run: python app.py"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse
from engine import connect, detect, ingest, parse_events, read_events

ROOT = Path(__file__).resolve().parent

def make_handler(db_path, port):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, body, content_type='application/json'):
            data = body.encode() if isinstance(body,str) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type',content_type+'; charset=utf-8')
            self.send_header('Content-Length',str(len(data)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)
        def allowed(self):
            hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if self.headers.get('Host') not in hosts:
                self.reply(403, {'error':'Invalid host'})
                return False
            origin = self.headers.get('Origin')
            if origin and origin not in {f'http://{h}' for h in hosts}:
                self.reply(403, {'error':'Cross-origin request rejected'})
                return False
            return True
        def do_GET(self):
            if not self.allowed(): return
            path = urlparse(self.path).path
            if path == '/':
                return self.reply(200,(ROOT/'dashboard.html').read_text(encoding= 'utf-8'), 'text/html')
            if path == '/api/state':
                with connect(db_path) as db: events=read_events(db)
                return self.reply(200,dict(events=events,alerts=detect(events)))
            self.reply(404,{'error':'Not found'})
        def do_POST(self):
            if not self.allowed(): return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0 <= size <= 10*1024*1024: raise ValueError('Maximum upload is 10 MiB')
                path=urlparse(self.path).path
                if path == '/api/demo':
                    raw=(ROOT/'samples/demo.json').read_bytes()
                    events=parse_events(raw)
                elif path == '/api/import':
                    raw=self.rfile.read(size)
                    events=parse_events(raw, 'xml' if 'xml' in self.headers.get('Content-Type','') else 'json')
                else: return self.reply(404,{'error':'Not found'})
                with connect(db_path) as db: count=ingest(db,events)
                self.reply(200,{'added':count,'duplicates':len(events)-count})
            except (ValueError, KeyError, TypeError) as exc:
                self.reply(400,{'error':str(exc)})
            except Exception:
                self.reply(400,{'error':'Import failed. Check XML syntax and the documented event schema.'})
    return Handler

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8501)
    parser.add_argument('--db',type=Path,default=ROOT/'data/events.db')
    args=parser.parse_args()
    args.db.parent.mkdir(parents=True,exist_ok=True)
    server=HTTPServer(('127.0.0.1',args.port),make_handler(args.db,args.port))
    print(f'EventWatch is running at http://127.0.0.1:{args.port} — Ctrl+C to stop',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
