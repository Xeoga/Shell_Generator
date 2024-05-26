import webbrowser
import threading
from http.server import SimpleHTTPRequestHandler
import socketserver

def start_server(port=8000):
    handler = SimpleHTTPRequestHandler
    handler.extensions_map.update({
        '.html': 'text/html',
    })
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"Serving at port {port}")
    httpd.serve_forever()

# Define a function to open the local server in a web browser
def open_local_server():
    port = 8000
    threading.Thread(target=start_server, args=(port,), daemon=True).start()
    webbrowser.open(f"http://localhost:{port}")