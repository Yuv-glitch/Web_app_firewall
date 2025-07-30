from flask import Flask, request


app = Flask(__name__)
BACKEND_PORT = 8001

@app.route('/', defaults = {'path':''}, methods = ['GET', 'POST', 'DELETE', 'PUT'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    print(f"Backend server received a {request.method} request for path:/ {path}")
    if request.data:
        print(f" Request body: {request.data.decode('utf-8')}")
    return f"""
    <html>
          <body style='font-family: sans-serif; text-align: center; padding: 40px;'>
            <h1>Hello from your Local Backend Server!</h1>
            <p>The reverse proxy successfully forwarded the request to me.</p>
            <p><b>Request Method:</b> {request.method}</p>
            <p><b>Request Path:</b> /{path}</p>
            <form>Enter text here</form>
        </body>
    </html>
    """
if __name__ == "__main__":
    print(f"Starting backend server on http://locaclhost:{BACKEND_PORT}")
    app.run(host='0.0.0.0', port=BACKEND_PORT)