import requests
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json 
import time
import threading

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8001
PROXY_PORT = 8888

RATE_LIMIT = 1
BURST_SIZE = 3


blacklist = {}
ip_rate_state = {}
limiter_lock = threading.Lock()

with open("rules.json", "r") as file:
    rules = json.load(file)

def score(data: str):
    score = 0
    for pattern,value in rules.items():
        if pattern in data:
            score += value
    return score

def log_dmp(dta):
    with open("logs.json", "r+") as file:
        file_new = json.load(file)
        file_new["logs"].append(dta)
        file.seek(0)
        json.dump(file_new, file, indent=4)

def clean_list(list):
    current_time = time.time()
    expired_items = [item for item, expiry_time in list.items()
                     if expiry_time <= current_time]
    
    for item in expired_items:
        del list[item]
        print(f"{item} has been whitelisted")


def add_to(list, item, duration_time=1):
    duration_seconds = duration_time * 60
    expiration_time = time.time() + duration_seconds

    list[item] = expiration_time
    print(f"{item} has been blacklisted")

def rate_limited(client_ip):
    with limiter_lock:
        current_time = time.time()
        tokens, last_check = ip_rate_state.get(client_ip, (BURST_SIZE, current_time))
        time_elapsed = current_time - last_check

        tokens_to_add = time_elapsed * RATE_LIMIT
        tokens = min(BURST_SIZE, tokens + tokens_to_add)

        last_check = current_time
        
        if tokens >= 1:
            tokens -= 1
            ip_rate_state[client_ip] = (tokens, last_check)
            print(f"{client_ip} allowed tokens remaining {tokens}")
            return False
        else:
            ip_rate_state[client_ip] = (tokens, last_check)
            print(f"{client_ip} not allowed, Try again later")
            return True


class ReverseProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        self.proxy_request("GET")

    def do_POST(self):
        self.proxy_request("POST")

    def do_PUT(self):
        self.proxy_request("PUT")
    
    def do_DELETE(self):
        self.proxy_request("DELETE")
    
    def do_HEAD(self):
        self.proxy_request("HEAD")
    
    def do_OPTIONS(self):
        self.proxy_request("OPTIONS")

    def proxy_request(self, method):
        clean_list(blacklist)
        # print(self.headers.items())


        # print(f"URL: {unquote(self.path)}")
        # print(f"Headers: {str(self.headers)}")
        if self.client_address[0] not in blacklist.keys():
            if rate_limited(self.client_address[0]):
                self.send_error(429, "Too Many Requests")
                return 
            else:
                
                url_frmt = unquote(self.path)
                url_frmt = url_frmt.lower().replace('\n', ' ').replace('\r', ' ')

                header_frmt = str(self.headers).lower().replace('\n', ' ').replace('\r', ' ')

                cntnt_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(cntnt_length) if cntnt_length > 0 else None
                body_frmt = str(body).lower().replace('\n', ' ').replace('\r', ' ')


                def lger(url, location, body, headers, score:int):
                    data = {"Status": "Blocked",
                            "IP_address": self.client_address[0],
                            "PORT": self.client_address[1],
                            "Location": location,
                            "URL": url,
                            "Headers": headers,
                            "Body": body,
                            "Severity score": score}
                    return data


                if score(url_frmt) > 5:
                    print("Suspicion found in URL")
                    dta = lger(url_frmt, "URL", body_frmt, str(self.headers.items()), score(url_frmt))
                    add_to(blacklist,self.client_address[0])
                    log_dmp(dta)
                    return

                if score(header_frmt) > 5:
                    print("Suspicion found in HEADER")
                    dta = lger(url_frmt, "HEADER", body_frmt, str(self.headers.items()), score(header_frmt))
                    add_to(blacklist,self.client_address[0])
                    log_dmp(dta)
                    return

                if score(body_frmt) > 5:
                    print("Suspicion found in Body")
                    dta = lger(url_frmt, "Body", body_frmt, str(self.headers.items()), score(body_frmt))
                    add_to(blacklist,self.client_address[0])
                    log_dmp(dta)
                    return
                
                # log_dmp(dta)
                
                try:
                    url = f"http://{TARGET_HOST}:{TARGET_PORT}{self.path}"            
                    headers = dict(self.headers)
                        
                    headers['Host'] = TARGET_HOST
                
                    response = requests.request(method, url, headers=headers, data=body, allow_redirects=False)
                    # print("Injecting secure headers")

                    self.send_response(response.status_code)
                    self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
                    self.send_header('X-Frame-Options', 'DENY')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('Content-Security-Policy', "default-src 'self'")

                    for key, value in response.headers.items():
                        if key.lower() not in ('content-encoding', 'transfer-encoding', 'connection'):
                            self.send_header(key, value)
                    self.end_headers()

                    self.wfile.write(response.content)

                except requests.exceptions.ConnectionError:
                    self.send_error(502, "Bad Gateway: Could not connect to the backend server.")
                except Exception as e:
                    self.send_error(500, f"Proxy Error: {e}")
        else:
            print(f"{self.client_address[0]} has been blocked")
            
    
def run(server_class=ThreadingHTTPServer, handler_class=ReverseProxy, port=PROXY_PORT):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting reverse proxy on port {port}, forwarding to http://{TARGET_HOST}:{TARGET_PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the proxy server.")
        httpd.server_close()

if __name__ == "__main__":
    run()
