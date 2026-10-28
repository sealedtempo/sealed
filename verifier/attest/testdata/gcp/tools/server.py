import http.client,http.server,json,re,socket,urllib.parse
class U(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost",timeout=60)
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect("/var/run/dstack.sock")
def call(method,path,body=None):
    c=U()
    h={"Content-Type":"application/json"} if body is not None else {}
    c.request(method,path,body=body,headers=h)
    r=c.getresponse()
    return r.status,r.read()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u=urllib.parse.urlparse(self.path)
        q=urllib.parse.parse_qs(u.query)
        try:
            if u.path=="/quote":
                rd=q.get("report_data",[""])[0].lower()
                if re.fullmatch("[0-9a-f]{0,128}",rd) is None or len(rd)%2:
                    st,b=400,b'{"error":"report_data must be even-length hex, at most 128 chars"}'
                else:
                    st,b=call("POST","/GetQuote",json.dumps({"report_data":rd}))
            elif u.path=="/info":
                st,b=call("GET","/Info")
            else:
                st,b=404,b'{"error":"not found"}'
        except Exception as e:
            st,b=502,json.dumps({"error":repr(e)}).encode()
        self.send_response(st)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)
http.server.ThreadingHTTPServer(("0.0.0.0",8080),H).serve_forever()
