#!/usr/bin/env python3
"""Firma desde una página web real en Windows y macOS (CI), sin intervención.

Como en una sede electrónica: Chrome (sin interfaz) carga una página con el
`autoscript.js` original y pide una firma CAdES. AutoFirma se lanza con el
manejador del sistema (`start afirma://...` en Windows, `open afirma://...` en
macOS, que entrega la URL como evento de Apple) y abre su servidor WebSocket
TLS; Chrome solo puede conectarse si la CA local está instalada como de
confianza (no se desactiva la comprobación de certificados). El certificado de
prueba, importado en el almacén del sistema, se selecciona sin diálogo con
`headless=true` y un filtro por huella. La firma devuelta se verifica con la
línea de comandos de AutoFirma.

Uso: web_sign.py <autofirma> <directorio de trabajo>
"""
import base64, http.server, json, os, platform, shutil, socket, subprocess, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
APP, WORK = sys.argv[1], os.path.abspath(sys.argv[2])
THUMBPRINT = "7D6ECA0FFB928B5DAB80727F059103BF6C2A3894"  # testdata/pki/firmante-rsa.crt
DATA = base64.b64encode(b"Firma desde la web en la CI").decode()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def chrome():
    for c in (
        os.environ.get("CHROME", ""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
    ):
        if c and os.path.exists(c):
            return c
    sys.exit("no se encuentra Chrome")


def launch(url):
    system = platform.system()
    if system == "Windows":
        subprocess.Popen(["cmd", "/c", "start", "", url])
    elif system == "Darwin":
        subprocess.Popen(["open", url])
    else:
        subprocess.Popen(["xdg-open", url])


os.makedirs(WORK, exist_ok=True)
ws_port, web_port = free_port(), free_port()
results = []
script = open(os.path.join(ROOT, "afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js"), "rb").read()
params = f"headless=true\\nfilters=thumbprint:SHA1:{THUMBPRINT}\\nmode=implicit"
page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><script src="autoscript.js"></script></head><body><script>
function report(o) {{ return fetch('/result', {{ method: 'POST', body: JSON.stringify(o) }}); }}
AutoScript.setPortRange({ws_port}, {ws_port});
AutoScript.cargarAppAfirma();
AutoScript.sign('{DATA}', 'SHA256withRSA', 'CAdES', '{params}',
  function (sig, cert, extra) {{ report({{ ok: true, sig: sig, cert: cert }}); }},
  function (t, m) {{ report({{ ok: false, type: t, msg: m }}); }});
</script></body></html>""".encode()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body, ct = (page, "text/html; charset=utf-8") if self.path.startswith("/page") else (script, "application/javascript")
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        results.append(json.loads(self.rfile.read(n)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


srv = http.server.ThreadingHTTPServer(("127.0.0.1", web_port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# La página no puede lanzar el protocolo desde un navegador sin interfaz: se lanza con
# el manejador registrado en el sistema, como haría el navegador.
launch(f"afirma://websocket?ports={ws_port}&v=4&jvc=4")
time.sleep(5)
browser = subprocess.Popen(
    [chrome(), "--headless=new", "--no-first-run", "--disable-gpu", f"--user-data-dir={WORK}/chrome",
     f"http://127.0.0.1:{web_port}/page.html"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(180):
        if results:
            break
        time.sleep(1)
finally:
    browser.terminate()
    srv.shutdown()
if not results:
    sys.exit("la página no ha recibido respuesta de AutoFirma")
r = results[0]
print(json.dumps({k: (v[:60] + "…") if isinstance(v, str) and len(v) > 60 else v for k, v in r.items()}, ensure_ascii=False))
if not r.get("ok"):
    sys.exit("AutoFirma devolvió un error a la página")
sig = os.path.join(WORK, "firma-web.csig")
with open(sig, "wb") as f:
    f.write(base64.b64decode(r["sig"].replace("-", "+").replace("_", "/") + "=="))
v = subprocess.run([APP, "verify", "-i", sig], capture_output=True, text=True)
print(v.stdout.strip())
if "Firma válida" not in v.stdout and "Valid signature" not in v.stdout:
    sys.exit("la firma devuelta no es válida")
print("firma desde la web correcta")
