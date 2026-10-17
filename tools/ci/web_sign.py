#!/usr/bin/env python3
"""Firma desde una página web real en Windows y macOS (CI), sin intervención.

Como en una sede electrónica: Chrome (sin interfaz) carga una página con el
`autoscript.js` original y pide una firma CAdES. Cuando la página está cargada
(como hace `autoscript.js` al firmar, que un Chrome sin interfaz no puede),
AutoFirma se lanza con el manejador del sistema (`start afirma://...` en Windows, `open afirma://...` en
macOS, que entrega la URL como evento de Apple) y abre su servidor WebSocket
TLS; Chrome solo puede conectarse si la CA local está instalada como de
confianza (no se desactiva la comprobación de certificados). El certificado de
prueba, importado en el almacén del sistema, se selecciona sin diálogo con
`headless=true` y un filtro por huella. La firma devuelta se verifica con la
línea de comandos de AutoFirma.

Uso: web_sign.py <autofirma> <directorio de trabajo>
"""
import base64, http.server, json, os, platform, shutil, socket, subprocess, sys, threading, time

T0 = time.monotonic()


def log(msg):
    print(f"[{time.monotonic() - T0:6.1f} s] {msg}", flush=True)

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
    # Registro detallado (Windows hereda el entorno con ShellExecute; en macOS lo
    # pone `launchctl setenv` en la CI).
    os.environ.setdefault("AUTOFIRMA_LOG", "debug")
    system = platform.system()
    if system == "Windows":
        # Como el navegador: ShellExecute con el manejador registrado (con `cmd /c start`
        # los «&» de la URL separarían órdenes).
        os.startfile(url)
    elif system == "Darwin":
        subprocess.Popen(["open", url])
    else:
        subprocess.Popen(["xdg-open", url])


def processes():
    """Procesos de AutoFirma y estado del puerto del WebSocket."""
    system = platform.system()
    cmds = {
        "Windows": [["tasklist"], ["netstat", "-ano"]],
        "Darwin": [["ps", "-axo", "pid,etime,command"], ["lsof", "-nP", f"-iTCP:{ws_port}"]],
    }.get(system, [["ps", "-eo", "pid,etime,args"], ["ss", "-tanp"]])
    for c in cmds:
        out = subprocess.run(c, capture_output=True).stdout.decode("utf-8", "replace")
        lines = [l for l in out.splitlines() if "autofirma" in l.lower() or str(ws_port) in l]
        print(f"--- {' '.join(c)}\n" + "\n".join(lines), flush=True)


def probe():
    """Mientras la página intenta conectar: ¿sigue vivo AutoFirma y acepta conexiones?

    Solo abre y cierra una conexión TCP (no llega a la negociación WebSocket, así que
    no ocupa el lugar de la página como primer cliente)."""
    for delay in (3, 6, 12):
        time.sleep(delay)
        try:
            socket.create_connection(("127.0.0.1", ws_port), timeout=3).close()
            log(f"sondeo: el puerto {ws_port} acepta conexiones TCP")
        except OSError as e:
            log(f"sondeo: el puerto {ws_port} no acepta conexiones: {e}")
        processes()


os.makedirs(WORK, exist_ok=True)
ws_port, web_port = free_port(), free_port()
results = []
launched = threading.Event()
script = open(os.path.join(ROOT, "afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js"), "rb").read()
params = f"headless=true\\nfilters=thumbprint:SHA1:{THUMBPRINT}\\nmode=implicit"
page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><script src="autoscript.js"></script></head><body><script>
function post(path, o) {{ return fetch(path, {{ method: 'POST', body: JSON.stringify(o) }}); }}
function report(o) {{ return post('/result', o); }}
var origLog = console.log;
console.log = function () {{ post('/log', Array.prototype.join.call(arguments, ' ')); origLog.apply(console, arguments); }};
window.onerror = function (m) {{ post('/log', 'error: ' + m); }};
AutoScript.setPortRange({ws_port}, {ws_port});
AutoScript.cargarAppAfirma();
post('/ready', '').then(function () {{ AutoScript.sign('{DATA}', 'SHA256withRSA', 'CAdES', '{params}',
  function (sig, cert, extra) {{ report({{ ok: true, sig: sig, cert: cert }}); }},
  function (t, m) {{ report({{ ok: false, type: t, msg: m }}); }}); }});
</script></body></html>""".encode()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        log(f"GET {self.path}")
        body, ct = (page, "text/html; charset=utf-8") if self.path.startswith("/page") else (script, "application/javascript")
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b'""')
        if self.path == "/ready":
            log("página cargada: se lanza AutoFirma")
            launch(f"afirma://websocket?ports={ws_port}&v=4&jvc=4")
            threading.Thread(target=probe, daemon=True).start()
            time.sleep(2)
            launched.set()
        elif self.path == "/log":
            log(f"consola: {body}")
        else:
            log("resultado recibido")
            results.append(body)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


srv = http.server.ThreadingHTTPServer(("127.0.0.1", web_port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# `--use-mock-keychain`: en macOS, sin él Chrome puede quedarse esperando al llavero
# para guardar su clave de cifrado (no afecta a la confianza en certificados).
chrome_log = open(os.path.join(WORK, "chrome.log"), "wb")
log("se abre Chrome")
browser = subprocess.Popen(
    [chrome(), "--headless=new", "--no-first-run", "--disable-gpu", "--use-mock-keychain",
     "--password-store=basic", f"--user-data-dir={WORK}/chrome", f"--log-net-log={WORK}/netlog.json",
     f"http://127.0.0.1:{web_port}/page.html"],
    stdout=chrome_log, stderr=subprocess.STDOUT)
try:
    for _ in range(240):
        if results:
            break
        time.sleep(1)
finally:
    browser.terminate()
    srv.shutdown()
if not results:
    chrome_log.close()
    print("--- Chrome (últimas líneas)")
    print("\n".join(open(chrome_log.name, encoding="utf-8", errors="replace").read().splitlines()[-30:]))
    if not launched.is_set():
        sys.exit("la página no llegó a cargarse en Chrome")
    # Códigos de error de red que ha visto Chrome (p. ej. -102 conexión rechazada,
    # -202 CA no reconocida).
    try:
        net = open(os.path.join(WORK, "netlog.json"), encoding="utf-8", errors="replace").read().splitlines()
        errs = sorted({l.split('"net_error":')[1].split(",")[0].split("}")[0] for l in net if '"net_error":' in l})
        print(f"--- errores de red de Chrome: {errs}")
        for l in [l for l in net if str(ws_port) in l][:8]:
            print(l[:400])
    except OSError as e:
        print(f"--- sin registro de red de Chrome: {e}")
    processes()
    sys.exit(f"la página no ha recibido respuesta de AutoFirma (puerto {ws_port})")
r = results[0]
print(json.dumps({k: (v[:60] + "…") if isinstance(v, str) and len(v) > 60 else v for k, v in r.items()}, ensure_ascii=False))
if not r.get("ok"):
    sys.exit("AutoFirma devolvió un error a la página")
sig = os.path.join(WORK, "firma-web.csig")
with open(sig, "wb") as f:
    f.write(base64.b64decode(r["sig"].replace("-", "+").replace("_", "/") + "=="))
v = subprocess.run([APP, "verify", "-i", sig], capture_output=True)
out = v.stdout.decode("utf-8", "replace")  # AutoFirma escribe UTF-8 también en Windows
print(out.strip())
if "Firma válida" not in out and "Valid signature" not in out:
    sys.exit("la firma devuelta no es válida")
print("firma desde la web correcta")
