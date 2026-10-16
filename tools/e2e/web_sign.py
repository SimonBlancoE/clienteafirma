#!/usr/bin/env python3
"""Prueba de extremo a extremo del modo protocolo con el autoscript.js real.

Chromium (sin interfaz) carga una página que usa autoscript.js para firmar;
la aplicación AutoFirma-rs se arranca con `afirma://websocket?...` en un X
virtual (el navegador sin interfaz no puede lanzar el protocolo) y se maneja
con xdotool (contraseña del almacén PKCS#12 y selección de certificado). La
firma devuelta a la página se verifica con OpenSSL.

Uso: web_sign.py <binario-autofirma> <dir-trabajo> [formato] [datos-base64]
"""
import base64, http.server, json, os, shutil, socket, subprocess, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
FORMAT = sys.argv[3] if len(sys.argv) > 3 else "CAdES"
DATA = sys.argv[4] if len(sys.argv) > 4 else base64.b64encode(b"Hola, firma desde la web").decode()
DISPLAY = ":179"

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, **kw)

shutil.rmtree(WORK, ignore_errors=True)
home = os.path.join(WORK, "home"); os.makedirs(os.path.join(home, ".afirma", "Autofirma"))
# Certificado local del servidor WebSocket (como el que genera la instalación).
pki = os.path.join(WORK, "pki"); os.makedirs(pki)
run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{pki}/k.pem", "-out", f"{pki}/c.pem",
     "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"])
run(["openssl", "pkcs12", "-export", "-inkey", f"{pki}/k.pem", "-in", f"{pki}/c.pem", "-name", "SocketAutoFirma",
     "-passout", "pass:654321", "-out", os.path.join(home, ".afirma", "Autofirma", "autofirma.pfx")])

ws_port, web_port = free_port(), free_port()
results = []
script = open(os.path.join(ROOT, "afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js"), "rb").read()
page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><script src="autoscript.js"></script></head><body><script>
function report(o) {{ return fetch('/result', {{ method: 'POST', body: JSON.stringify(o) }}); }}
AutoScript.setPortRange({ws_port}, {ws_port});
AutoScript.cargarAppAfirma();
AutoScript.sign('{DATA}', 'SHA256withRSA', '{FORMAT}', 'mode=implicit',
  function (sig, cert, extra) {{ report({{ ok: true, sig: sig, cert: cert }}); }},
  function (t, m) {{ report({{ ok: false, type: t, msg: m }}); }});
</script></body></html>""".encode()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body, ct = (page, "text/html; charset=utf-8") if self.path.startswith("/page") else (script, "application/javascript")
        self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); results.append(json.loads(self.rfile.read(n)))
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", web_port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

procs = []
try:
    procs.append(subprocess.Popen(["Xvfb", DISPLAY, "-screen", "0", "1100x800x24", "-nolisten", "tcp"], stderr=subprocess.DEVNULL))
    time.sleep(1)
    env = dict(os.environ, HOME=home, XDG_DATA_HOME=os.path.join(home, ".local/share"), XDG_CONFIG_HOME=os.path.join(home, ".config"), DISPLAY=DISPLAY, LIBGL_ALWAYS_SOFTWARE="1", WINIT_UNIX_BACKEND="x11",
               AF_STORE="pkcs12:" + os.path.join(ROOT, "testdata/pki/firmante-rsa.p12"))
    env.pop("WAYLAND_DISPLAY", None)
    log = open(os.path.join(WORK, "app.log"), "wb")
    app = subprocess.Popen([BIN, f"afirma://websocket?ports={ws_port}&v=4&jvc=4"], env=env, stdout=log, stderr=log)
    procs.append(app)
    time.sleep(2)
    procs.append(subprocess.Popen(["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
                                   "--no-first-run", f"--user-data-dir={WORK}/chrome", f"http://127.0.0.1:{web_port}/page.html"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    xenv = dict(os.environ, DISPLAY=DISPLAY)
    def x(*args): return subprocess.run(["xdotool", *args], env=xenv, capture_output=True, text=True).stdout.strip()
    def shot(name): subprocess.run(["import", "-window", "root", os.path.join(WORK, name)], env=xenv)
    # Espera a que la ventana aparezca (solo se muestra cuando hace falta al usuario).
    win = ""
    for _ in range(120):
        win = x("search", "--onlyvisible", "--name", "AutoFirma")
        if win: break
        time.sleep(1)
    if not win: raise SystemExit("la ventana no ha aparecido")
    win = win.splitlines()[0]
    time.sleep(8); shot("1-ventana.png")
    x("windowfocus", "--sync", win)
    x("type", "--delay", "60", "12341234"); time.sleep(0.5); x("key", "Return")
    time.sleep(4); shot("2-certificado.png")
    x("windowfocus", "--sync", win); x("key", "Return")
    for _ in range(60):
        if results: break
        time.sleep(1)
    shot("3-final.png")
    if not results: raise SystemExit("la página no ha recibido respuesta")
    r = results[0]
    print(json.dumps({k: (v[:60] + "…") if isinstance(v, str) and len(v) > 60 else v for k, v in r.items()}, ensure_ascii=False))
    if not r.get("ok"): raise SystemExit("error devuelto a la página")
    sig = base64.b64decode(r["sig"].replace("-", "+").replace("_", "/"))
    open(os.path.join(WORK, "firma.csig"), "wb").write(sig)
    if FORMAT.lower().startswith("cades"):
        v = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", os.path.join(WORK, "firma.csig"), "-noverify",
                            "-out", os.path.join(WORK, "datos")], capture_output=True, text=True)
        print("openssl:", (v.stderr or v.stdout).strip())
        print("datos firmados:", open(os.path.join(WORK, "datos"), "rb").read())
    for _ in range(40):
        if app.poll() is not None: break
        time.sleep(1)
    print("código de salida de la aplicación:", app.poll())
finally:
    for p in reversed(procs):
        if p.poll() is None: p.terminate()
    srv.shutdown()
