#!/usr/bin/env python3
"""Production-ready static file server with fallback proxy to Wayback Machine."""

import gzip
import http.server
import io
import logging
import mimetypes
import os
import re
import signal
import socketserver
import ssl
import threading
import urllib.request
from urllib.error import HTTPError, URLError

# ── Configuration ──────────────────────────────────────────────────────────────
PORT         = int(os.environ.get("PORT", 8000))
HOST         = os.environ.get("HOST", "")
PROXY_BASE   = "https://web.archive.org/web/20220101000000id_/https://shutdown.gallery"
PROXY_TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", 15))
LOG_LEVEL    = os.environ.get("LOG_LEVEL", "INFO").upper()

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("gallery")

# ── MIME types ─────────────────────────────────────────────────────────────────
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("font/otf",              ".otf")
mimetypes.add_type("font/woff",             ".woff")
mimetypes.add_type("font/woff2",            ".woff2")
mimetypes.add_type("model/gltf+json",       ".gltf")
mimetypes.add_type("model/gltf-binary",     ".glb")

# MIME types eligible for gzip compression
COMPRESSIBLE = {
    "text/html", "text/css", "application/javascript",
    "application/json", "image/svg+xml", "text/plain",
}

# Cache-Control values
CACHE_IMMUTABLE = "public, max-age=31536000, immutable"  # hashed static assets
CACHE_PROXIED   = "public, max-age=86400"                # proxied assets (1 day)
CACHE_HTML      = "no-cache, no-store, must-revalidate"  # HTML pages

SECURITY_HEADERS = {
    "X-Content-Type-Options":  "nosniff",
    "X-Frame-Options":         "SAMEORIGIN",
    "Referrer-Policy":         "strict-origin-when-cross-origin",
    "X-XSS-Protection":        "1; mode=block",
}

_HASHED_ASSET = re.compile(r'\.[a-f0-9]{7,}\.(js|css)(\?.*)?$')

# Thread-safe set of paths already saved to disk from the proxy
_cached_paths: set = set()
_cache_lock   = threading.Lock()


# ── Request handler ────────────────────────────────────────────────────────────
class GalleryHandler(http.server.SimpleHTTPRequestHandler):

    # Silence the default per-request log line; we write our own.
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        local = self.translate_path(self.path)
        if self._local_exists(local):
            self._serve_local(local)
        else:
            self._serve_proxy()

    # ── Local ──────────────────────────────────────────────────────────────────
    def _local_exists(self, path: str) -> bool:
        if os.path.isfile(path):
            return True
        if os.path.isdir(path) and os.path.isfile(os.path.join(path, "index.html")):
            return True
        return False

    def _serve_local(self, local: str):
        # Directories (index.html): delegate to SimpleHTTPRequestHandler.
        if os.path.isdir(local):
            super().do_GET()
            return

        mime, _ = mimetypes.guess_type(local)
        mime = mime or "application/octet-stream"
        is_html = mime == "text/html"

        cache = (
            CACHE_HTML      if is_html
            else CACHE_IMMUTABLE if _HASHED_ASSET.search(self.path)
            else CACHE_PROXIED
        )

        try:
            with open(local, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self.send_error(500, str(exc))
            return

        # Gzip for compressible types when client accepts it
        accept_enc = self.headers.get("Accept-Encoding", "")
        use_gzip = "gzip" in accept_enc and mime in COMPRESSIBLE and len(data) > 512
        if use_gzip:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(data)
            data = buf.getvalue()

        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",  cache)
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(data)
        log.info("200 LOCAL  %s", self.path)

    # ── Proxy ──────────────────────────────────────────────────────────────────
    def _serve_proxy(self):
        url = PROXY_BASE + self.path
        req = urllib.request.Request(url, headers={
            "User-Agent":      "Mozilla/5.0 (compatible; GalleryServer/1.0)",
            "Accept-Encoding": "identity",
        })

        ctx = ssl.create_default_context()
        # The Wayback Machine uses valid certs; disable only if needed.
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=PROXY_TIMEOUT) as resp:
                body = resp.read()
                mime = resp.headers.get("Content-Type", "application/octet-stream")

                self.send_response(200)
                self.send_header("Content-Type",              mime)
                self.send_header("Content-Length",            str(len(body)))
                self.send_header("Cache-Control",             CACHE_PROXIED)
                self.send_header("Access-Control-Allow-Origin", "*")
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
                log.info("200 PROXY  %s", self.path)

                # Persist to disk so the next request is served locally.
                self._persist(body)

        except HTTPError as exc:
            self.send_error(exc.code, exc.reason)
            log.warning("%d PROXY  %s", exc.code, self.path)
        except TimeoutError:
            self.send_error(504, "Proxy upstream timed out")
            log.error("504 PROXY  %s", self.path)
        except URLError as exc:
            self.send_error(502, f"Bad gateway: {exc.reason}")
            log.error("502 PROXY  %s — %s", self.path, exc.reason)
        except Exception as exc:
            self.send_error(500, str(exc))
            log.error("500 PROXY  %s — %s", self.path, exc)

    def _persist(self, body: bytes):
        """Write a proxied response to disk so future hits are served locally."""
        local = self.translate_path(self.path)
        with _cache_lock:
            if local in _cached_paths:
                return
            _cached_paths.add(local)
        try:
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, "wb") as fh:
                fh.write(body)
            log.debug("PERSISTED  %s", self.path)
        except Exception as exc:
            log.debug("Persist failed for %s: %s", self.path, exc)

    def _send_security_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)


# ── Threaded TCP server ────────────────────────────────────────────────────────
class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True   # avoid "Address already in use" on restart
    daemon_threads      = True   # worker threads die with the main thread


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    server = Server((HOST, PORT), GalleryHandler)
    addr = HOST or "0.0.0.0"
    log.info("Gallery server → http://%s:%d  (threads=on, proxy-timeout=%ds)",
             addr, PORT, PROXY_TIMEOUT)

    def _shutdown(sig, _frame):
        log.info("Signal %s received — shutting down…", signal.Signals(sig).name)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.serve_forever()


if __name__ == "__main__":
    main()
