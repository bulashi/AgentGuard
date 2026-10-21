"""Exercise the native launcher exchange without putting a token in CLI arguments."""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from backend.config.model_profiles import WindowsCredentialCipher

ROOT = Path(__file__).resolve().parents[1]


class BootstrapBridge(HTTPServer):
    def __init__(self, token: str):
        self.token = token
        self.path = "/" + secrets.token_hex(32)
        self.deadline = time.monotonic() + 30
        self.consumed = False
        super().__init__(("127.0.0.1", 0), BridgeHandler)


class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        server = self.server
        valid = (
            self.client_address[0] == "127.0.0.1"
            and self.headers.get("Host") == f"127.0.0.1:{server.server_port}"
            and self.path == server.path
            and time.monotonic() <= server.deadline
            and not server.consumed
        )
        if not valid:
            self.send_error(404)
            return
        server.consumed = True
        body = json.dumps({"launch_token": server.token}).encode("ascii")
        server.token = ""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def browser_code(bridge: str, target: str) -> str:
    return """async page => {
      const bridge = BRIDGE, target = TARGET;
      const response = await fetch(bridge);
      if (!response.ok) throw new Error('native launcher bridge rejected');
      const value = await response.json();
      if (!/^[0-9a-f]{64}$/.test(value.launch_token)) throw new Error('invalid launch token');
      try {
        await page.goto('about:blank');
        await page.goto(target + '#launch_token=' + value.launch_token);
        await page.getByTestId('task-overview').waitFor({timeout:30000});
        if (new URL(page.url()).hash.includes('launch_token')) throw new Error('token retained');
        const cookies = await page.context().cookies();
        const session = cookies.find(item => item.name === 'agentguard_operator');
        if (!session?.httpOnly || session.sameSite !== 'Strict' || session.path !== '/api')
          throw new Error('operator cookie protection missing');
        const stored = await page.evaluate(() => ({
          local: Object.keys(localStorage), session: Object.keys(sessionStorage)
        }));
        if ([...stored.local, ...stored.session].some(key => /token|secret|api.?key/i.test(key)))
          throw new Error('secret browser storage found');
        const read = await page.request.get(new URL('/api/tasks', target).href);
        if (!read.ok()) throw new Error('authenticated task read failed');
        await page.reload();
        await page.getByTestId('task-overview').waitFor({timeout:30000});
        return {status:'PASS', token_removed:true, http_only:true,
          same_site:'Strict', no_secret_storage:true, authenticated_read:true, reload:true};
      } finally {
        value.launch_token = '';
        if (new URL(page.url()).hash.includes('launch_token')) await page.goto(target);
      }
    }""".replace("BRIDGE", json.dumps(bridge)).replace("TARGET", json.dumps(target))


def result_passed(output: str) -> bool:
    for line in output.splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("status") == "PASS":
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", default="agfinal")
    parser.add_argument("--task")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    token = WindowsCredentialCipher().decrypt(
        (ROOT / ".native/operator-session.dpapi").read_text(encoding="ascii")
    )
    target = "http://127.0.0.1:8088/"
    if args.task:
        from urllib.parse import urlencode

        target += "?" + urlencode({"task": args.task})
    server = BootstrapBridge(token)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cli = ROOT / "frontend/node_modules/.bin/playwright-cli.cmd"
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        code_path = args.output.with_suffix(".cli.js").resolve()
        code_path.write_text(
            browser_code(f"http://127.0.0.1:{server.server_port}{server.path}", target),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                str(cli),
                "-s=" + args.session,
                "run-code",
                "--filename=" + str(code_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (result.stdout + result.stderr).replace(token, "[REDACTED]")
        passed = result.returncode == 0 and result_passed(output)
        args.output.write_text(output, encoding="utf-8")
        print(json.dumps({"status": "PASS" if passed else "FAIL", "log": str(args.output)}))
        return 0 if passed else 1
    finally:
        server.token = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
