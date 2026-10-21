"""Browser verification against the parent-owned authenticated isolated stack."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

from scripts.native_web import NativeWebServer
from scripts.verify_browser_bootstrap import BootstrapBridge, result_passed

ROOT = Path(__file__).resolve().parents[1]


def browser_code(bridge: str, target: str, output: Path) -> str:
    code = r"""async page => {
      const bridge = BRIDGE, target = TARGET, output = OUTPUT;
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      const response = await fetch(bridge);
      if (!response.ok) throw new Error('ephemeral operator bridge rejected');
      const launch = await response.json();
      await page.setViewportSize({width:1440, height:1000});
      try {
        await page.goto(target + '#launch_token=' + launch.launch_token);
        launch.launch_token = '';
        await page.getByTestId('task-overview').waitFor({timeout:30000});
        if (page.url().includes('launch_token')) throw new Error('launch token was retained');
        await page.getByTestId('nav-security').click();
        const panel = page.getByTestId('security-proof');
        await panel.waitFor();
        const closeDrawer = async () => {
          await page.locator('.ant-drawer-close').click();
          await page.getByTestId('evidence-detail').waitFor({state:'hidden'});
          await page.locator('.ant-drawer-content-wrapper').waitFor({state:'hidden'});
          await page.locator('.ant-drawer-mask').waitFor({state:'hidden'});
        };
        const waitDrawer = async () => {
          await page.getByTestId('evidence-detail').waitFor();
          await page.waitForFunction(() => {
            const wrapper = document.querySelector('.ant-drawer-content-wrapper');
            if (!wrapper) return false;
            const transform = new DOMMatrixReadOnly(getComputedStyle(wrapper).transform);
            return Math.abs(transform.m41) < 0.1 && Math.abs(transform.m42) < 0.1;
          });
        };
        await page.getByText('36 项逐场景核验').waitFor({timeout:30000});
        const matrixResponse = await page.request.get(target + 'api/security/matrix');
        const matrix = await matrixResponse.json();
        if (!matrixResponse.ok() || matrix.latest_batch?.status !== 'VERIFIED'
            || matrix.scenarios.length !== 36
            || matrix.scenarios.some(x => x.latest_result?.status !== 'PASS'))
          throw new Error('scenario matrix is not bound to all 36 actual records');
        const posts = [];
        page.on('request', request => {
          if (request.method() === 'POST'
              && new URL(request.url()).pathname === '/api/security/proofs')
            posts.push(request.url());
        });
        await panel.getByRole('button', {name:'验证拒绝与合法对照'}).click();
        await page.getByRole('button', {name:/取\s*消/}).click();
        if (posts.length) throw new Error('cancel confirmation executed a probe');
        const decision = page.waitForResponse(r => r.request().method() === 'POST'
          && new URL(r.url()).pathname === '/api/security/proofs', {timeout:90000});
        await panel.getByRole('button', {name:'验证拒绝与合法对照'}).click();
        await page.getByRole('button', {name:'确认验证'}).click();
        const proofResponse = await decision, proof = await proofResponse.json();
        if (!proofResponse.ok() || proof.status !== 'PASS' || proof.llm_required !== false
            || proof.attack.gateway.decision !== 'DENY'
            || proof.attack.gateway.reason_code !== 'RESOURCE_NOT_ALLOWED'
            || proof.attack.refund_delta !== 0 || proof.attack.notification_delta !== 0
            || proof.control?.gateway.state !== 'COMMITTED' || proof.control?.refund_delta !== 1
            || !proof.attack.holder_proof_valid || !proof.attack.receipt_valid
            || !proof.attack.record_binding_valid)
          throw new Error('browser real probe failed: ' + (proof.reason_code ?? proof.status));
        await panel.getByText('本次核验证据').waitFor({timeout:30000});
        await page.waitForFunction(() =>
          !document.querySelector('[data-testid="security-proof"] .proof-running'));
        if (posts.length !== 1) throw new Error('one confirmation submitted multiple probes');
        await page.screenshot({
          path:output + '/security-desktop.png', fullPage:true, animations:'disabled'
        });
        await panel.screenshot({path:output + '/proof-desktop.png', animations:'disabled'});
        for (let i=0; i<7; i++) {
          await panel.locator('.proof-check-row').nth(i).click();
          await waitDrawer();
          const text = await page.getByTestId('evidence-detail').innerText();
          if (!text.includes('direct_verification_or_observed_database_state'))
            throw new Error('proof row omitted its observation');
          if (text.includes('credential_chain":') || text.includes('holder_proof":')
              || text.includes('signature":{"value'))
            throw new Error('browser exposed reusable authority material');
          await closeDrawer();
        }
        await panel.getByRole('button', {name:'请求与签名'}).click();
        await waitDrawer();
        if (!(await page.getByTestId('evidence-detail').innerText())
            .includes('BFF_public_projection'))
          throw new Error('request details lost their public projection boundary');
        await page.screenshot({
          path:output + '/request-detail-desktop.png', fullPage:true, animations:'disabled'
        });
        await closeDrawer();
        await page.locator('tr[data-row-key="' + matrix.scenarios[0].id + '"]').click();
        await page.getByText('本批次实际核验').waitFor();
        await waitDrawer();
        const scenarioText = await page.getByTestId('evidence-detail').innerText();
        if (!scenarioText.includes(matrix.scenarios[0].test_ref)
            || !scenarioText.includes('退款行数\uFF08前 → 后\uFF09'))
          throw new Error(
            'scenario details lack unique test mapping or actual before/after values'
          );
        await page.screenshot({
          path:output + '/scenario-detail-desktop.png', fullPage:true, animations:'disabled'
        });
        await closeDrawer();
        await page.setViewportSize({width:390, height:844});
        await panel.scrollIntoViewIfNeeded();
        await page.waitForFunction(() => {
          const bounds = document.querySelector('[data-testid="security-proof"]')
            .getBoundingClientRect();
          return bounds.left >= 0 && bounds.right <= innerWidth + 1 && scrollX === 0;
        });
        const geometry = await page.evaluate(() => ({
          viewport:innerWidth, width:document.documentElement.scrollWidth
        }));
        if (geometry.width > geometry.viewport + 1)
          throw new Error('mobile document overflows: ' + JSON.stringify(geometry));
        await page.screenshot({
          path:output + '/security-mobile.png', fullPage:true, animations:'disabled'
        });
        await panel.screenshot({path:output + '/proof-mobile.png', animations:'disabled'});
        await panel.getByRole('button', {name:'完整记录'}).click();
        await waitDrawer();
        await page.screenshot({
          path:output + '/proof-detail-mobile.png', fullPage:true, animations:'disabled'
        });
        await closeDrawer();
        await page.reload();
        await page.getByTestId('security-proof').waitFor({timeout:30000});
        const history = await page.request.get(target + 'api/security/proofs');
        if (!history.ok() || !(await history.json()).items.some(x => x.proof_id === proof.proof_id))
          throw new Error('saved proof disappeared on reload');
        const cookies = await page.context().cookies();
        const operator = cookies.find(x => x.name === 'agentguard_operator');
        if (!operator?.httpOnly || operator.sameSite !== 'Strict')
          throw new Error('operator cookie boundary missing');
        await page.setViewportSize({width:1440, height:1000});
        await page.goto(target + '?task=' + encodeURIComponent(proof.task_id) + '#evidence');
        await page.getByRole('tab', {name:'撤销控制', exact:true}).click();
        const revocation = page.getByTestId('credential-revocation');
        await revocation.waitFor({timeout:30000});
        const rootId = proof.control.request.credential_ids[0];
        await page.waitForFunction(id =>
          document.querySelector('[data-testid="revocation-credential"]')
            ?.textContent?.includes(id), rootId);
        const revocationPosts = [], revocationBodies = [], verificationPosts = [];
        page.on('request', request => {
          const path = new URL(request.url()).pathname;
          if (request.method() === 'POST' && path.endsWith('/revoke')) {
            revocationPosts.push(path);
            revocationBodies.push(request.postDataJSON());
          }
          if (request.method() === 'POST' && path.endsWith('/verify-revoked'))
            verificationPosts.push(path);
        });
        if (await page.getByTestId('revocation-reason').count())
          throw new Error('revocation unexpectedly requires a free-text reason');
        await page.getByTestId('revocation-open-confirm').click();
        let confirmation = page.getByRole('dialog', {name:'确认撤销凭证', exact:true});
        await confirmation.getByRole('button', {name:'取消', exact:true}).click();
        await confirmation.waitFor({state:'hidden'});
        if (revocationPosts.length) throw new Error('cancel executed a revocation');
        await page.getByTestId('revocation-open-confirm').click();
        await page.getByTestId('revocation-confirm-scope').check();
        const revokeResponse = page.waitForResponse(r => r.request().method() === 'POST'
          && new URL(r.url()).pathname ===
            '/api/tasks/' + proof.task_id + '/credentials/' + rootId + '/revoke', {timeout:90000});
        await page.getByTestId('revocation-submit').click();
        const revokedResponse = await revokeResponse, revoked = await revokedResponse.json();
        if (!revokedResponse.ok() || revoked.status !== 'REVOKED'
          || revoked.credential_id !== rootId
          || revoked.boundary !== 'DISPATCH_BOUNDARY_NO_ROLLBACK' || revoked.descendant_count !== 2
          || revoked.revocation_reason !== '用户主动撤销授权'
          || revocationBodies.length !== 1 || revocationBodies[0].confirmed !== true
          || revocationBodies[0].reason !== '用户主动撤销授权')
          throw new Error('browser revocation did not bind the selected root');
        await page.getByTestId('revocation-saved-record').waitFor();
        await page.getByTestId('revocation-verify-open-confirm').click();
        confirmation = page.getByRole('dialog', {name:'确认验证撤销拦截', exact:true});
        await confirmation.getByRole('button', {name:'取消', exact:true}).click();
        await confirmation.waitFor({state:'hidden'});
        if (verificationPosts.length) throw new Error('cancel executed a verification request');
        await page.getByTestId('revocation-verify-open-confirm').click();
        await page.getByTestId('revocation-verify-confirm-scope').check();
        const verifyResponse = page.waitForResponse(r => r.request().method() === 'POST'
          && new URL(r.url()).pathname.endsWith('/' + rootId + '/verify-revoked'), {timeout:90000});
        await page.getByTestId('revocation-verify-submit').click();
        const verifiedResponse = await verifyResponse, verified = await verifiedResponse.json();
        if (!verifiedResponse.ok() || verified.status !== 'PASS'
          || verified.reason_code !== 'ANCESTOR_REVOKED'
          || !verified.holder_proof_valid || !verified.chain_signature_valid
          || !verified.receipt_valid
          || !verified.record_binding_valid || !verified.budget_unchanged
          || verified.new_holder_proof !== true
          || verified.before.refund_rows !== 1 || verified.after.refund_rows !== 1
          || verified.before.notification_rows !== 0 || verified.after.notification_rows !== 0
          || verified.before.refund_amount_fen !== 7000
          || verified.after.refund_amount_fen !== 7000)
          throw new Error('fresh proof after revocation failed its real effect/receipt checks'
            + ': HTTP ' + verifiedResponse.status()
            + ', public reason ' + (verified.reason_code || 'UNAVAILABLE'));
        await waitDrawer();
        await page.screenshot({
          path:output + '/revocation-denial-receipt-desktop.png',
          fullPage:true, animations:'disabled'
        });
        if (!(await page.getByTestId('evidence-detail').innerText()).includes('ANCESTOR_REVOKED'))
          throw new Error('actual denial receipt is not reachable');
        await closeDrawer();
        await page.getByTestId('revocation-verification-result').waitFor();
        if (revocationPosts.length !== 1 || verificationPosts.length !== 1)
          throw new Error('one confirmation generated duplicate mutations');
        await page.screenshot({
          path:output + '/revocation-desktop.png', fullPage:true, animations:'disabled'
        });
        await revocation.screenshot({
          path:output + '/revocation-panel-desktop.png', animations:'disabled'
        });
        await page.getByTestId('revocation-verify-details').click();
        await waitDrawer();
        const verifyText = await page.getByTestId('evidence-detail').innerText();
        if (!verifyText.includes(verified.request_id)
            || !verifyText.includes('"budget_unchanged": true'))
          throw new Error('verification projection omitted real request/budget observation');
        const verificationProjection = JSON.parse(await page.getByTestId('evidence-detail')
          .locator('pre.projection-json').first().innerText());
        const hasAuthorityMaterial = value => value !== null && typeof value === 'object'
          && Object.entries(value).some(([key, child]) =>
            ['holder_proof', 'credential_chain'].includes(key)
            || hasAuthorityMaterial(child));
        if (verificationProjection.request_id !== verified.request_id
          || verificationProjection.budget_unchanged !== true)
          throw new Error('verification JSON does not match the real response');
        if (hasAuthorityMaterial(verificationProjection))
          throw new Error('verification exposed reusable authority material');
        await closeDrawer();
        await page.setViewportSize({width:390, height:844});
        await revocation.scrollIntoViewIfNeeded();
        const revocationGeometry = await page.evaluate(() => {
          const bounds = document.querySelector('[data-testid="credential-revocation"]')
            .getBoundingClientRect();
          return {
            viewport:innerWidth, width:document.documentElement.scrollWidth,
            left:bounds.left, right:bounds.right
          };
        });
        if (revocationGeometry.width > revocationGeometry.viewport + 1
          || revocationGeometry.left < 0
          || revocationGeometry.right > revocationGeometry.viewport + 1)
          throw new Error('mobile revocation overflows: ' + JSON.stringify(revocationGeometry));
        await page.screenshot({
          path:output + '/revocation-mobile.png', fullPage:true, animations:'disabled'
        });
        await revocation.screenshot({
          path:output + '/revocation-panel-mobile.png', animations:'disabled'
        });
        await page.getByTestId('revocation-verify-receipt').click();
        await waitDrawer();
        await page.screenshot({
          path:output + '/revocation-denial-receipt-mobile.png',
          fullPage:true, animations:'disabled'
        });
        await closeDrawer();
        await page.reload();
        await page.getByRole('tab', {name:'撤销控制', exact:true}).click();
        await page.getByTestId('revocation-saved-record').waitFor();
        const finalSnapshotResponse = await page.request.get(target + 'api/tasks/' + proof.task_id);
        const finalSnapshot = await finalSnapshotResponse.json();
        if (!finalSnapshotResponse.ok() || !finalSnapshot.credentials.some(x =>
          x.credential_id === rootId
          && x.revoked_at !== null && x.revocation_reason === '用户主动撤销授权')
          || finalSnapshot.business_effects.refunds.length !== 1
          || finalSnapshot.business_effects.notifications.length !== 0)
          throw new Error(
            'revocation or the preserved original business effect disappeared on reload'
          );
        if (errors.length) throw new Error('browser page errors: ' + errors.join('; '));
        return {status:'PASS', proof_id:proof.proof_id, task_id:proof.task_id,
          real_gateway_denial:true, attack_refunds:0, separate_control_refunds:1,
          rows_inspected:7, scenario_mapping:36, desktop:[1440,1000], mobile:[390,844],
          cancel_without_effect:true, persisted_history:true, page_errors:errors,
          mobile_geometry:geometry,
          root_revocation:true, default_revocation_reason_saved:true,
          fresh_revoked_request:verified.request_id, revoked_denial:'ANCESTOR_REVOKED',
          revocation_cancel_without_effect:true, preserved_refunds:1, revoked_new_refunds:0,
          actual_denial_receipt_opened:true, revocation_persisted:true,
          revocation_mobile_geometry:revocationGeometry};
      } finally {
        launch.launch_token = '';
        if (page.url().includes('launch_token')) await page.goto('about:blank');
      }
    }"""
    for name, value in (("BRIDGE", bridge), ("TARGET", target), ("OUTPUT", output.as_posix())):
        code = code.replace(name, json.dumps(value))
    return code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        parser.error("allocate a new browser evidence directory inside the project")
    token = os.environ.get("AGENTGUARD_OPERATOR_SESSION_SECRET", "")
    if os.environ.get("AGENTGUARD_OPERATOR_AUTH_REQUIRED") != "true" or len(token) != 64:
        parser.error("browser proof requires the parent-owned authenticated isolated stack")
    output.mkdir(parents=True)
    summary = ROOT / "artifacts/security/current-ledger-summary.json"
    artifact_root = Path(os.environ["AGENTGUARD_UI_ARTIFACT_ROOT"])
    (artifact_root / "security").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(summary, artifact_root / "security/current-ledger-summary.json")
    web = NativeWebServer(ROOT / "frontend/dist", 0, backend_port=18090)
    bridge = BootstrapBridge(token)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (web, bridge)
    ]
    for thread in threads:
        thread.start()
    cli = ROOT / "frontend/node_modules/.bin/playwright-cli.cmd"
    session = "security-closure-" + output.parent.name[-8:]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    code = output / "browser.cli.js"
    code.write_text(
        browser_code(
            f"http://127.0.0.1:{bridge.server_port}{bridge.path}",
            f"http://127.0.0.1:{web.server_port}/",
            output,
        ),
        encoding="utf-8",
    )
    try:
        opened = subprocess.run(
            [str(cli), "-s=" + session, "open", "about:blank"],
            cwd=output,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            creationflags=flags,
        )
        if opened.returncode:
            raise RuntimeError("isolated browser could not start")
        run = subprocess.run(
            [str(cli), "-s=" + session, "run-code", "--filename=" + str(code)],
            cwd=output,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            creationflags=flags,
        )
        text = (run.stdout + run.stderr).replace(token, "[REDACTED]")
        (output / "browser.log").write_text(text, encoding="utf-8")
        passed = run.returncode == 0 and result_passed(text)
        print(
            json.dumps({"status": "PASS" if passed else "FAIL", "log": str(output / "browser.log")})
        )
        return 0 if passed else 1
    finally:
        subprocess.run(
            [str(cli), "-s=" + session, "close"],
            cwd=output,
            capture_output=True,
            timeout=30,
            creationflags=flags,
        )
        bridge.token = ""
        for server in (bridge, web):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
