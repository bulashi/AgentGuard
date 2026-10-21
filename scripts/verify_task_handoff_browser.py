"""Verify the current-task authorization handoff in an isolated native stack."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

from scripts.native_web import NativeWebServer
from scripts.verify_browser_bootstrap import BootstrapBridge, result_passed

ROOT = Path(__file__).resolve().parents[1]


def require_isolated_stack() -> tuple[str, str]:
    token = os.environ.get("AGENTGUARD_OPERATOR_SESSION_SECRET", "")
    database = os.environ.get("AGENTGUARD_DATABASE_URL", "")
    ui_database = os.environ.get("AGENTGUARD_UI_DATABASE_URL", "")
    api_url = os.environ.get("AGENTGUARD_UI_API_URL", "")
    if os.environ.get("AGENTGUARD_OPERATOR_AUTH_REQUIRED") != "true":
        raise RuntimeError("current-task handoff requires the authenticated isolated stack")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise RuntimeError("current-task handoff requires an ephemeral operator session")
    main = urlsplit(database)
    reader = urlsplit(ui_database)
    if main.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("main database must be localhost")
    if not re.fullmatch(r"/agentguard_test_backend_[a-f0-9]{16}", main.path):
        raise RuntimeError("refusing a database outside this run's disposable test database")
    if (reader.hostname, reader.port, reader.path) != (main.hostname, main.port, main.path):
        raise RuntimeError("UI reader must point at the same disposable test database")
    if api_url != "http://127.0.0.1:18090":
        raise RuntimeError("UI BFF must be the authenticated isolated stack on port 18090")
    for name, value in os.environ.items():
        if name.upper().startswith("AGENTGUARD_") and name.upper().endswith("_URL"):
            target = urlsplit(value)
            if target.port in {8088, 8090}:
                raise RuntimeError(f"refusing demo runtime URL from {name}")
    return token, api_url


def browser_code(bridge: str, target: str, output: Path) -> str:
    code = r"""async page => {
      const bridge = __BRIDGE_URL__, target = __TARGET_URL__, output = __OUTPUT_DIR__;
      const errors = [];
      const posts = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('request', request => {
        const url = new URL(request.url());
        if (request.method() === 'POST' && url.origin === new URL(target).origin)
          posts.push(url.pathname);
      });

      const apiGet = async path => {
        const response = await page.request.get(new URL(path, target).href);
        if (!response.ok()) throw new Error(path + ' returned HTTP ' + response.status());
        return response.json();
      };
      const waitCompleted = async (taskId, runId) => {
        const deadline = Date.now() + 90000;
        while (Date.now() < deadline) {
          const snapshot = await apiGet('api/tasks/' + encodeURIComponent(taskId));
          const runs = snapshot.workflow_runs || [];
          if (runs.length === 1 && runs[0].run_id === runId
              && !['QUEUED', 'RUNNING'].includes(runs[0].state)) {
            if (runs[0].state !== 'COMPLETED' || runs[0].reason_code !== null)
              throw new Error(
                'workflow ended without success: ' + runs[0].state + '/' + runs[0].reason_code
              );
            return snapshot;
          }
          await new Promise(resolve => setTimeout(resolve, 200));
        }
        throw new Error('workflow did not complete within 90 seconds');
      };

      const launchResponse = await fetch(bridge);
      if (!launchResponse.ok) throw new Error('ephemeral operator bridge rejected');
      const launch = await launchResponse.json();
      if (!/^[0-9a-f]{64}$/.test(launch.launch_token || ''))
        throw new Error('invalid ephemeral launch token');
      await page.setViewportSize({width:1440, height:1000});
      try {
        await page.goto(target + '#launch_token=' + launch.launch_token);
        launch.launch_token = '';
        await page.getByTestId('task-overview').waitFor({timeout:30000});
        if (page.url().includes('launch_token'))
          throw new Error('launch token was retained in the browser URL');

        const cookie = (await page.context().cookies()).find(
          item => item.name === 'agentguard_operator'
        );
        if (!cookie?.httpOnly || cookie.sameSite !== 'Strict' || cookie.path !== '/api')
          throw new Error('operator session cookie is missing its expected protections');

        const tickets = await apiGet('api/business/tickets');
        const ticket = (tickets.items || []).find(item => item.status === 'OPEN'
          && item.can_refund === true && item.verification_status === 'VERIFIED'
          && item.payment_verification_status === 'VERIFIED' && item.already_processed === false
          && item.in_progress === false && item.refundable_amount_fen >= 7000
          && item.transaction_remaining_fen >= 7000);
        if (!ticket) throw new Error('fresh isolated catalog has no verified 70-yuan ticket');

        await page.getByRole('button', {name:'新建任务'}).click();
        const createDialog = page.getByRole('dialog', {name:'基于已有工单创建待授权任务'});
        await createDialog.waitFor();
        await createDialog.locator('.ant-select-selector').first().click();
        const ticketOption = page.locator('.record-select-dropdown .ant-select-item-option')
          .filter({hasText:ticket.ticket_id + ' · ' + ticket.tenant_id}).first();
        await ticketOption.waitFor();
        await ticketOption.click();
        const selectedTicket = createDialog.locator('.ant-select-selection-item').first();
        await selectedTicket.waitFor();
        if (!(await selectedTicket.innerText()).includes(ticket.ticket_id)
            || !(await selectedTicket.innerText()).includes(ticket.tenant_id))
          throw new Error('UI ticket selection differs from the verified API candidate');
        await page.screenshot({
          path:output + '/01-pending-task-form.png', fullPage:true, animations:'disabled'
        });

        const createdResponseWait = page.waitForResponse(response =>
          response.request().method() === 'POST'
          && new URL(response.url()).pathname === '/api/tasks', {timeout:60000});
        await createDialog.getByRole('button', {name:'创建待授权任务'}).click();
        const createdResponse = await createdResponseWait;
        const created = await createdResponse.json();
        if (!createdResponse.ok() || created.status !== 'PENDING_AUTHORIZATION' || !created.task_id)
          throw new Error('UI did not create a pending authorization task');
        const taskId = created.task_id;
        let snapshot = await apiGet('api/tasks/' + encodeURIComponent(taskId));
        if (snapshot.task?.task_id !== taskId || snapshot.task.ticket_id !== ticket.ticket_id
            || snapshot.task.status !== 'PENDING_AUTHORIZATION'
            || snapshot.credentials.length !== 0)
          throw new Error('created task is not bound to the selected ticket in pending state');
        await page.getByTestId('task-overview').waitFor();
        await page.waitForFunction(
          id => new URL(location.href).searchParams.get('task') === id, taskId
        );
        await page.getByLabel(taskId, {exact:true}).waitFor();
        await page.screenshot({
          path:output + '/02-pending-task-created.png', fullPage:true, animations:'disabled'
        });

        await page.getByRole('button', {name:'打开当前任务授权'}).click();
        await page.getByTestId('authorization-explorer').waitFor();
        await page.getByText('当前授权任务\uFF1A工单 ' + ticket.ticket_id, {exact:true}).waitFor();
        await page.screenshot({
          path:output + '/03-current-task-authorization.png', fullPage:true, animations:'disabled'
        });

        await page.getByRole('button', {name:'查看并授权当前任务'}).click();
        const authDialog = page.getByRole('dialog', {name:'确认任务授权'});
        await authDialog.waitFor();
        if (!(await authDialog.innerText()).includes(taskId))
          throw new Error('authorization dialog changed task context');
        await authDialog.getByRole('checkbox', {name:'我确认本次工单、客户和授权额度'}).check();
        await page.screenshot({
          path:output + '/04-root-authorization-confirmation.png',
          fullPage:true, animations:'disabled'
        });
        const authResponseWait = page.waitForResponse(response =>
          response.request().method() === 'POST'
          && new URL(response.url()).pathname === '/api/tasks/' + taskId + '/authorize',
          {timeout:90000});
        await authDialog.getByRole('button', {name:'确认签发根授权'}).click();
        const authResponse = await authResponseWait;
        const authorization = await authResponse.json();
        if (authResponse.status() !== 201 || authorization.task_id !== taskId
            || authorization.status !== 'AUTHORIZED' || !authorization.credential_id
            || authorization.signature?.algorithm !== 'SM2')
          throw new Error('real root authorization API did not issue a bound signed credential');

        await page.getByTestId('task-overview').waitFor({timeout:30000});
        await page.getByTestId('authorization-explorer').waitFor({state:'detached', timeout:30000});
        await page.waitForFunction(
          id => new URL(location.href).searchParams.get('task') === id, taskId
        );
        await page.getByLabel(taskId, {exact:true}).waitFor();
        snapshot = await apiGet('api/tasks/' + encodeURIComponent(taskId));
        const roots = snapshot.credentials.filter(item => item.credential_type === 'ROOT');
        if (snapshot.task.task_id !== taskId || snapshot.task.status !== 'AUTHORIZED'
            || roots.length !== 1 || roots[0].credential_id !== authorization.credential_id
            || roots[0].signature?.valid !== true || roots[0].stored_hash_valid !== true)
          throw new Error(
            'authorization return did not retain the same task and valid root credential'
          );
        const authorizedTaskId = snapshot.task.task_id;
        const authorizationStatus = snapshot.task.status;
        await page.screenshot({
          path:output + '/05-returned-to-same-task.png', fullPage:true, animations:'disabled'
        });

        const profiles = await apiGet('api/runtime-profiles');
        const deterministic = profiles.items?.find(item => item.mode === 'deterministic');
        if (!profiles.workflow_enabled || deterministic?.available !== true)
          throw new Error('isolated deterministic workflow profile is unavailable');
        await page.getByTestId('nav-flow').click();
        await page.getByTestId('business-workspace').waitFor();
        const startButton = page.getByTestId('start-business-workflow');
        await startButton.waitFor();
        await page.waitForFunction(() =>
          document.querySelector('[data-testid="start-business-workflow"]')
          ?.textContent?.trim() === '运行当前任务', null, {timeout:30000});
        const workflowResponseWait = page.waitForResponse(response =>
          response.request().method() === 'POST'
          && new URL(response.url()).pathname === '/api/tasks/' + taskId + '/workflow',
          {timeout:90000});
        await page.screenshot({
          path:output + '/06-authorized-task-ready-to-run.png', fullPage:true, animations:'disabled'
        });
        await startButton.click();
        const workflowResponse = await workflowResponseWait;
        const workflow = await workflowResponse.json();
        const workflowRequest = workflowResponse.request().postDataJSON();
        if (workflowResponse.status() !== 202 || workflow.task_id !== taskId || !workflow.run_id
            || workflow.state !== 'QUEUED' || workflow.runtime_mode !== 'deterministic'
            || workflowRequest.runtime_mode !== 'deterministic'
            || workflowRequest.scenario !== 'normal')
          throw new Error(
            'workflow request did not run deterministically against the authorized task'
          );

        snapshot = await waitCompleted(taskId, workflow.run_id);
        const run = snapshot.workflow_runs[0];
        const expectedAgents = [
          'agent-coordinator', 'agent-knowledge', 'agent-case', 'agent-refund'
        ];
        if (run.events.length < expectedAgents.length
            || expectedAgents.some(agentId =>
              !run.events.some(event => event.agent_id === agentId)))
          throw new Error('completed workflow is missing one or more persisted agent records');
        const refunds = snapshot.business_effects.refunds.filter(
          item => item.status === 'COMMITTED'
        );
        const notices = snapshot.business_effects.notifications;
        const refund = refunds.length === 1 ? refunds[0] : null;
        if (!refund || refund.amount_fen !== 7000)
          throw new Error('expected one committed 70-yuan refund');
        if (notices.length !== 1 || notices[0].status !== 'SENT'
            || notices[0].customer_id !== snapshot.task.customer_id
            || notices[0].related_business_effect_id !== refund.refund_id
            || notices[0].template_id !== 'REFUND_SUCCESS' || typeof notices[0].content !== 'string'
            || !notices[0].content.includes(ticket.ticket_id))
          throw new Error('saved notification is missing or not bound to the committed refund');
        const tools = new Set(snapshot.executions.filter(item =>
          item.state === 'COMMITTED' && item.decision === 'ALLOW')
          .map(item => item.tool_name));
        if (snapshot.executions.length !== 4 || tools.size !== 4
            || [
              'knowledge.read_associated','ticket.read','refund.create','notification.send_template'
            ].some(name => !tools.has(name)))
          throw new Error('expected exactly four committed workflow tool executions');
        if (snapshot.receipts.length !== 4 || snapshot.receipts.some(item =>
            item.receipt_status !== 'SIGNED'
            || item.signature?.valid !== true || item.source_verification?.schema_valid !== true
            || item.source_verification?.stored_hash_valid !== true
            || item.source_verification?.row_binding_valid !== true
            || item.source_verification?.execution_binding_valid !== true))
          throw new Error('one or more persisted signed receipts failed source verification');
        const receiptIds = snapshot.receipts.map(item => item.receipt_id);

        await page.waitForFunction(() => {
          const text = document.querySelector('[data-testid="business-workspace-outcome"]')
            ?.textContent || '';
          return text.includes('退款业务结果\uFF1A退款已提交') && text.includes('客户通知已发送');
        }, null, {timeout:30000});
        await page.getByTestId('nav-overview').click();
        await page.getByTestId('task-overview').waitFor();
        await page.waitForFunction(
          id => new URL(location.href).searchParams.get('task') === id, taskId
        );
        await page.waitForFunction(() => {
          const detail = document.querySelector('[data-testid="business-outcome-detail"]')
            ?.textContent || '';
          const result = document.querySelector('.studio-business-result h2')?.textContent || '';
          const state = document.querySelector('.studio-task-meta')?.textContent || '';
          const records = document.querySelectorAll('[data-testid="notification-record"]');
          return detail.includes('退款已提交 70 元') && detail.includes('客户通知已发送 1 条')
            && result === '业务结果已提交' && state.includes('已完成')
            && !state.includes('运行中') && records.length === 1;
        }, null, {timeout:30000});
        const notificationText = await page.getByTestId('notification-record').innerText();
        if (!notificationText.includes(ticket.ticket_id)
            || !notificationText.includes('通知已发送'))
          throw new Error('overview does not show the actual saved customer notification');
        await page.getByLabel(taskId, {exact:true}).waitFor();
        await page.screenshot({
          path:output + '/07-completed-refund-notification-receipts.png',
          fullPage:true, animations:'disabled'
        });

        const taskPosts = posts.filter(path => path === '/api/tasks');
        const authPosts = posts.filter(path => path === '/api/tasks/' + taskId + '/authorize');
        const workflowPosts = posts.filter(path => path === '/api/tasks/' + taskId + '/workflow');
        if (taskPosts.length !== 1 || authPosts.length !== 1 || workflowPosts.length !== 1
            || posts.some(path => path === '/api/workflows'))
          throw new Error(
        'browser did not perform exactly one create, current-task authorization and same-task start'
          );
        if (errors.length) throw new Error('browser page errors: ' + errors.join('; '));
        return {status:'PASS', task_id:taskId, ticket_id:ticket.ticket_id,
          root_credential_id:authorization.credential_id, run_id:workflow.run_id,
          authorization_status:authorizationStatus, authorized_task_id:authorizedTaskId,
          workflow_task_id:workflow.task_id,
          returned_to_same_task:true, created_through_ui:true, authorized_through_ui:true,
          ran_same_task_through_ui:true, runtime_mode:workflow.runtime_mode,
          workflow_state:run.state, refund_id:refund.refund_id, refund_amount_fen:refund.amount_fen,
          notification_id:notices[0].notification_id, notification_status:notices[0].status,
          notification_refund_id:notices[0].related_business_effect_id,
          notification_refund_binding:true, receipt_ids:receiptIds,
          signed_verified_receipts:snapshot.receipts.length,
          committed_tool_executions:snapshot.executions.length,
          browser_mutations:posts, page_errors:errors};
      } catch (error) {
        await page.screenshot({
          path:output + '/failure-state.png', fullPage:true, animations:'disabled'
        }).catch(() => {});
        throw error;
      } finally {
        launch.launch_token = '';
        if (page.url().includes('launch_token')) await page.goto('about:blank');
      }
    }"""
    for placeholder, value in (
        ("__BRIDGE_URL__", bridge),
        ("__TARGET_URL__", target),
        ("__OUTPUT_DIR__", output.as_posix()),
    ):
        code = code.replace(placeholder, json.dumps(value))
    return code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        token, _ = require_isolated_stack()
    except RuntimeError as exc:
        parser.error(str(exc))
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        parser.error("allocate a new browser evidence directory inside the project")
    if not (ROOT / "frontend/dist/index.html").is_file():
        parser.error("build the frontend before launching the isolated browser")

    output.mkdir(parents=True)
    web = NativeWebServer(ROOT / "frontend/dist", 0, backend_port=18090)
    bridge = BootstrapBridge(token)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (web, bridge)
    ]
    for thread in threads:
        thread.start()

    cli = ROOT / "frontend/node_modules/.bin/playwright-cli.cmd"
    session = "task-handoff-" + output.parent.name[-10:]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    code_path = output / "browser.cli.js"
    log_path = output / "browser.log"
    bridge_url = f"http://127.0.0.1:{bridge.server_port}{bridge.path}"
    code_text = browser_code(
        bridge_url,
        f"http://127.0.0.1:{web.server_port}/",
        output,
    )
    code_path.write_text(code_text, encoding="utf-8")
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
            [str(cli), "-s=" + session, "run-code", "--filename=" + str(code_path)],
            cwd=output,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=360,
            creationflags=flags,
        )
        text = (run.stdout + run.stderr).replace(token, "[REDACTED]")
        text = text.replace(bridge_url, "[REDACTED_EPHEMERAL_BRIDGE_URL]")
        log_path.write_text(text, encoding="utf-8")
        passed = run.returncode == 0 and result_passed(text)
        print(json.dumps({"status": "PASS" if passed else "FAIL", "log": str(log_path)}))
        return 0 if passed else 1
    finally:
        subprocess.run(
            [str(cli), "-s=" + session, "close"],
            cwd=output,
            capture_output=True,
            timeout=30,
            creationflags=flags,
        )
        code_path.write_text(
            code_text.replace(bridge_url, "[REDACTED_EPHEMERAL_BRIDGE_URL]"),
            encoding="utf-8",
        )
        bridge.token = ""
        for server in (bridge, web):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
