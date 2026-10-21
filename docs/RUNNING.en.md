# Running AgentGuard

## Windows package

Download `AgentGuard-Windows-x64.zip` from GitHub Releases and extract it. Keep the complete `AgentGuard` directory. A writable path with English characters is recommended, such as `F:\AgentGuard`.

Double-click `启动AgentGuard.cmd` to start. On first use, follow the initialization prompt; the launcher opens the workspace when setup completes. The release includes a pinned PostgreSQL archive, which is verified and extracted during initialization. Network access is needed to download the archive only if it is missing. Downloaded archives are checked against the SHA-256 value pinned in the project.

Deterministic planning needs no model setup. To use a cloud model, double-click `配置智能体.cmd` and enter your own model service URL, model name, and API key in the workspace. Cloud planning also requires the ticket to be eligible for sharing and explicit confirmation before data is sent.

Double-click `停止本机.cmd` to stop the services. The first launch creates the database, keys, model configuration, and logs under `AgentGuard\\.native`. Preserve any needed data and do not publish this directory.

## Run from source

The source workflow requires Windows x64, Python 3.12, Node.js 20.19 or later or 22.12 or later, npm, and network access. Open PowerShell in the repository root and run:

```powershell
.\scripts\bootstrap.ps1
.\scripts\native-up.ps1 -OpenBrowser
```

Stop the local services with:

```powershell
.\scripts\native-down.ps1
```

Source setup creates a Python virtual environment and stores the database, runtime configuration, keys, and logs in the project directory. For ordinary use, download the complete Windows package from GitHub Releases.
