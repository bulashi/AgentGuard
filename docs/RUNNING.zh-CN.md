# AgentGuard运行说明

## Windows运行包

从GitHub Releases下载`AgentGuard-Windows-x64.zip`并解压，完整保留`AgentGuard`目录。建议将目录放在可读写的英文路径中，例如`F:\AgentGuard`。

双击`启动AgentGuard.cmd`启动系统。首次使用时，按提示完成初始化，启动器随后打开工作台。初始化需要网络连接，用于下载PostgreSQL组件；下载文件会按项目内锁定的SHA-256值校验。

使用确定性规则规划时无需配置模型。若要使用云端模型，双击`配置智能体.cmd`，在工作台填写自己的模型服务地址、模型名称和API Key。只有在工单允许云端共享并确认发送资料后，云端规划才可运行。

退出时双击`停止本机.cmd`。首次启动生成的数据库、密钥、模型配置和日志均保存在`AgentGuard\\.native`目录，请保留需要的数据，并避免公开该目录。

## 从源码启动

源码启动需要Windows x64、Python 3.12、Node.js 20.19以上或22.12以上、npm和网络连接。在PowerShell进入仓库根目录，依次运行：

```powershell
.\scripts\bootstrap.ps1
.\scripts\native-up.ps1 -OpenBrowser
```

停止本机服务：

```powershell
.\scripts\native-down.ps1
```

源码启动会创建Python虚拟环境并在项目目录生成数据库、运行配置、密钥和日志。只需运行系统时，使用Releases中的完整Windows运行包。
