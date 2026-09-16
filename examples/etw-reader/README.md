# ETW reader

通过库的统一 `eventlog.New → Open → Read → Close` 接口采集 Analytic/Debug
channel。只需提供 channel 名；provider 和 channel ID 从 Windows 元数据解析。
完整 API 及边界见 [ETW 集成说明](../../docs/etw.md)。

## 构建与运行

Windows amd64/arm64、Go 1.23+，无 CGO 要求。在仓库根目录：

```powershell
go build -o etw-reader.exe ./examples/etw-reader

# 只查询后端，不启动会话。
.\etw-reader.exe -channel Microsoft-Windows-WMI-Activity/Trace -describe
.\etw-reader.exe -channel Application -describe

# 管理员 PowerShell；30 秒后结束，也可 Ctrl+C。
.\etw-reader.exe -channel Microsoft-Windows-WMI-Activity/Trace -duration 30s
```

另一个 PowerShell 中触发 WMI 活动：

```powershell
1..20 | ForEach-Object { Get-CimInstance Win32_OperatingSystem | Out-Null }
```

事件以 JSON Lines 写入 stdout，能力声明与最终统计写入 stderr。真实 provider 的
事件产生仍取决于 Windows 版本、服务状态和工作负载。有 DNS Server 环境时也可
尝试 `Microsoft-Windows-DNSServer/Analytical`。

慢消费验证：

```powershell
.\etw-reader.exe -duration 60s -queue 8 -batch 1 -slow 2s > events.jsonl
```

只有事件速率足够高时才会丢弃。`queue_dropped` 是库内丢弃；`events_lost`、
`realtime_buffers_lost` 是 Windows 统计；`statistics_error` 非空表示统计不完整。
`-event-id '1,2,3-10,-5'` 和 `-level verbose` 使用库内精确过滤。

本例采集时要求 ETW channel。普通 channel 的持续采集与 bookmark 示例在
`examples/eventlog-reader`。实时 ETW 没有历史回放、断点恢复或停机补采。

## 测试

无需管理员的测试：

```powershell
go test ./internal/etw ./pkg/eventlog -run 'TestETW|TestWindowsABI|TestDecodeValues|TestTDH|TestSession|TestNativePermission' -count=1 -v
```

管理员 PowerShell 中运行原生实时序号测试：

```powershell
$env:ETW_INTEGRATION = '1'
go test ./internal/etw -run TestNativeRealtimeSequence -count=1 -v
Remove-Item Env:ETW_INTEGRATION
```

此测试用进程内 fixture provider 向两个 channel 各写入 10 条 verbose 事件，
根据载荷中的 Sequence 验证目标 channel 无混入、无重复、无缺失；停止后继续
检查是否存在额外事件。它只加载进程内 TDH manifest，不安装/启停系统 channel。

已收到维护者对原 PoC 的管理员 WMI 采集与实时序号测试通过的反馈。正式化后的
生命周期与解码修改有新增回归测试；更新后的管理员集成测试与 race detector 已
纳入 Windows CI，执行结果以实际运行日志为准。
