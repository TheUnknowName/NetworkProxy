$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
Set-Location $repo_root

$echo_job = $null
$proxy_job = $null

try {
    $echo_job = Start-Job -ScriptBlock {
        param($repo)
        Set-Location $repo
        .\tools\echo_servers.ps1
    } -ArgumentList $repo_root

    $proxy_job = Start-Job -ScriptBlock {
        param($repo)
        Set-Location $repo
        .\build\Debug\network_proxy.exe --config config/proxy_smoke.yaml
    } -ArgumentList $repo_root

    Start-Sleep -Seconds 3

    $tcp_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
    $tcp_stream = $tcp_client.GetStream()
    $tcp_stream.ReadTimeout = 5000
    $tcp_payload = [System.Text.Encoding]::UTF8.GetBytes("hello from tcp")
    $tcp_stream.Write($tcp_payload, 0, $tcp_payload.Length)
    $tcp_buffer = New-Object byte[] 4096
    $tcp_read = $tcp_stream.Read($tcp_buffer, 0, $tcp_buffer.Length)
    $tcp_result = [System.Text.Encoding]::UTF8.GetString($tcp_buffer, 0, $tcp_read)
    $tcp_stream.Dispose()
    $tcp_client.Dispose()

    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = 5000
    $udp_remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 19081)
    $udp_payload = [System.Text.Encoding]::UTF8.GetBytes("hello from udp")
    [void]$udp.Send($udp_payload, $udp_payload.Length, $udp_remote)
    $udp_sender = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $udp_response = $udp.Receive([ref]$udp_sender)
    $udp_result = [System.Text.Encoding]::UTF8.GetString($udp_response)
    $udp.Close()

    Write-Output "TCP_RESULT=$tcp_result"
    Write-Output "UDP_RESULT=$udp_result"

    if ($tcp_result -notmatch "patched_world") {
        throw "tcp smoke check failed"
    }

    if ($udp_result -notmatch "patched_world") {
        throw "udp smoke check failed"
    }

    Write-Output "SMOKE_TEST_PASS"
}
finally {
    if ($proxy_job) {
        Stop-Job -Job $proxy_job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $proxy_job -ErrorAction SilentlyContinue | Out-Null
    }
    if ($echo_job) {
        Stop-Job -Job $echo_job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $echo_job -ErrorAction SilentlyContinue | Out-Null
    }
}
