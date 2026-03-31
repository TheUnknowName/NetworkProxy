$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
Set-Location $repo_root

$report_dir = Join-Path $repo_root "reports"
$report_path = Join-Path $report_dir "e2e_validation_report.md"
$config_path = Join-Path $repo_root "config\proxy_e2e.yaml"
$ca_dir = Join-Path $repo_root "cert\ca"
$cache_dir = Join-Path $repo_root "cert\cache"
$temp_dir = Join-Path $repo_root "cert\temp"

New-Item -ItemType Directory -Force -Path $report_dir | Out-Null
New-Item -ItemType Directory -Force -Path $ca_dir | Out-Null
New-Item -ItemType Directory -Force -Path $cache_dir | Out-Null
New-Item -ItemType Directory -Force -Path $temp_dir | Out-Null

$openssl_cmd = Get-Command openssl -ErrorAction SilentlyContinue
$openssl_bin_path = if ($null -ne $openssl_cmd) { $openssl_cmd.Source } else { "" }
if ([string]::IsNullOrWhiteSpace($openssl_bin_path)) {
    $fallback_openssl = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    if (Test-Path $fallback_openssl) {
        $openssl_bin_path = $fallback_openssl
    }
}

$openssl_available = -not [string]::IsNullOrWhiteSpace($openssl_bin_path)
$https_mitm_enabled_value = if ($openssl_available) { "true" } else { "false" }
$openssl_bin_value = if ($openssl_available) { $openssl_bin_path } else { "openssl-not-found" }

$root_ca_crt = Join-Path $ca_dir "root_ca.crt"
$root_ca_key = Join-Path $ca_dir "root_ca.key"
$upstream_crt = Join-Path $temp_dir "upstream.crt"
$upstream_key = Join-Path $temp_dir "upstream.key"
$upstream_pfx = Join-Path $temp_dir "upstream.pfx"

if ($openssl_available) {
    & $openssl_bin_path req -x509 -newkey rsa:2048 -nodes -keyout $root_ca_key -out $root_ca_crt -subj "/CN=NetworkProxy Local CA" -days 2 | Out-Null
    & $openssl_bin_path req -x509 -newkey rsa:2048 -nodes -keyout $upstream_key -out $upstream_crt -subj "/CN=127.0.0.1" -days 2 | Out-Null
    & $openssl_bin_path pkcs12 -export -out $upstream_pfx -inkey $upstream_key -in $upstream_crt -passout pass: | Out-Null
}

@"
capture:
  enabled: false
  use_windivert: false
  windivert_filter: outbound and (tcp or udp)

tcp:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 19080
  upstream_host: 127.0.0.1
  upstream_port: 29080

udp:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 19081
  upstream_host: 127.0.0.1
  upstream_port: 29081

runtime:
  log_level: debug
  dry_run: false
  max_runtime_seconds: 45

protocol:
  enabled: true
  http_enabled: true

https_mitm:
    enabled: $https_mitm_enabled_value
  ca_cert_path: cert/ca/root_ca.crt
  ca_key_path: cert/ca/root_ca.key
  ca_subject_name: NetworkProxy Local CA
  install_to_current_user: false
  cert_cache_dir: cert/cache
    openssl_bin_path: $openssl_bin_value
  plaintext_test_mode: false

patch:
  enable_text_patch: true
  enable_hex_patch: false
  add_proxy_header: true
  append_debug_suffix: false
  outbound_find: hello
  outbound_replace: patched_hello
  inbound_find: world
  inbound_replace: patched_world
  outbound_find_hex: ""
  outbound_replace_hex: ""
  inbound_find_hex: ""
  inbound_replace_hex: ""
"@ | Set-Content -Encoding ascii $config_path

$results = [ordered]@{}
$proxy_job = $null
$echo_job = $null
$tls_job = $null

try {
    $echo_job = Start-Job -ScriptBlock {
        param($repo)
        Set-Location $repo
        .\tools\echo_servers.ps1
    } -ArgumentList $repo_root

    if ($openssl_available) {
        $tls_job = Start-Job -ScriptBlock {
            param($pfx_path)
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 29443)
            $listener.Start()
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx_path, "", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $ssl = [System.Net.Security.SslStream]::new($stream, $false)
                    $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)

                    $buffer = New-Object byte[] 8192
                    [void]$ssl.Read($buffer, 0, $buffer.Length)

                    $body = "world from tls upstream"
                    $response = "HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                    $bytes = [System.Text.Encoding]::ASCII.GetBytes($response)
                    $ssl.Write($bytes, 0, $bytes.Length)
                    $ssl.Flush()
                    $ssl.Dispose()
                }
                finally {
                    $client.Dispose()
                }
            }
            finally {
                $listener.Stop()
            }
        } -ArgumentList $upstream_pfx
    }

    $proxy_job = Start-Job -ScriptBlock {
        param($repo, $cfg)
        Set-Location $repo
        .\build\Debug\network_proxy.exe --config $cfg
    } -ArgumentList $repo_root, "config/proxy_e2e.yaml"

    Start-Sleep -Seconds 3

    $tcp_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
    $tcp_stream = $tcp_client.GetStream()
    $tcp_stream.ReadTimeout = 4000
    $tcp_bytes = [System.Text.Encoding]::UTF8.GetBytes("hello from tcp")
    $tcp_stream.Write($tcp_bytes, 0, $tcp_bytes.Length)
    $tcp_buffer = New-Object byte[] 4096
    $tcp_read = $tcp_stream.Read($tcp_buffer, 0, $tcp_buffer.Length)
    $tcp_result = [System.Text.Encoding]::UTF8.GetString($tcp_buffer, 0, $tcp_read)
    $tcp_stream.Dispose()
    $tcp_client.Dispose()
    $results["TCP"] = if ($tcp_result -match "patched_world") { "PASS" } else { "FAIL: $tcp_result" }

    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = 4000
    $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 19081)
    $udp_bytes = [System.Text.Encoding]::UTF8.GetBytes("hello from udp")
    [void]$udp.Send($udp_bytes, $udp_bytes.Length, $remote)
    $udp_sender_endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $udp_response = $udp.Receive([ref]$udp_sender_endpoint)
    $udp_result = [System.Text.Encoding]::UTF8.GetString($udp_response)
    $udp.Close()
    $results["UDP"] = if ($udp_result -match "patched_world") { "PASS" } else { "FAIL: $udp_result" }

    if ($openssl_available) {
        $connect_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
        $connect_stream = $connect_client.GetStream()
        $connect_stream.ReadTimeout = 5000
        $connect_request = "CONNECT 127.0.0.1:29443 HTTP/1.1`r`nHost: 127.0.0.1:29443`r`n`r`n"
        $connect_bytes = [System.Text.Encoding]::ASCII.GetBytes($connect_request)
        $connect_stream.Write($connect_bytes, 0, $connect_bytes.Length)
        $head_buffer = New-Object byte[] 4096
        $head_read = $connect_stream.Read($head_buffer, 0, $head_buffer.Length)
        $connect_head = [System.Text.Encoding]::ASCII.GetString($head_buffer, 0, $head_read)
        $connect_ok = $connect_head -match "200 Connection Established"

        $ssl = [System.Net.Security.SslStream]::new($connect_stream, $false, { $true })
        $ssl.AuthenticateAsClient("127.0.0.1")
        $https_request = "GET / HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n`r`nhello"
        $https_bytes = [System.Text.Encoding]::ASCII.GetBytes($https_request)
        $ssl.Write($https_bytes, 0, $https_bytes.Length)
        $ssl.Flush()

        $response_builder = New-Object System.Text.StringBuilder
        $read_buffer = New-Object byte[] 4096
        while ($true) {
            try {
                $count = $ssl.Read($read_buffer, 0, $read_buffer.Length)
            }
            catch {
                break
            }
            if ($count -le 0) {
                break
            }
            [void]$response_builder.Append([System.Text.Encoding]::ASCII.GetString($read_buffer, 0, $count))
        }

        $https_result = $response_builder.ToString()
        $ssl.Dispose()
        $connect_stream.Dispose()
        $connect_client.Dispose()

        $results["CONNECT"] = if ($connect_ok) { "PASS" } else { "FAIL: no 200" }
        $results["TLS_MITM_PATCH"] = if ($https_result -match "patched_world") { "PASS" } else { "FAIL: response=$https_result" }

        $leaf_cert_path = Join-Path $cache_dir "127.0.0.1.crt"
        $results["LEAF_CERT"] = if (Test-Path $leaf_cert_path) { "PASS" } else { "FAIL: missing $leaf_cert_path" }
    }
    else {
        $results["CONNECT"] = "SKIP: openssl not found"
        $results["TLS_MITM_PATCH"] = "SKIP: openssl not found"
        $results["LEAF_CERT"] = "SKIP: openssl not found"
    }
}
finally {
    if ($proxy_job) {
        Stop-Job -Job $proxy_job -ErrorAction SilentlyContinue | Out-Null
    }
    if ($echo_job) {
        Stop-Job -Job $echo_job -ErrorAction SilentlyContinue | Out-Null
    }
    if ($tls_job) {
        Stop-Job -Job $tls_job -ErrorAction SilentlyContinue | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$lines = @()
$lines += "# NetworkProxy E2E Validation Report"
$lines += ""
$lines += "- generated_at: $timestamp"
$lines += "- config: config/proxy_e2e.yaml"
$lines += "- scope: TCP + UDP + CONNECT + certificate generation + TLS MITM plaintext patch"
$lines += ""
$lines += "## Results"
foreach ($key in $results.Keys) {
    $lines += "- ${key}: $($results[$key])"
}

$lines | Set-Content -Encoding ascii $report_path

Write-Output "E2E report generated: $report_path"
foreach ($key in $results.Keys) {
    Write-Output "$key => $($results[$key])"
}
