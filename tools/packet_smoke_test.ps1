$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
Set-Location $repo_root

$report_dir = Join-Path $repo_root "reports"
$report_path = Join-Path $report_dir "packet_smoke_report.md"
$config_path = Join-Path $repo_root "config\proxy_packet_smoke.yaml"
$rules_path = Join-Path $repo_root "config\rules_packet_smoke.dsl"

$ca_dir = Join-Path $repo_root "cert\ca"
$temp_dir = Join-Path $repo_root "cert\temp"
$cache_dir = Join-Path $repo_root "cert\cache"

New-Item -ItemType Directory -Force -Path $report_dir | Out-Null
New-Item -ItemType Directory -Force -Path $ca_dir | Out-Null
New-Item -ItemType Directory -Force -Path $temp_dir | Out-Null
New-Item -ItemType Directory -Force -Path $cache_dir | Out-Null

$openssl_cmd = Get-Command openssl -ErrorAction SilentlyContinue
$openssl_bin_path = if ($null -ne $openssl_cmd) { $openssl_cmd.Source } else { "" }
if ([string]::IsNullOrWhiteSpace($openssl_bin_path)) {
    $fallback_openssl = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    if (Test-Path $fallback_openssl) {
        $openssl_bin_path = $fallback_openssl
    }
}

$openssl_available = -not [string]::IsNullOrWhiteSpace($openssl_bin_path)
$https_enabled = if ($openssl_available) { "true" } else { "false" }
$openssl_bin = if ($openssl_available) { $openssl_bin_path } else { "openssl-not-found" }

$root_ca_crt = Join-Path $ca_dir "root_ca.crt"
$root_ca_key = Join-Path $ca_dir "root_ca.key"
$upstream_crt = Join-Path $temp_dir "packet_upstream.crt"
$upstream_key = Join-Path $temp_dir "packet_upstream.key"
$upstream_pfx = Join-Path $temp_dir "packet_upstream.pfx"

if ($openssl_available) {
    & $openssl_bin_path req -x509 -newkey rsa:2048 -nodes -keyout $root_ca_key -out $root_ca_crt -subj "/CN=NetworkProxy Local CA" -days 2 | Out-Null
    & $openssl_bin_path req -x509 -newkey rsa:2048 -nodes -keyout $upstream_key -out $upstream_crt -subj "/CN=127.0.0.1" -days 2 | Out-Null
    & $openssl_bin_path pkcs12 -export -out $upstream_pfx -inkey $upstream_key -in $upstream_crt -passout pass: | Out-Null
}

@"
rule "tcp-text-outbound" {
  when.protocol = tcp
  when.direction = outbound
  action.text_find = hello
  action.text_replace = patched_hello
}

rule "tcp-text-inbound" {
  when.protocol = tcp
  when.direction = inbound
  action.text_find = world
  action.text_replace = patched_world
}

rule "udp-text-outbound" {
  when.protocol = udp
  when.direction = outbound
  action.text_find = hello
  action.text_replace = patched_hello
}

rule "udp-text-inbound" {
  when.protocol = udp
  when.direction = inbound
  action.text_find = world
  action.text_replace = patched_world
}

rule "tcp-binary-outbound" {
  when.protocol = tcp
  when.direction = outbound
  when.remote_port = 29080
  action.hex_find = 0102
  action.hex_replace = 0A0B
}

rule "tcp-binary-inbound" {
  when.protocol = tcp
  when.direction = inbound
  when.remote_port = 29080
  action.hex_find = 0A0B
  action.hex_replace = C0D0
}

rule "http-header-outbound" {
  when.protocol = http
  when.direction = outbound
  when.method = post
  when.path_contains = /api
  action.header_set.X-Smoke = dsl-smoke
}

rule "http-body-inbound" {
  when.protocol = http
  when.direction = inbound
  action.body_find = world
  action.body_replace = patched_world
}
"@ | Set-Content -Encoding ascii $rules_path

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
  log_level: info
  dry_run: false
  max_runtime_seconds: 40

protocol:
  enabled: true
  http_enabled: true

rules:
  enabled: true
  file: config/rules_packet_smoke.dsl

https_mitm:
  enabled: $https_enabled
  ca_cert_path: cert/ca/root_ca.crt
  ca_key_path: cert/ca/root_ca.key
  ca_subject_name: NetworkProxy Local CA
  install_to_current_user: false
  cert_cache_dir: cert/cache
  openssl_bin_path: $openssl_bin
  plaintext_test_mode: false

patch:
  enable_text_patch: false
  enable_hex_patch: false
  add_proxy_header: false
  append_debug_suffix: false
  outbound_find: ""
  outbound_replace: ""
  inbound_find: ""
  inbound_replace: ""
  outbound_find_hex: ""
  outbound_replace_hex: ""
  inbound_find_hex: ""
  inbound_replace_hex: ""
"@ | Set-Content -Encoding ascii $config_path

$tcp_udp_job = $null
$tls_job = $null
$proxy_job = $null
$results = [ordered]@{}

function Set-Result([string]$name, [bool]$ok, [string]$detail) {
    if ($ok) {
        $results[$name] = "PASS"
    } else {
        $results[$name] = "FAIL: $detail"
    }
}

try {
    $tcp_udp_job = Start-Job -ScriptBlock {
        $tcp_listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 29080)
        $tcp_listener.Start()

        $udp = [System.Net.Sockets.UdpClient]::new(29081)
        $udp_remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

        $stop_at = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $stop_at) {
            if ($tcp_listener.Pending()) {
                $client = $tcp_listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $buffer = New-Object byte[] 8192
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    if ($read -gt 0) {
                        $data = $buffer[0..($read - 1)]
                        $ascii = [System.Text.Encoding]::ASCII.GetString($data)

                        if ($ascii.StartsWith("POST ") -or $ascii.StartsWith("GET ")) {
                            $header_ok = $ascii.Contains("X-Smoke: dsl-smoke")
                            $body = if ($header_ok) { "world header-ok" } else { "world header-missing" }
                            $response = "HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                            $resp_bytes = [System.Text.Encoding]::ASCII.GetBytes($response)
                            $stream.Write($resp_bytes, 0, $resp_bytes.Length)
                            $stream.Flush()
                        } else {
                            $text = [System.Text.Encoding]::UTF8.GetString($data)
                            $resp_text = $text.Replace("patched_hello", "world")
                            $resp_bytes = [System.Text.Encoding]::UTF8.GetBytes($resp_text)
                            $stream.Write($resp_bytes, 0, $resp_bytes.Length)
                            $stream.Flush()
                        }
                    }
                }
                finally {
                    $client.Dispose()
                }
            }

            if ($udp.Available -gt 0) {
                $bytes = $udp.Receive([ref]$udp_remote)
                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                $resp_text = $text.Replace("patched_hello", "world")
                $resp_bytes = [System.Text.Encoding]::UTF8.GetBytes($resp_text)
                [void]$udp.Send($resp_bytes, $resp_bytes.Length, $udp_remote)
            }

            Start-Sleep -Milliseconds 30
        }

        $udp.Close()
        $tcp_listener.Stop()
    }

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

                    $body = "world tls"
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
    } -ArgumentList $repo_root, "config/proxy_packet_smoke.yaml"

    Start-Sleep -Seconds 3

    # TCP text packet
    $tcp_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
    $tcp_stream = $tcp_client.GetStream()
    $tcp_stream.ReadTimeout = 5000
    $tcp_payload = [System.Text.Encoding]::UTF8.GetBytes("hello from tcp")
    $tcp_stream.Write($tcp_payload, 0, $tcp_payload.Length)
    $tcp_buf = New-Object byte[] 4096
    $tcp_read = $tcp_stream.Read($tcp_buf, 0, $tcp_buf.Length)
    $tcp_text = [System.Text.Encoding]::UTF8.GetString($tcp_buf, 0, $tcp_read)
    Set-Result "TCP_TEXT" ($tcp_text -match "patched_world") $tcp_text
    $tcp_stream.Dispose()
    $tcp_client.Dispose()

    # TCP unknown binary packet
    $bin_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
    $bin_stream = $bin_client.GetStream()
    $bin_stream.ReadTimeout = 5000
    [byte[]]$bin_payload = 0x01,0x02,0x03
    $bin_stream.Write($bin_payload, 0, $bin_payload.Length)
    $bin_buf = New-Object byte[] 64
    $bin_read = $bin_stream.Read($bin_buf, 0, $bin_buf.Length)
    $bin_resp = $bin_buf[0..($bin_read - 1)]
    $bin_ok = ($bin_resp.Length -ge 3 -and $bin_resp[0] -eq 0xC0 -and $bin_resp[1] -eq 0xD0 -and $bin_resp[2] -eq 0x03)
    Set-Result "TCP_BINARY_UNKNOWN" $bin_ok ([System.BitConverter]::ToString($bin_resp))
    $bin_stream.Dispose()
    $bin_client.Dispose()

    # UDP text packet
    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = 5000
    $udp_remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 19081)
    $udp_payload = [System.Text.Encoding]::UTF8.GetBytes("hello from udp")
    [void]$udp.Send($udp_payload, $udp_payload.Length, $udp_remote)
    $udp_sender = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $udp_resp = $udp.Receive([ref]$udp_sender)
    $udp_text = [System.Text.Encoding]::UTF8.GetString($udp_resp)
    Set-Result "UDP_TEXT" ($udp_text -match "patched_world") $udp_text
    $udp.Close()

    # HTTP packet
    $http_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
    $http_stream = $http_client.GetStream()
    $http_stream.ReadTimeout = 5000
    $http_body = "hello"
    $http_request = "POST /api/orders HTTP/1.1`r`nHost: test.local`r`nContent-Length: $($http_body.Length)`r`nConnection: close`r`n`r`n$http_body"
    $http_bytes = [System.Text.Encoding]::ASCII.GetBytes($http_request)
    $http_stream.Write($http_bytes, 0, $http_bytes.Length)
    $http_buf = New-Object byte[] 8192
    $http_read = $http_stream.Read($http_buf, 0, $http_buf.Length)
    $http_text = [System.Text.Encoding]::ASCII.GetString($http_buf, 0, $http_read)
    $http_ok = $http_text.Contains("patched_world") -and $http_text.Contains("header-ok")
    Set-Result "HTTP_PACKET" $http_ok $http_text
    $http_stream.Dispose()
    $http_client.Dispose()

    if ($openssl_available) {
        # CONNECT + HTTPS MITM packet
        $connect_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
        $connect_stream = $connect_client.GetStream()
        $connect_stream.ReadTimeout = 5000
        $connect_req = "CONNECT 127.0.0.1:29443 HTTP/1.1`r`nHost: 127.0.0.1:29443`r`n`r`n"
        $connect_bytes = [System.Text.Encoding]::ASCII.GetBytes($connect_req)
        $connect_stream.Write($connect_bytes, 0, $connect_bytes.Length)
        $head_buf = New-Object byte[] 4096
        $head_read = $connect_stream.Read($head_buf, 0, $head_buf.Length)
        $connect_head = [System.Text.Encoding]::ASCII.GetString($head_buf, 0, $head_read)
        $connect_ok = $connect_head -match "200 Connection Established"

        $ssl = [System.Net.Security.SslStream]::new($connect_stream, $false, { $true })
        $ssl.AuthenticateAsClient("127.0.0.1")
        $https_req = "GET / HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n`r`n"
        $https_bytes = [System.Text.Encoding]::ASCII.GetBytes($https_req)
        $ssl.Write($https_bytes, 0, $https_bytes.Length)
        $ssl.Flush()

        $builder = New-Object System.Text.StringBuilder
        $read_buf = New-Object byte[] 4096
        while ($true) {
            try {
                $count = $ssl.Read($read_buf, 0, $read_buf.Length)
            }
            catch {
                break
            }
            if ($count -le 0) {
                break
            }
            [void]$builder.Append([System.Text.Encoding]::ASCII.GetString($read_buf, 0, $count))
        }

        $https_text = $builder.ToString()
        $ssl.Dispose()
        $connect_stream.Dispose()
        $connect_client.Dispose()

        Set-Result "CONNECT_HTTPS_PACKET" ($connect_ok -and $https_text.Contains("patched_world")) $https_text
    }
    else {
        # CONNECT plain tunnel packet fallback
        $connect_client = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 19080)
        $connect_stream = $connect_client.GetStream()
        $connect_stream.ReadTimeout = 5000
        $connect_req = "CONNECT 127.0.0.1:29080 HTTP/1.1`r`nHost: 127.0.0.1:29080`r`n`r`n"
        $connect_bytes = [System.Text.Encoding]::ASCII.GetBytes($connect_req)
        $connect_stream.Write($connect_bytes, 0, $connect_bytes.Length)
        $head_buf = New-Object byte[] 4096
        $head_read = $connect_stream.Read($head_buf, 0, $head_buf.Length)
        $connect_head = [System.Text.Encoding]::ASCII.GetString($head_buf, 0, $head_read)

        $payload = [System.Text.Encoding]::UTF8.GetBytes("hello from connect")
        $connect_stream.Write($payload, 0, $payload.Length)
        $buf = New-Object byte[] 4096
        $read = $connect_stream.Read($buf, 0, $buf.Length)
        $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
        $connect_stream.Dispose()
        $connect_client.Dispose()

        Set-Result "CONNECT_TUNNEL_PACKET" (($connect_head -match "200 Connection Established") -and ($text -match "patched_world")) $text
    }
}
finally {
    if ($proxy_job) {
        Stop-Job -Job $proxy_job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $proxy_job -ErrorAction SilentlyContinue | Out-Null
    }
    if ($tcp_udp_job) {
        Stop-Job -Job $tcp_udp_job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $tcp_udp_job -ErrorAction SilentlyContinue | Out-Null
    }
    if ($tls_job) {
        Stop-Job -Job $tls_job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $tls_job -ErrorAction SilentlyContinue | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$lines = @()
$lines += "# Packet Protocol Smoke Report"
$lines += ""
$lines += "- generated_at: $timestamp"
$lines += "- scope: tcp-text, tcp-binary-unknown, udp-text, http, connect, https-mitm(if openssl)"
$lines += ""
$lines += "## Results"

$has_fail = $false
foreach ($key in $results.Keys) {
    $value = $results[$key]
    $lines += "- ${key}: $value"
    if ($value.StartsWith("FAIL")) {
        $has_fail = $true
    }
}

$lines | Set-Content -Encoding ascii $report_path
Write-Output "packet smoke report: $report_path"
foreach ($key in $results.Keys) {
    Write-Output "${key} => $($results[$key])"
}

if ($has_fail) {
    throw "packet protocol smoke tests failed"
}
