$tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 29080)
$tcpListener.Start()

$udpClient = [System.Net.Sockets.UdpClient]::new(29081)
$udpRemote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

$stopAt = (Get-Date).AddSeconds(60)

while ((Get-Date) -lt $stopAt) {
    if ($tcpListener.Pending()) {
        $client = $tcpListener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $buffer = New-Object byte[] 4096
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -gt 0) {
                $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
                $responseText = $text.Replace('patched_hello', 'world')
                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseText)
                $stream.Write($responseBytes, 0, $responseBytes.Length)
                $stream.Flush()
            }
        }
        finally {
            $client.Dispose()
        }
    }

    if ($udpClient.Available -gt 0) {
        $bytes = $udpClient.Receive([ref]$udpRemote)
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $responseText = $text.Replace('patched_hello', 'world')
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseText)
        [void]$udpClient.Send($responseBytes, $responseBytes.Length, $udpRemote)
    }

    Start-Sleep -Milliseconds 50
}

$udpClient.Close()
$tcpListener.Stop()
