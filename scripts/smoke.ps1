$ErrorActionPreference = 'Continue'
$listening = $false
$proc = Start-Process -FilePath dotnet -ArgumentList 'run --project "c:\Users\brand\Desktop\BCMTrac Auth Service\YARP\YARP.csproj" -c Release --no-build' -PassThru -WindowStyle Hidden
try {
  # Wait up to 60 seconds for port 7001 (HTTP) to accept connections
  for ($i=0; $i -lt 120; $i++) {
    try {
      $tcp = New-Object System.Net.Sockets.TcpClient
      $iar = $tcp.BeginConnect('localhost', 7001, $null, $null)
      if ($iar.AsyncWaitHandle.WaitOne(250)) {
        $tcp.EndConnect($iar)
        $tcp.Close()
        $listening = $true
        break
      }
      $tcp.Close()
    } catch {
      # ignore and retry
    }
  }

  if (-not $listening) {
    Write-Error 'YARP failed to start listening on http://localhost:7001'
    exit 1
  }

  # Probe /health over HTTP (bypasses TLS and any cert issues)
  $resp = Invoke-RestMethod -Uri http://localhost:7001/health
  if ($resp -and $resp.ok -eq $true) { Write-Output 'HEALTH OK'; exit 0 }
  else { Write-Error 'HEALTH check returned unexpected response.'; exit 1 }
}
finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}