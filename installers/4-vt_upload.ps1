# vt_upload.ps1 — VirusTotal v3 uploader + report
# PowerShell 5.1+, supporte fichiers multiples et wildcards

param(
  [Parameter(Mandatory = $true)] [string[]]$FilePath,
  [string]$ApiKey = $env:VT_API_KEY,
  [int]$WaitSeconds = 120,          # temps max d'attente de l'analyse après upload
  [int]$PollIntervalSeconds = 3     # intervalle de polling de l'analyse
)

if (-not $ApiKey) { Write-Host "Missing API key. Use -ApiKey or set VT_API_KEY." -ForegroundColor Red; exit 1 }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-VT {
  param([string]$Uri, [string]$Method = "GET", $Body = $null, [int]$TimeoutSec = 60)
  $headers = @{ "x-apikey" = $ApiKey }
  try {
    if ($Method -eq "GET") { return Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -TimeoutSec $TimeoutSec -ErrorAction Stop }
    elseif ($Method -eq "POST") {
      return Invoke-RestMethod -Uri $Uri -Headers $headers -Method POST -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
  } catch {
    throw $_
  }
}

function Get-VTFileInfo {  # /files/{sha256}
  param([string]$Sha256)
  try { return Invoke-VT -Uri "https://www.virustotal.com/api/v3/files/$Sha256" -Method GET -TimeoutSec 30 }
  catch { return $null }
}

function Get-VTAnalysis {  # /analyses/{id}
  param([string]$AnalysisId)
  try { return Invoke-VT -Uri "https://www.virustotal.com/api/v3/analyses/$AnalysisId" -Method GET -TimeoutSec 30 }
  catch { return $null }
}

function Wait-VTAnalysis {
  param([string]$AnalysisId, [int]$TimeoutSec = 120, [int]$Poll = 3)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    $a = Get-VTAnalysis -AnalysisId $AnalysisId
    if ($a -and $a.data.attributes.status -eq 'completed') { return $a }
    Start-Sleep -Seconds $Poll
  }
  return $null
}

function Show-VTFileSummary {
  param($FileInfo, [string]$Sha256)
  if (-not $FileInfo) { Write-Host "⚠️  Aucun détail d’analyse disponible." -ForegroundColor Yellow; return }
  $attr = $FileInfo.data.attributes
  $stats = $attr.last_analysis_stats
  $msg = "Harmless=$($stats.harmless)  Malicious=$($stats.malicious)  Suspicious=$($stats.suspicious)  Undetected=$($stats.undetected)  Timeout=$($stats.timeout)"
  $reputation = $attr.reputation
  $size = $attr.size
  $type = $attr.type_description
  Write-Host ("📊 " + $msg)
  if ($reputation -ne $null) { Write-Host ("🧭 Reputation: {0}" -f $reputation) }
  if ($size -ne $null -and $type) { Write-Host ("📦 {0} bytes — {1}" -f $size, $type) }
  Write-Host ("🔗 GUI: https://www.virustotal.com/gui/file/{0}" -f $Sha256)
}

function Send-VTFile {
  param([string]$Path, [int]$TimeoutSec = 180)
  $handler = New-Object System.Net.Http.HttpClientHandler
  $client  = [System.Net.Http.HttpClient]::new($handler)
  $client.DefaultRequestHeaders.Add("x-apikey", $ApiKey)
  $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

  $content = New-Object System.Net.Http.MultipartFormDataContent
  $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
  $fileContent = New-Object System.Net.Http.StreamContent($fs)
  $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
  $null = $content.Add($fileContent, "file", [IO.Path]::GetFileName($Path))

  $resp = $client.PostAsync("https://www.virustotal.com/api/v3/files", $content).Result
  $fs.Dispose(); $content.Dispose(); $client.Dispose()
  if (-not $resp.IsSuccessStatusCode) { throw "Upload failed: $($resp.StatusCode) $($resp.ReasonPhrase)" }
  return ($resp.Content.ReadAsStringAsync().Result | ConvertFrom-Json)
}

# --- Main ---
foreach ($p in $FilePath) {
  $items = @()

  if (Test-Path -LiteralPath $p) {
    $it = Get-Item -LiteralPath $p
    if ($it.PSIsContainer) {
      $items = Get-ChildItem -LiteralPath $p -Filter *.exe -File -ErrorAction SilentlyContinue
    } else {
      $items = ,$it
    }
  } else {
    $items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue
  }

  if (-not $items -or $items.Count -eq 0) {
    Write-Host "⚠️  Aucun fichier correspondant: $p" -ForegroundColor Yellow
    continue
  }

  foreach ($file in $items) {
    $full = $file.FullName
    try { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLower() }
    catch { Write-Host "❌ Impossible de calculer le SHA256: $full — $_" -ForegroundColor Red; continue }

    Write-Host "`n📄 $($file.Name) — SHA256: $sha"

    # 1) Le fichier existe déjà sur VT ?
    $info = Get-VTFileInfo -Sha256 $sha
    if ($info) {
      Write-Host "✅ Déjà présent sur VirusTotal."
      Show-VTFileSummary -FileInfo $info -Sha256 $sha
      continue
    }

    # 2) Sinon on upload puis on attend l’analyse (optionnel)
    Write-Host "🚀 Uploading..."
    try {
      $upload = Send-VTFile -Path $full -TimeoutSec 300
      $analysisId = $upload.data.id
      Write-Host "🆔 Analysis ID: $analysisId"

      if ($WaitSeconds -gt 0) {
        Write-Host "⏳ Attente de la fin d’analyse (max ${WaitSeconds}s)..."
        $analysis = Wait-VTAnalysis -AnalysisId $analysisId -TimeoutSec $WaitSeconds -Poll $PollIntervalSeconds
        if ($analysis -and $analysis.meta.'file_info'.sha256) {
          $finalSha = $analysis.meta.'file_info'.sha256
          $final = Get-VTFileInfo -Sha256 $finalSha
          if ($final) {
            Write-Host "✅ Analyse terminée."
            Show-VTFileSummary -FileInfo $final -Sha256 $finalSha
          } else {
            Write-Host "⚠️  Analyse complétée, mais impossible de récupérer le détail fichier." -ForegroundColor Yellow
          }
        } else {
          Write-Host "⚠️  Analyse non terminée dans le temps imparti." -ForegroundColor Yellow
          Write-Host ("🔗 Analysis: https://www.virustotal.com/gui/file-analysis/{0}" -f $analysisId)
        }
      } else {
        Write-Host ("🔗 Analysis: https://www.virustotal.com/gui/file-analysis/{0}" -f $analysisId)
      }
    } catch {
      Write-Host "❌ $_" -ForegroundColor Red
    }
  }
}
