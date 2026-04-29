$OutFile = Join-Path $PSScriptRoot 'out.txt'
$ErrFile = Join-Path $PSScriptRoot 'err.txt'
if (Test-Path $OutFile) { Remove-Item $OutFile }
if (Test-Path $ErrFile) { Remove-Item $ErrFile }

$job = Start-Job -ScriptBlock {
    Set-Location $using:PSScriptRoot
    cargo run > out.txt 2> err.txt
}
Start-Sleep -Seconds 4
& curl.exe -x http://127.0.0.1:8080 https://www.google.com | Out-Null
Start-Sleep -Seconds 4
Get-Content -Path $OutFile -TotalCount 200
Stop-Job $job
Remove-Job $job
