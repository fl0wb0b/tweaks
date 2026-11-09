# Rauchtest fuer Get-WindowsUpdateStatus.ps1 auf einem Windows-Testrechner (GitHub-Runner, als Administrator).
# Veraendert C:\Zabbix und einen Testschluessel unter HKCU - nicht auf einem echten Server ausfuehren.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\smoke.ps1
$Skript = Join-Path $PSScriptRoot '..\Get-WindowsUpdateStatus.ps1'
$Dir    = 'C:\Zabbix'
$Ziel   = 'C:\ZabbixZiel'
$Key    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZZ-Rauchtest'
$script:Fail = 0

function Check($Name, $Ok) {
    if ($Ok) { Write-Output "OK     $Name" } else { Write-Output "FEHLER $Name"; $script:Fail++ }
}
function Lauf { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Skript *> $null }
function Leeren {
    if (Test-Path $Dir) { cmd /c rmdir /s /q $Dir }      # rmdir entfernt eine Junction, ohne ihr Ziel zu leeren
    if (Test-Path $Ziel) { Remove-Item $Ziel -Recurse -Force }
}
function Inventar {
    try {
        $Ms = New-Object IO.MemoryStream(, [Convert]::FromBase64String((Get-Content "$Dir\software_inventory.b64" -Raw)))
        $Gz = New-Object IO.Compression.GzipStream($Ms, [IO.Compression.CompressionMode]::Decompress)
        return (New-Object IO.StreamReader($Gz, [Text.Encoding]::UTF8)).ReadToEnd() | ConvertFrom-Json
    } catch { return $null }
}

# 1. C:\Zabbix ist eine Verzeichnisverknuepfung: das Skript (als SYSTEM) darf nicht hindurch schreiben
Leeren
New-Item -ItemType Directory $Ziel | Out-Null
cmd /c mklink /J $Dir $Ziel | Out-Null
Lauf
Check 'Junction: nichts ins Ziel geschrieben' (@(Get-ChildItem $Ziel -Force).Count -eq 0)

# 2. Vorhandener Ordner (erbt die Rechte von C:\) mit State-Datei in der Zukunft
Leeren
New-Item -ItemType Directory $Dir | Out-Null
Set-Content "$Dir\software_inventory.state" '2099-01-01 00:00:00'
Lauf
$Acl = Get-Acl $Dir
$Schreiben = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 0x10000000 -bor 0x40000000   # Daten, Anhaengen, Attribute, Loeschen, Rechte, Besitz, GENERIC_ALL/WRITE
$Fremd = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
    $_.AccessControlType -eq 'Allow' -and ([int]$_.FileSystemRights -band $Schreiben) -and $_.IdentityReference.Value -notin 'S-1-5-18', 'S-1-5-32-544' })
Check "nur SYSTEM und Administratoren duerfen schreiben ($(($Fremd | ForEach-Object { $_.IdentityReference.Value }) -join ', '))" ($Fremd.Count -eq 0)
Check 'Rechte nicht von C:\ geerbt' $Acl.AreAccessRulesProtected
Check 'Inventar laeuft trotz State-Datei in der Zukunft' (-not (Get-Content "$Dir\software_inventory.state" -Raw).StartsWith('2099'))
$St = Get-Content "$Dir\update_status.txt" -Raw | ConvertFrom-Json
Check "update_status.txt ist JSON mit Status ($($St.status))" ([bool]$St.status)
if ($St.status -eq 'error') {
    Check 'Report sagt bei Fehler nicht "Keine ausstehenden Updates"' (-not (Select-String -Path "$Dir\report.html" -Pattern 'Keine ausstehenden Updates' -Quiet))
}

# 3. Benutzer-Uninstall-Eintrag mit DisplayName als DWORD (jeder Benutzer kann das im eigenen HKCU anlegen)
Leeren
New-Item $Key -Force | Out-Null
New-ItemProperty $Key -Name DisplayName -Value 1 -PropertyType DWord -Force | Out-Null
Lauf
Remove-Item $Key -Force
$Inv = Inventar
Check 'Inventar trotz DWORD-DisplayName dekodierbar und gefuellt' ($Inv -and $Inv.count -gt 1)

# 4. Rechte einer Ausgabedatei nicht setzbar: jeder darf schreiben, niemand die Rechte aendern (OWNER RIGHTS nur lesen nimmt
#    auch dem Besitzer WRITE_DAC). Das Skript muss abbrechen, bevor es etwas schreibt. Eine Dateisperre reicht dafuer nicht:
#    sie sperrt nur Inhaltszugriffe, nicht das Aendern der Rechte.
Leeren
New-Item -ItemType Directory $Dir | Out-Null
Set-Content "$Dir\update_status.txt" 'ALT'
Set-Content "$Dir\report.html" 'ALT'
icacls "$Dir\report.html" /inheritance:r /grant:r '*S-1-1-0:(R,W)' '*S-1-3-4:(R)' /Q | Out-Null
$Vorbedingung = $LASTEXITCODE -eq 0
icacls "$Dir\report.html" /reset /Q 2>$null | Out-Null
Check 'Vorbedingung: icacls kann die Rechte der Datei nicht mehr aendern' ($Vorbedingung -and $LASTEXITCODE -ne 0)
Lauf
Check 'icacls-Fehler: update_status.txt unveraendert' ((Get-Content "$Dir\update_status.txt" -Raw).Trim() -eq 'ALT')

# 5. Annahme hinter dem Absichern: icacls mit /L aendert bei einer Junction die Junction selbst, nie ihr Ziel
Leeren
New-Item -ItemType Directory $Ziel | Out-Null
icacls $Ziel /grant '*S-1-5-32-546:(OI)(CI)R' /Q | Out-Null                         # Markierung: Gaeste lesen
cmd /c mklink /J $Dir $Ziel | Out-Null
icacls $Dir /reset /L /C /Q | Out-Null
icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' /L /C /Q | Out-Null
$ZielAcl = Get-Acl $Ziel
Check 'icacls /L laesst das Junction-Ziel unveraendert' ((-not $ZielAcl.AreAccessRulesProtected) -and @($ZielAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-546' }).Count -gt 0)

Leeren
if ($script:Fail) { Write-Output "$($script:Fail) FEHLER"; exit 1 }
Write-Output 'alle Pruefungen bestanden'
