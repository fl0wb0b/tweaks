# Get-WindowsUpdateStatus.ps1  (v2.0.0)
# Laeuft als Scheduled Task (SYSTEM) alle 6 Stunden
# Teil 1: Windows Update Status  -> C:\Zabbix\update_status.txt        (jeder Lauf)
# Teil 2: Software-Inventar      -> C:\Zabbix\software_inventory.b64   (woechentlich, State-Gate)
#                                   C:\Zabbix\software_inventory.json  (Klartext, fuer HTML/Debug)
# Teil 3: HTML-Report            -> C:\Zabbix\report.html              (jeder Lauf)
# Zabbix liest .txt und .b64 per vfs.file.contents - kein Active Check, kein UserParameter
#
# v2.0.0: + OS/Build als Inventory-Eintrag (CVE-Match fuer OS-Advisories)
#         + Architektur pro Eintrag (x86/x64 via WOW6432Node)
#         + KB/Hotfix-Filter (ParentKeyName, ReleaseType, KB-Pattern)
#         + .NET Framework Erkennung (NDP-Registry, Release-Mapping)
#         + script_version im Payload, HTML-Report
# v2.1.0: + WSUS-Infos (Server, TargetGroup, UseWUServer, Dual-Scan-Hinweis)
#         + Letzte Erfolgszeiten Detect/Download/Install (AU Results Registry)
#         + wuauserv-Dienststatus, zuletzt installiertes Update (WU-History)
# v2.1.1: Kompatibilitaet Server 2016-2025: Get-WmiObject -> Get-CimInstance,
#         Scan-Source-Policy (2022/2025) zusaetzlich zu DisableDualScan (2016/2019)
# v2.1.2: update_status.txt BOM-frei (Out-File UTF8 schreibt in WinPS 5.1 BOM ->
#         kann Zabbix-JSONPath-Preprocessing brechen)
# v2.1.3: C:\Zabbix abgesichert (nur SYSTEM/Administratoren schreiben, keine Junction/Reparse Points,
#         icacls mit /L und Abbruch, wenn Rechte nicht setzbar sind),
#         State-Datei in der Zukunft blockiert das Inventar nicht mehr, Inventar mit 0/1 Eintraegen,
#         HTML: Fehlerzeile statt "Keine ausstehenden Updates", allgemeiner Dual-Scan-Hinweis

$ScriptVersion  = "2.1.3"
$OutputDir      = "C:\Zabbix"
$OutputFile     = "$OutputDir\update_status.txt"
$LogFile        = "$OutputDir\update_check.log"
$InventoryFile  = "$OutputDir\software_inventory.b64"
$InventoryJson  = "$OutputDir\software_inventory.json"
$InventoryState = "$OutputDir\software_inventory.state"
$HtmlFile       = "$OutputDir\report.html"
$InventoryMaxAgeDays = 7

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts $msg" -Encoding UTF8
}

function HtmlEscape($s) {
    if ($null -eq $s) { return "" }
    "$s".Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

# Ausgabeordner absichern: das Skript laeuft als SYSTEM. Ein Ordner direkt unter C:\ erbt sonst Rechte, mit denen Benutzer
# dort Dateien/Ordner anlegen (Server) bzw. aendern (Client) koennen; wer das kann, faelscht Ausgaben oder leitet die
# Schreibzugriffe von SYSTEM per Junction an beliebige Orte um. Daher: Reparse Points ablehnen, Rechte bei jedem Lauf setzen.
$OutFiles = @($OutputFile, $LogFile, $InventoryFile, $InventoryJson, $InventoryState, $HtmlFile)
function Stop-Ausgabe($Grund) {
    Write-Error "$Grund - Abbruch, nichts geschrieben"
    exit 1
}
function Test-Ausgabepfade {
    foreach ($p in @($OutputDir) + $OutFiles) {
        $i = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if ($i -and ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Stop-Ausgabe "$p ist eine Verknuepfung (Reparse Point)" }
    }
}
# /L: icacls aendert immer das Objekt unter dem Pfad selbst und folgt keiner (zwischendurch untergeschobenen) Verknuepfung
function Set-Rechte {
    icacls @args /L /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Ausgabe "Rechte fuer $($args[0]) nicht setzbar (Datei loeschen, sie wird neu angelegt)" }
}
Test-Ausgabepfade
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
# Vererbung von C:\ kappen, fremde Eintraege entfernen: SYSTEM und Administratoren Vollzugriff, Benutzer nur lesen (wie bisher);
# OWNER RIGHTS nur lesen, damit Besitzer eines vorab angelegten Ordners oder untergeschobener Dateien keine Rechte behalten
Set-Rechte $OutputDir /reset
Set-Rechte $OutputDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' '*S-1-3-4:(OI)(CI)RX'
foreach ($f in $OutFiles) { if (Test-Path -LiteralPath $f) { Set-Rechte $f /reset } }
# Erneut pruefen: wurde zwischen erster Pruefung und icacls getauscht, faellt es hier auf. Danach koennen nur noch
# SYSTEM und Administratoren den Ordner ersetzen.
Test-Ausgabepfade

# ============================================================
# TEIL 1: Windows Update Status (jeder Lauf)
# ============================================================

Write-Log "Update-Check gestartet (Script v$ScriptVersion)"

$Output = $null
try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0 and BrowseOnly=0")
    $AllUpdates   = $SearchResult.Updates

    $TotalCount    = $AllUpdates.Count
    $SecurityCount = 0
    $CriticalCount = 0
    $UpdateList    = @()

    foreach ($Update in $AllUpdates) {
        $Title    = $Update.Title
        $KBs      = ($Update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ","
        $Category = ($Update.Categories | Select-Object -First 1).Name

        if ($Category -match "Security|Sicherheit") { $SecurityCount++ }
        if ($Category -match "Critical|Kritisch")   { $CriticalCount++ }

        $UpdateList += "$Title ($KBs)"
    }

    $RebootRequired  = $false
    $RebootScheduled = $false

    $RebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )
    foreach ($key in $RebootKeys) {
        if (Test-Path $key) { $RebootRequired = $true }
    }
    $PendingRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($PendingRename) { $RebootRequired = $true }

    $WsusReboot = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
    if ($WsusReboot.ScheduledRebootTime) { $RebootScheduled = $true }

    if ($TotalCount -eq 0) {
        $Status = "ok"
    } elseif ($SecurityCount -gt 0 -or $CriticalCount -gt 0) {
        $Status = "update_available_critical"
    } else {
        $Status = "update_available"
    }

    # --- WSUS / Update-Quelle (GPO-Registry) ---
    $WuPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    $AuPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue

    $UseWsus      = [bool]($AuPolicy.UseWUServer -eq 1)
    $WsusServer   = if ($UseWsus -and $WuPolicy.WUServer) { $WuPolicy.WUServer } else { "" }
    $WsusGroup    = if ($WuPolicy.TargetGroupEnabled -eq 1) { $WuPolicy.TargetGroup } else { "" }
    $UpdateSource = if ($UseWsus) { "WSUS" } else { "Microsoft Update" }

    # Dual Scan (Server 2016/2019): Deferral-Policies + DisableDualScan nicht gesetzt
    $DualScanRisk = [bool]($UseWsus -and (
        $WuPolicy.DeferFeatureUpdates -or $WuPolicy.DeferQualityUpdates -or
        $WuPolicy.BranchReadinessLevel) -and
        ($WuPolicy.DisableDualScan -ne 1))

    # Scan Source Policy (Server 2022/2025): pro Kategorie WSUS(1) oder Microsoft Update(0)
    $ScanSource = ""
    $SrcParts = foreach ($k in 'FeatureUpdates','QualityUpdates','DriverUpdates','OtherUpdates') {
        $v = $WuPolicy."SetPolicyDrivenUpdateSourceFor$k"
        if ($null -ne $v) { "$k=$(if ($v -eq 1) { 'WSUS' } else { 'MU' })" }
    }
    if ($SrcParts) {
        $ScanSource = $SrcParts -join ", "
        # WSUS aktiv, aber mind. eine Kategorie auf Microsoft Update -> Bypass moeglich
        if ($UseWsus -and ($ScanSource -match '=MU')) { $DualScanRisk = $true }
    }

    # --- Letzte Erfolgszeiten (AU Results, UTC) ---
    $ResBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results"
    $LastDetect   = (Get-ItemProperty "$ResBase\Detect"   -ErrorAction SilentlyContinue).LastSuccessTime
    $LastDownload = (Get-ItemProperty "$ResBase\Download" -ErrorAction SilentlyContinue).LastSuccessTime
    $LastInstall  = (Get-ItemProperty "$ResBase\Install"  -ErrorAction SilentlyContinue).LastSuccessTime

    # --- wuauserv-Dienststatus ---
    $WuSvc = Get-Service wuauserv -ErrorAction SilentlyContinue
    $WuSvcStatus = if ($WuSvc) { "$($WuSvc.Status)/$($WuSvc.StartType)" } else { "not found" }

    # --- Zuletzt installiertes Update (WU-History, gleiche COM-Session) ---
    $LastInstalled = ""
    try {
        $HistCount = $UpdateSearcher.GetTotalHistoryCount()
        if ($HistCount -gt 0) {
            $Hist = $UpdateSearcher.QueryHistory(0, [Math]::Min(10, $HistCount)) |
                Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } |   # Installation, Succeeded
                Select-Object -First 1
            if ($Hist) {
                $LastInstalled = "$($Hist.Date.ToLocalTime().ToString('yyyy-MM-dd HH:mm')) - $($Hist.Title)"
            }
        }
    } catch {
        Write-Log "WARNUNG: WU-History nicht lesbar: $($_.Exception.Message)"
    }

    $Output = @{
        status            = $Status
        total             = $TotalCount
        security          = $SecurityCount
        critical          = $CriticalCount
        list              = ($UpdateList -join " | ")
        last_check        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        os                = (Get-CimInstance Win32_OperatingSystem).Caption
        build             = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        reboot_required   = $RebootRequired
        reboot_scheduled  = $RebootScheduled
        update_source     = $UpdateSource
        wsus_server       = $WsusServer
        wsus_target_group = $WsusGroup
        scan_source       = $ScanSource
        dual_scan_risk    = $DualScanRisk
        last_detect_utc   = "$LastDetect"
        last_download_utc = "$LastDownload"
        last_install_utc  = "$LastInstall"
        last_installed    = $LastInstalled
        wuauserv          = $WuSvcStatus
    }

    # WriteAllText BOM-frei: Out-File -Encoding UTF8 schreibt in WinPS 5.1 einen BOM,
    # der Zabbix-JSONPath-Preprocessing brechen kann
    [System.IO.File]::WriteAllText($OutputFile, ($Output | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))

    Write-Log "OK: total=$TotalCount security=$SecurityCount critical=$CriticalCount status=$Status reboot_required=$RebootRequired reboot_scheduled=$RebootScheduled source=$UpdateSource wsus=$WsusServer dual_scan_risk=$DualScanRisk"

} catch {
    $ErrorMsg = $_.Exception.Message
    Write-Log "FEHLER (Update-Check): $ErrorMsg"
    $Output = @{ status = "error"; error = $ErrorMsg; last_check = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
    [System.IO.File]::WriteAllText($OutputFile, ($Output | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
    $UpdateList = @()
}

# ============================================================
# TEIL 2: Software-Inventar (nur wenn State > 7 Tage alt / fehlt)
# ============================================================

$RunInventory = $true
$LastRun = ""
if (Test-Path $InventoryState) {
    $LastRun = (Get-Content $InventoryState -Raw -ErrorAction SilentlyContinue).Trim()
    try {
        $LastRunDate = [datetime]::Parse($LastRun)
        $Alter = ((Get-Date) - $LastRunDate).TotalDays
        if ($Alter -ge 0 -and $Alter -lt $InventoryMaxAgeDays) {    # Datum in der Zukunft (Uhr verstellt): faellig
            $RunInventory = $false
        }
    } catch {
        # State-Datei kaputt/leer -> Inventory trotzdem laufen lassen
    }
}

if ($RunInventory) {
    Write-Log "Inventory-Check gestartet (faellig, letzter Lauf > $InventoryMaxAgeDays Tage oder erstmalig)"

    try {
        $Is64OS = [Environment]::Is64BitOperatingSystem

        # Pfade mit Arch-Zuordnung: WOW6432Node = 32bit-Software auf 64bit-OS
        $RegSources = @(
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Arch = $(if ($Is64OS) { 'x64' } else { 'x86' }); Source = 'HKLM' },
            @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x86';                                     Source = 'HKLM-WOW64' },
            @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Arch = $(if ($Is64OS) { 'x64' } else { 'x86' }); Source = 'HKCU' }
        )

        # geladene User-Hives (RDP/Terminalserver mit angemeldeten Usern)
        $UserHives = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }
        foreach ($hive in $UserHives) {
            $RegSources += @{ Path = "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Arch = $(if ($Is64OS) { 'x64' } else { 'x86' }); Source = 'HKU' }
        }

        $Entries = @(foreach ($src in $RegSources) {     # @(): bei 0 oder 1 Eintrag sonst $null bzw. Einzelobjekt, += unten scheitert
            $Items = Get-ItemProperty -Path $src.Path -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -and ([string]$_.DisplayName).Trim() -ne '' -and   # [string]: DisplayName kann (Benutzer-Hive) auch DWORD sein
                    -not $_.SystemComponent -and
                    -not $_.ParentKeyName -and                                        # Kind-Eintraege von Updates
                    $_.ReleaseType -notmatch 'Update|Hotfix|ServicePack' -and         # als Update/Hotfix markiert
                    $_.DisplayName -notmatch '\(KB\d{6,7}\)'                          # "Update for ... (KB123456)"
                }
            foreach ($it in $Items) {
                [PSCustomObject]@{
                    name         = ([string]$it.DisplayName).Trim()
                    version      = $it.DisplayVersion
                    publisher    = $it.Publisher
                    arch         = $src.Arch
                    source       = $src.Source
                    install_date = $it.InstallDate
                }
            }
        })

        # --- OS als Inventory-Eintrag (fuer OS-Advisories im CSAF-Match) ---
        $CV      = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $UBR     = if ($CV.UBR) { ".$($CV.UBR)" } else { "" }
        $OsBuild = "$($CV.CurrentBuildNumber)$UBR"
        $OsName  = (Get-CimInstance Win32_OperatingSystem).Caption
        $Entries += [PSCustomObject]@{
            name         = $OsName
            version      = $OsBuild
            publisher    = "Microsoft Corporation"
            arch         = $(if ($Is64OS) { 'x64' } else { 'x86' })
            source       = "OS"
            install_date = $null
        }

        # --- .NET Framework (steht NICHT im Uninstall-Key) ---
        $Ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
        if ($Ndp -and $Ndp.Release) {
            $NetVersion = switch ($Ndp.Release) {
                { $_ -ge 533320 } { "4.8.1"; break }
                { $_ -ge 528040 } { "4.8";   break }
                { $_ -ge 461808 } { "4.7.2"; break }
                { $_ -ge 461308 } { "4.7.1"; break }
                { $_ -ge 460798 } { "4.7";   break }
                { $_ -ge 394802 } { "4.6.2"; break }
                { $_ -ge 394254 } { "4.6.1"; break }
                { $_ -ge 393295 } { "4.6";   break }
                { $_ -ge 379893 } { "4.5.2"; break }
                default           { $Ndp.Version }
            }
            $Entries += [PSCustomObject]@{
                name         = "Microsoft .NET Framework"
                version      = $NetVersion
                publisher    = "Microsoft Corporation"
                arch         = $(if ($Is64OS) { 'x64' } else { 'x86' })
                source       = "NDP"
                install_date = $null
            }
        }

        $Inventory = @($Entries | Sort-Object name, version, arch -Unique)

        $Payload = [PSCustomObject]@{
            hostname       = $env:COMPUTERNAME
            script_version = $ScriptVersion
            collected_at   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            count          = $Inventory.Count
            software       = $Inventory
        }

        $Json  = $Payload | ConvertTo-Json -Depth 4 -Compress
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)

        $Ms   = New-Object System.IO.MemoryStream
        $Gzip = New-Object System.IO.Compression.GzipStream($Ms, [System.IO.Compression.CompressionMode]::Compress)
        $Gzip.Write($Bytes, 0, $Bytes.Length)
        $Gzip.Close()
        $B64 = [Convert]::ToBase64String($Ms.ToArray())
        $Ms.Close()

        # WriteAllText statt Out-File -> kein UTF-16 BOM, reines ASCII (Base64-safe)
        [System.IO.File]::WriteAllText($InventoryFile, $B64, [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($InventoryJson, $Json, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText($InventoryState, (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), [System.Text.Encoding]::ASCII)

        Write-Log "Inventory OK: $($Inventory.Count) Eintraege, $($B64.Length) Bytes b64 (roh $($Bytes.Length) Bytes)"

        if ($B64.Length -gt 65536) {
            Write-Log "WARNUNG: Inventory-Payload > 64KB - vfs.file.contents liefert abgeschnittenen Wert!"
        }

    } catch {
        $ErrorMsg = $_.Exception.Message
        Write-Log "FEHLER (Inventory-Check): $ErrorMsg"
        $ErrPayload = @{ status = "error"; error = $ErrorMsg; hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($InventoryFile, $ErrPayload, [System.Text.Encoding]::UTF8)
        # State-Datei bei Fehler NICHT aktualisieren -> naechster Lauf in 6h versucht es erneut
    }
} else {
    Write-Log "Inventory-Check uebersprungen (letzter Lauf: $LastRun)"
}

# ============================================================
# TEIL 3: HTML-Report (jeder Lauf, liest software_inventory.json)
# ============================================================

try {
    $Inv = $null
    if (Test-Path $InventoryJson) {
        $Inv = Get-Content $InventoryJson -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    # --- Update-Status als einfacher Text ---
    $WuStatus  = if ($Output.status) { $Output.status } else { "unknown" }
    $RebootTxt = ""
    if ($Output.reboot_required)  { $RebootTxt += ", Reboot erforderlich" }
    if ($Output.reboot_scheduled) { $RebootTxt += ", Reboot geplant" }

    $UpdateRows = ""
    foreach ($u in $UpdateList) {
        $UpdateRows += "<li>$(HtmlEscape $u)</li>`n"
    }
    if (-not $UpdateRows) {
        $UpdateRows = if ($WuStatus -eq 'error') { "<li>Update-Pruefung fehlgeschlagen: $(HtmlEscape $Output.error)</li>" } else { "<li>Keine ausstehenden Updates</li>" }
    }

    $WsusLine = ""
    if ($Output.wsus_server) {
        $WsusLine = " ($(HtmlEscape $Output.wsus_server)"
        if ($Output.wsus_target_group) { $WsusLine += ", Gruppe: $(HtmlEscape $Output.wsus_target_group)" }
        $WsusLine += ")"
    }
    $DualScanTxt = if ($Output.dual_scan_risk) { " &middot; <b>Achtung: Dual-Scan-Risiko (Updates koennen an WSUS vorbei von Microsoft Update kommen: Deferral-Policies ohne DisableDualScan oder Scan Source auf MU)</b>" } else { "" }

    # --- Inventar-Tabelle ---
    $InvRows  = ""
    $InvCount = 0
    $InvDate  = "-"
    if ($Inv -and $Inv.software) {
        $InvCount = $Inv.count
        $InvDate  = HtmlEscape $Inv.collected_at
        foreach ($sw in $Inv.software) {
            $InvRows += "<tr><td>$(HtmlEscape $sw.name)</td><td>$(HtmlEscape $sw.version)</td><td>$(HtmlEscape $sw.publisher)</td><td>$(HtmlEscape $sw.arch)</td><td>$(HtmlEscape $sw.source)</td></tr>`n"
        }
    } else {
        $InvRows = "<tr><td colspan='5'>Noch kein Inventar erfasst</td></tr>"
    }

    $Html = @'
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>{{HOST}} - Update &amp; Software Report</title>
<style>
  body { font:14px/1.5 "Segoe UI",Arial,sans-serif; margin:24px; color:#000; }
  h1 { font-size:20px; margin:0 0 2px; }
  h2 { font-size:15px; margin:20px 0 6px; }
  p.meta { color:#555; font-size:12px; margin:0 0 16px; }
  table { border-collapse:collapse; width:100%; }
  th, td { border:1px solid #999; padding:4px 8px; text-align:left; font-size:13px; }
  th { background:#e8e8e8; }
  ul { margin:4px 0; }
</style>
</head>
<body>
<h1>{{HOST}}</h1>
<p class="meta">{{OS}} &middot; Build {{BUILD}} &middot; Script v{{SCRIPTVER}} &middot; Report erzeugt: {{GENERATED}}</p>

<h2>Windows Update Status</h2>
<p>Status: <b>{{STATUS}}</b> ({{TOTAL}} ausstehend, davon {{SECURITY}} Security, {{CRITICAL}} kritisch{{REBOOT}})<br>
Letzter Check: {{WU_CHECK}}</p>
<p>Update-Quelle: <b>{{SOURCE}}</b>{{WSUSLINE}}{{SCANSOURCE}}{{DUALSCAN}}<br>
Letzte Suche (UTC): {{LASTDETECT}} &middot; Letzter Download (UTC): {{LASTDOWNLOAD}} &middot; Letzte Installation (UTC): {{LASTINSTALLTS}}<br>
Zuletzt installiert: {{LASTINSTALLED}}<br>
Dienst wuauserv: {{WUAUSERV}}</p>
<ul>
{{UPDATELIST}}
</ul>

<h2>Software-Inventar ({{INVCOUNT}} Eintraege, erfasst: {{INVDATE}})</h2>
<table>
<tr><th>Name</th><th>Version</th><th>Hersteller</th><th>Arch</th><th>Quelle</th></tr>
{{INVROWS}}
</table>
</body>
</html>
'@

    $Html = $Html.Replace('{{HOST}}',       (HtmlEscape $env:COMPUTERNAME)).
                  Replace('{{OS}}',         (HtmlEscape $Output.os)).
                  Replace('{{BUILD}}',      (HtmlEscape $Output.build)).
                  Replace('{{SCRIPTVER}}',  $ScriptVersion).
                  Replace('{{GENERATED}}',  (Get-Date -Format "yyyy-MM-dd HH:mm:ss")).
                  Replace('{{WU_CHECK}}',   (HtmlEscape $Output.last_check)).
                  Replace('{{STATUS}}',     (HtmlEscape $WuStatus)).
                  Replace('{{TOTAL}}',      "$($Output.total)").
                  Replace('{{SECURITY}}',   "$($Output.security)").
                  Replace('{{CRITICAL}}',   "$($Output.critical)").
                  Replace('{{REBOOT}}',     (HtmlEscape $RebootTxt)).
                  Replace('{{SOURCE}}',     (HtmlEscape $Output.update_source)).
                  Replace('{{WSUSLINE}}',   $WsusLine).
                  Replace('{{SCANSOURCE}}', $(if ($Output.scan_source) { " &middot; Scan Source: $(HtmlEscape $Output.scan_source)" } else { "" })).
                  Replace('{{DUALSCAN}}',   $DualScanTxt).
                  Replace('{{LASTDETECT}}',    (HtmlEscape $(if ($Output.last_detect_utc)   { $Output.last_detect_utc }   else { "-" }))).
                  Replace('{{LASTDOWNLOAD}}',  (HtmlEscape $(if ($Output.last_download_utc) { $Output.last_download_utc } else { "-" }))).
                  Replace('{{LASTINSTALLTS}}', (HtmlEscape $(if ($Output.last_install_utc)  { $Output.last_install_utc }  else { "-" }))).
                  Replace('{{LASTINSTALLED}}', (HtmlEscape $(if ($Output.last_installed)    { $Output.last_installed }    else { "-" }))).
                  Replace('{{WUAUSERV}}',      (HtmlEscape $(if ($Output.wuauserv)          { $Output.wuauserv }          else { "-" }))).
                  Replace('{{UPDATELIST}}', $UpdateRows).
                  Replace('{{INVCOUNT}}',   "$InvCount").
                  Replace('{{INVDATE}}',    $InvDate).
                  Replace('{{INVROWS}}',    $InvRows)

    [System.IO.File]::WriteAllText($HtmlFile, $Html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "HTML-Report geschrieben: $HtmlFile"

} catch {
    Write-Log "FEHLER (HTML-Report): $($_.Exception.Message)"
}

# Log auf 1000 Zeilen begrenzen
if (Test-Path $LogFile) {
    $Lines = Get-Content $LogFile
    if ($Lines.Count -gt 1000) {
        $Lines | Select-Object -Last 500 | Set-Content $LogFile -Encoding UTF8
    }
}
