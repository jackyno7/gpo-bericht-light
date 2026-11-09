#Requires -Version 5.1
<#
.SYNOPSIS
    LIGHT-VERSION (6 von 26 Prüfpunkten, kostenlos). GPO-Bericht: listet alle Gruppenrichtlinien einer Domäne mit Inhalt und Verknüpfungen und prüft sie auf Fehler,
    Sicherheitslücken und Altlasten. Ergebnis ist ein HTML-Bericht.

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Gruppenrichtlinie, keine Verknüpfung und nichts
    im Active Directory oder in SYSVOL und überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf
    Wunsch CSV-Dateien) in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" und ein Domänenkonto mit Leserechten.
    Die Gruppenrichtlinienverwaltung (GPMC) wird nicht benötigt: Das Skript liest die Richtlinien direkt aus dem
    Verzeichnis und aus der Freigabe SYSVOL. Administratorrechte sind nicht erforderlich; Richtlinien, die das
    ausführende Konto nicht lesen darf, fehlen dann im Bericht.

.PARAMETER Ausgabe
    Pfad der HTML-Datei. Standard: GPO-Bericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER OhneDcVergleich
    SYSVOL nur auf einem Domänencontroller lesen statt auf allen (schneller, aber ohne Vergleich der Stände).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft.
    Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Schreibt die Liste aller Richtlinien, alle Verknüpfungen und je Prüfpunkt mit Treffern eine CSV-Datei.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\GPO-Bericht.ps1

.EXAMPLE
    .\GPO-Bericht.ps1 -Csv -Ausgabe C:\Berichte\gpo.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [switch]$OhneDcVergleich,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, $Bezug, $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten aus dem Verzeichnis
Write-Host 'GPO-Bericht - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$wurzel = Get-ADRootDSE @ad
$stammSid = $sid
try { if ($wald.RootDomain -ne $dom.DNSRoot) { $stammSid = (Get-ADDomain -Identity $wald.RootDomain @ad).DomainSID.Value } } catch { }

# Konten, die Gruppenrichtlinien ohnehin verwalten dürfen
$vertraut = @('S-1-5-18', 'S-1-3-0', 'S-1-5-9', 'S-1-5-32-544', "$sid-512", "$stammSid-519")
# Sammelgruppen, in denen (fast) jeder Mitglied ist
$jedermann = @{ 'S-1-1-0' = 'Jeder'; 'S-1-5-11' = 'Authentifizierte Benutzer'; 'S-1-5-7' = 'Anonymous-Anmeldung'; 'S-1-5-32-545' = 'Benutzer'; "$sid-513" = 'Domänen-Benutzer'; "$sid-515" = 'Domänencomputer'; 'S-1-5-32-554' = 'Prä-Windows 2000 kompatibler Zugriff' }
$bekannt = @{ 'S-1-5-18' = 'SYSTEM'; 'S-1-3-0' = 'ERSTELLER-BESITZER'; 'S-1-5-9' = 'Domänencontroller der Organisation' }
foreach ($k in $jedermann.Keys) { $bekannt[$k] = $jedermann[$k] }
$sidCache = @{}
function Wer($s) {
    $s = "$s"
    if (-not $sidCache.ContainsKey($s)) {
        $o = $null
        if ($bekannt.ContainsKey($s)) { $sidCache[$s] = $bekannt[$s] }
        else {
            try { $o = Get-ADObject -LDAPFilter "(objectSid=$s)" -Properties sAMAccountName @ad } catch { }
            $sidCache[$s] = if ($o -and $o.sAMAccountName) { $o.sAMAccountName } elseif ($o) { $o.Name } elseif ($s -like 'S-1-5-21-*') { "$s (Konto gelöscht)" } else { $s }
        }
    }
    $sidCache[$s]
}

Write-Host '  Gruppenrichtlinien ...'
$eig = 'displayName', 'flags', 'versionNumber', 'gPCFileSysPath', 'gPCWQLFilter', 'whenCreated', 'whenChanged', 'nTSecurityDescriptor'
$gpoObj = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$dn" -SearchScope OneLevel -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties $eig @ad)
$guidMuster = '\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'

$wmi = @{}
$wmiFehler = $null
try {
    Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$dn" -LDAPFilter '(objectClass=msWMI-Som)' -Properties 'msWMI-Name', 'msWMI-ID', 'msWMI-Parm2' @ad |
        ForEach-Object { $wmi["$($_.'msWMI-ID')".ToUpper()] = [pscustomobject]@{ Name = $_.'msWMI-Name'; Abfrage = (("$($_.'msWMI-Parm2')" -split ';') | Where-Object { $_ -match '^\s*select\s' }) -join ' / ' } }
} catch { $wmiFehler = Kurz $_.Exception.Message }

$R = [System.DirectoryServices.ActiveDirectoryRights]
$anwendenGuid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
$leer = [guid]::Empty.Guid

$gpos = foreach ($o in $gpoObj) {
    $v = [int64]$o.versionNumber
    $anwenden = @(); $verweigert = @(); $lesen = @(); $bearbeiten = @()
    $sd = $o.nTSecurityDescriptor
    if ($sd) {
        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
            $s = $ace.IdentityReference.Value
            $r = $ace.ActiveDirectoryRights
            $ot = "$($ace.ObjectType)"
            $erlaubt = "$($ace.AccessControlType)" -eq 'Allow'
            if (($r -band $R::ExtendedRight) -and $ot -in $leer, $anwendenGuid) { if ($erlaubt) { $anwenden += $s } else { $verweigert += $s } }
            if (-not $erlaubt) { continue }
            if (($r -band $R::ReadProperty) -and $ot -eq $leer) { $lesen += $s }
            $t = @()
            if (($r -band $R::GenericAll) -eq $R::GenericAll) { $t += 'Vollzugriff' }
            else {
                if (($r -band $R::WriteProperty) -and $ot -eq $leer) { $t += 'Einstellungen bearbeiten' }
                if ($r -band $R::WriteDacl) { $t += 'Berechtigungen ändern' }
                if ($r -band $R::WriteOwner) { $t += 'Besitz übernehmen' }
            }
            if ($t.Count -and $s -notin $vertraut) { $bearbeiten += [pscustomobject]@{ Sid = $s; Rechte = ($t -join '; ') } }
        }
    }
    $filter = if ("$($o.gPCWQLFilter)" -match $guidMuster) { $Matches[0].ToUpper() } else { '' }
    [pscustomobject]@{
        Guid = $o.Name.ToUpper(); Name = $(if ($o.displayName) { $o.displayName } else { $o.Name }); Flags = [int]$o.flags
        VerB = [int]($v -shr 16); VerC = [int]($v -band 0xFFFF); Angelegt = $o.whenCreated; Geaendert = $o.whenChanged
        Lesbar = [bool]$sd; Anwenden = @($anwenden | Select-Object -Unique); Verweigert = @($verweigert | Select-Object -Unique)
        Lesen = @($lesen | Select-Object -Unique); Bearbeiten = $bearbeiten; Filter = $filter
        InhaltC = @(); InhaltB = @(); Loopback = $false; Kennwortrichtlinie = $false; Kennwortdateien = @(); InhaltBekannt = $false
    }
}
$gpos = @($gpos | Sort-Object Name)
$gpoNach = @{}
foreach ($g in $gpos) { $gpoNach[$g.Guid] = $g }

# ------------------------------------------------------------------ Verknüpfungen
Write-Host '  Verknüpfungen ...'
$orte = @()
$orte += Get-ADObject -Identity $dn -Properties gPLink, gPOptions @ad | ForEach-Object { [pscustomobject]@{ Art = 'Domäne'; Pfad = "Domäne $($dom.DNSRoot)"; DN = $_.DistinguishedName; Link = $_.gPLink; Optionen = $_.gPOptions } }
$orte += Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions @ad | Sort-Object { $_.DistinguishedName.Length }, DistinguishedName |
    ForEach-Object { [pscustomobject]@{ Art = 'OU'; Pfad = ($_.DistinguishedName -replace ",$([regex]::Escape($dn))$", ''); DN = $_.DistinguishedName; Link = $_.gPLink; Optionen = $_.gPOptions } }
$standortFehler = $null
try {
    $orte += Get-ADObject -SearchBase "CN=Sites,$($wurzel.configurationNamingContext)" -SearchScope OneLevel -LDAPFilter '(objectClass=site)' -Properties gPLink @ad |
        ForEach-Object { [pscustomobject]@{ Art = 'Standort'; Pfad = "Standort $($_.Name)"; DN = $_.DistinguishedName; Link = $_.gPLink; Optionen = 0 } }
} catch { $standortFehler = Kurz $_.Exception.Message }

$links = foreach ($ort in $orte) {
    $treffer = [regex]::Matches("$($ort.Link)", '\[LDAP://([^;\]]+);(\d+)\]')
    for ($i = 0; $i -lt $treffer.Count; $i++) {
        $ziel = $treffer[$i].Groups[1].Value
        $opt = [int]$treffer[$i].Groups[2].Value
        $guid = if ($ziel -match $guidMuster) { $Matches[0].ToUpper() } else { $ziel }
        $fremd = $ziel -notlike "*,$dn"
        $g = $gpoNach[$guid]
        [pscustomobject]@{
            Ort = $ort.Pfad; Art = $ort.Art; OrtDN = $ort.DN; Guid = $guid; Name = $(if ($g) { $g.Name } else { $guid }); Vorhanden = [bool]$g; Fremd = $fremd
            Aktiv = -not ($opt -band 1); Erzwungen = [bool]($opt -band 2); Reihenfolge = $treffer.Count - $i
        }
    }
}
$links = @($links)

# Benutzer und Computer unterhalb einer Organisationseinheit (nur ob es welche gibt)
$inhaltOu = @{}
function OuInhalt($basis) {
    if (-not $inhaltOu.ContainsKey($basis)) {
        $b = @(Get-ADObject -SearchBase $basis -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -ResultSetSize 1 @ad).Count
        $c = @(Get-ADObject -SearchBase $basis -LDAPFilter '(objectCategory=computer)' -ResultSetSize 1 @ad).Count
        $inhaltOu[$basis] = [pscustomobject]@{ Benutzer = [bool]$b; Computer = [bool]$c }
    }
    $inhaltOu[$basis]
}

# ------------------------------------------------------------------ SYSVOL
$laufwerke = @()
function SysvolPfad($dcHost) {
    # Mit -Anmeldung wird die Freigabe unter diesem Konto geöffnet (Laufwerk nur innerhalb dieses Skripts)
    $unc = "\\$dcHost\SYSVOL\$($dom.DNSRoot)\Policies"
    if ($Anmeldung) {
        try {
            $n = "GpoBericht$($script:laufwerke.Count)"
            New-PSDrive -Name $n -PSProvider FileSystem -Root "\\$dcHost\SYSVOL" -Credential $Anmeldung -ErrorAction Stop | Out-Null
            $script:laufwerke += $n
        } catch { }
    }
    $unc
}
$einstellungName = @{ Drives = 'Laufwerke'; Printers = 'Drucker'; Files = 'Dateien'; Folders = 'Ordner'; Registry = 'Registrierung'; Shortcuts = 'Verknüpfungen'
    Groups = 'Lokale Benutzer und Gruppen'; ScheduledTasks = 'Geplante Aufgaben'; Services = 'Dienste'; EnvironmentVariables = 'Umgebungsvariablen'
    IniFiles = 'INI-Dateien'; InternetSettings = 'Interneteinstellungen'; FolderOptions = 'Ordneroptionen'; PowerOptions = 'Energieoptionen'
    NetworkShares = 'Netzwerkfreigaben'; NetworkOptions = 'Netzwerkoptionen'; DataSources = 'Datenquellen'; Devices = 'Geräte'
    StartMenuTaskbar = 'Startmenü'; RegionalOptions = 'Regionale Einstellungen'
}
function TeilInhalt($ordner, $g, $seite) {
    # Liest aus den Dateien einer Richtlinie, welche Arten von Einstellungen sie enthält
    $p = Join-Path $ordner $seite
    if (-not (Test-Path -LiteralPath $p)) { return }
    $p = (Get-Item -LiteralPath $p).FullName
    foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction Stop)) {
        $rel = $f.FullName.Substring($p.Length + 1)
        if ($rel -match '\.cmtx$') { continue }
        if ($rel -match '^Registry\.pol$') {
            if ($f.Length -le 8) { continue }
            $text = [System.Text.Encoding]::Unicode.GetString([System.IO.File]::ReadAllBytes($f.FullName))
            if ($seite -eq 'Machine' -and $text -match 'UserPolicyMode' -and $text -notmatch '\*\*del\.UserPolicyMode') { $g.Loopback = $true }
            # Zertifikatseinstellungen (z. B. der EFS-Wiederherstellungsagent der Default Domain Policy) liegen in derselben Datei
            $schluessel = @([regex]::Matches($text, '\[([^\x00;]+)\x00;') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            if (@($schluessel | Where-Object { $_ -like 'Software\Policies\Microsoft\SystemCertificates*' }).Count) { 'Zertifikate (öffentliche Schlüssel)' }
            if (-not $schluessel.Count -or @($schluessel | Where-Object { $_ -notlike 'Software\Policies\Microsoft\SystemCertificates*' }).Count) { 'Administrative Vorlagen' }
        } elseif ($rel -match 'SecEdit\\GptTmpl\.inf$') {
            $zeilen = @(Get-Content -LiteralPath $f.FullName)
            $abschnitt = ''
            $werte = 0
            foreach ($z in $zeilen) {
                if ($z -match '^\s*\[(.+)\]') { $abschnitt = $Matches[1] }
                elseif ($z.Trim() -and $abschnitt -notin 'Unicode', 'Version') {
                    $werte++
                    if ($abschnitt -eq 'System Access' -and $z -match '^\s*(MinimumPasswordLength|MaximumPasswordAge|MinimumPasswordAge|PasswordComplexity|PasswordHistorySize|LockoutBadCount)\s*=') { $g.Kennwortrichtlinie = $true }
                }
            }
            if ($werte) { 'Sicherheitseinstellungen' }
        } elseif ($rel -match 'Audit\\audit\.csv$') { if ($f.Length -gt 200) { 'Erweiterte Überwachung' } }
        elseif ($rel -match '^Scripts\\(ps)?scripts\.ini$') { if ($f.Length -gt 10) { 'Skripte' } }
        elseif ($rel -match '^Scripts\\') { }
        elseif ($rel -match '^Preferences\\([^\\]+)\\.+\.xml$') {
            $art = $Matches[1]
            if (Select-String -LiteralPath $f.FullName -Pattern 'cpassword="[^"]+"' -Quiet) { $g.Kennwortdateien += "$seite\$rel" }
            'Einstellungen: ' + $(if ($einstellungName.ContainsKey($art)) { $einstellungName[$art] } else { $art })
        } elseif ($rel -match '^Applications\\.+\.aas$') { 'Softwareinstallation' }
        elseif ($rel -match '^Documents & Settings\\fdeploy\d?\.ini$') { if ($f.Length -gt 10) { 'Ordnerumleitung' } }
        else { 'Sonstige Dateien' }
    }
}

Write-Host '  SYSVOL ...'
$dcs = @()
try {
    $ich = Get-ADDomainController @ad
    $dcs = @($ich)
    if (-not $OhneDcVergleich) { $dcs = @($ich) + @(Get-ADDomainController -Filter * @ad | Where-Object { $_.HostName -ne $ich.HostName } | Sort-Object Name) }
} catch { }
$svStand = @()      # je Domänencontroller: Ordnerliste und Versionen
$svFehler = @()
$inhaltVon = $null
foreach ($d in $dcs) {
    Write-Host "    $($d.Name) ..."
    try {
        $pfad = SysvolPfad $d.HostName
        $ordner = @(Get-ChildItem -LiteralPath $pfad -Directory -ErrorAction Stop | Where-Object { $_.Name -match "^$guidMuster$" })
        $ver = @{}
        foreach ($o in $ordner) {
            $ini = Join-Path $o.FullName 'GPT.INI'
            $ver[$o.Name.ToUpper()] = $null
            try { if ((Get-Content -LiteralPath $ini -Raw -ErrorAction Stop) -match '(?im)^\s*Version\s*=\s*(\d+)') { $ver[$o.Name.ToUpper()] = [int64]$Matches[1] } } catch { }
        }
        $svStand += [pscustomobject]@{ DC = $d.Name; Version = $ver }
        if (-not $inhaltVon) {
            foreach ($o in $ordner) {
                $g = $gpoNach[$o.Name.ToUpper()]
                if (-not $g) { continue }
                try {
                    $g.InhaltC = @(TeilInhalt $o.FullName $g 'Machine' | Sort-Object -Unique)
                    $g.InhaltB = @(TeilInhalt $o.FullName $g 'User' | Sort-Object -Unique)
                    $g.InhaltBekannt = $true
                } catch { }
            }
            $inhaltVon = $d.Name
        }
    } catch { $svFehler += [pscustomobject]@{ Gruppenrichtlinie = '(alle)'; Domänencontroller = $d.Name; Feststellung = 'SYSVOL nicht lesbar - nicht geprüft'; Details = Kurz $_.Exception.Message } }
}
if (-not $dcs.Count) { $svFehler += [pscustomobject]@{ Gruppenrichtlinie = '(alle)'; Domänencontroller = '-'; Feststellung = 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft'; Details = '' } }
foreach ($n in $laufwerke) { try { Remove-PSDrive -Name $n -Force } catch { } }
# Zeile für alle Prüfpunkte, die den Inhalt der Richtlinien brauchen. Einzelne nicht lesbare Richtlinien stehen unter F3.
$ohneInhalt = @()
if (-not $inhaltVon) { $ohneInhalt = @([pscustomobject]@{ Gruppenrichtlinie = '(alle)'; Feststellung = 'SYSVOL nicht lesbar - nicht geprüft' }) }

function Status($g) { switch ($g.Flags -band 3) { 0 { 'Aktiv' } 1 { 'Benutzerteil aus' } 2 { 'Computerteil aus' } 3 { 'Deaktiviert' } } }
function GZeile($g, [System.Collections.IDictionary]$Zusatz = @{}) {
    $z = [ordered]@{ Gruppenrichtlinie = $g.Name; Status = Status $g; Geändert = Datum $g.Geaendert }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}
function Inhalt($g) {
    if (-not $g.InhaltBekannt) { return 'nicht lesbar' }
    $t = @()
    if ($g.InhaltC.Count) { $t += 'Computer: ' + ($g.InhaltC -join ', ') }
    if ($g.InhaltB.Count) { $t += 'Benutzer: ' + ($g.InhaltB -join ', ') }
    if ($t.Count) { $t -join ' | ' } else { 'keine Einstellungen' }
}
function LZeile($l, [System.Collections.IDictionary]$Zusatz = @{}) {
    $z = [ordered]@{ Ort = $l.Ort; Gruppenrichtlinie = $l.Name; Reihenfolge = $l.Reihenfolge; Aktiv = JaNein $l.Aktiv; Erzwungen = JaNein $l.Erzwungen }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}
$aktiveLinks = @($links | Where-Object { $_.Aktiv -and $_.Vorhanden })
$domLinks = @($aktiveLinks | Where-Object Art -eq 'Domäne')

# ------------------------------------------------------------------ Prüfungen: Fehler
Write-Host '  Auswertung ...'
$f1 = @($links | Where-Object { -not $_.Vorhanden -and -not $_.Fremd } | ForEach-Object { LZeile $_ @{ Feststellung = 'Richtlinie gibt es nicht mehr oder sie ist für dieses Konto nicht lesbar' } })
if ($standortFehler) { $f1 += [pscustomobject]@{ Ort = 'Standorte'; Gruppenrichtlinie = ''; Feststellung = 'Abfrage fehlgeschlagen - nicht geprüft'; Details = $standortFehler } }
Befund 'F1' 'Fehler' 'Verknüpfungen auf nicht vorhandene Gruppenrichtlinien' 'Mittel' $f1 `
    'Die Verknüpfung zeigt auf eine Richtlinie, die es nicht mehr gibt - meist ein Überbleibsel nach dem Löschen. Läuft das Skript ohne Administratorrechte, kann es auch eine Richtlinie sein, die dieses Konto nicht lesen darf.' `
    'Als Administrator gegenprüfen und verwaiste Verknüpfungen in der Gruppenrichtlinienverwaltung entfernen.'

# ------------------------------------------------------------------ Prüfungen: Sicherheit
$s1 = @(); $s2 = @()
# Konten, die über Domänen-Admins oder die lokale Gruppe Administratoren ohnehin Administratoren sind (auch verschachtelt)
$adminSid = @{}
foreach ($gs in "$sid-512", 'S-1-5-32-544') {
    try {
        $gdn = (Get-ADGroup -Identity $gs @ad).DistinguishedName
        Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$gdn)" @ad | ForEach-Object { $adminSid[$_.SID.Value] = 1 }
    } catch { }
}
foreach ($g in $gpos) {
    foreach ($b in $g.Bearbeiten) {
        $z = [pscustomobject][ordered]@{ Gruppenrichtlinie = $g.Name; Konto = Wer $b.Sid; Rechte = $b.Rechte; 'Aktiv verknüpft mit' = (@($aktiveLinks | Where-Object Guid -eq $g.Guid | ForEach-Object { $_.Ort }) -join '; ') }
        if ($jedermann.ContainsKey($b.Sid)) { $s1 += $z }
        elseif ($adminSid.ContainsKey($b.Sid)) { continue }   # direkt eingetragen, aber ohnehin Administrator (z. B. Ersteller der Richtlinie)
        else { $s2 += $z }
    }
}
$unlesbar = @($gpos | Where-Object { -not $_.Lesbar } | ForEach-Object { [pscustomobject][ordered]@{ Gruppenrichtlinie = $_.Name; Konto = ''; Rechte = 'Berechtigungen nicht lesbar - nicht geprüft'; 'Aktiv verknüpft mit' = '' } })
Befund 'S1' 'Sicherheit' 'Jeder Benutzer darf die Richtlinie bearbeiten' 'Hoch' ($s1 + $unlesbar) `
    'Eine Sammelgruppe wie "Authentifizierte Benutzer" oder "Domänen-Benutzer" hat Schreibrechte auf diese Richtlinie. Jeder Angemeldete kann damit auf allen Rechnern, auf die sie wirkt, beliebige Programme mit Systemrechten ausführen.' `
    'Schreibrechte sofort entfernen (Registerkarte "Delegierung") und prüfen, ob die Richtlinie verändert wurde.'

# ------------------------------------------------------------------ Prüfungen: Aufräumen
$g1 = foreach ($g in $gpos) {
    $l = @($links | Where-Object Guid -eq $g.Guid)
    if (-not $l.Count) { GZeile $g ([ordered]@{ Inhalt = Inhalt $g; Feststellung = 'Nirgends verknüpft' }) }
    elseif (-not @($l | Where-Object Aktiv).Count) { GZeile $g ([ordered]@{ Inhalt = Inhalt $g; Feststellung = 'Nur deaktivierte Verknüpfungen' }) }
}
Befund 'G1' 'Aufräumen' 'Nicht verknüpfte Gruppenrichtlinien' 'Niedrig' $g1 `
    'Diese Richtlinien sind mit keiner Domäne, Organisationseinheit und keinem Standort aktiv verknüpft und wirken deshalb nirgends. Verknüpfungen aus anderen Domänen der Gesamtstruktur sieht das Skript nicht.' `
    'Prüfen, ob die Richtlinie noch gebraucht wird (Vorlage, Test). Sonst sichern und löschen.'

$g2 = @($ohneInhalt)
$g2 += $gpos | Where-Object { $_.InhaltBekannt -and -not $_.InhaltC.Count -and -not $_.InhaltB.Count } |
    ForEach-Object { GZeile $_ @{ Feststellung = $(if ($_.VerC -eq 0 -and $_.VerB -eq 0) { 'Wurde nie bearbeitet' } else { 'Keine Einstellungen in SYSVOL gefunden' }) } }
Befund 'G2' 'Aufräumen' 'Leere Gruppenrichtlinien' 'Niedrig' $g2 `
    'In diesen Richtlinien wurden keine Einstellungen gefunden. Hinweis: WLAN-, IPsec- und Softwareeinschränkungs-Richtlinien liegen teils nur im Verzeichnis und werden hier nicht erkannt.' `
    'In der Gruppenrichtlinienverwaltung auf der Registerkarte "Einstellungen" gegenprüfen und leere Richtlinien löschen.'

Befund 'G3' 'Aufräumen' 'Vollständig deaktivierte Gruppenrichtlinien' 'Niedrig' `
($gpos | Where-Object { ($_.Flags -band 3) -eq 3 } | ForEach-Object { GZeile $_ @{ Inhalt = Inhalt $_ } }) `
    'Bei diesen Richtlinien sind Computer- und Benutzerteil abgeschaltet. Sie wirken nicht, auch wenn sie verknüpft sind.' `
    'Wenn die Richtlinie nicht mehr gebraucht wird: sichern und löschen.'

# ------------------------------------------------------------------ Aufbau (zur Kenntnis)
Befund 'A1' 'Aufbau' 'Erzwungene Verknüpfungen' 'Info' `
($links | Where-Object { $_.Erzwungen -and $_.Vorhanden } | ForEach-Object { LZeile $_ }) `
    'Erzwungene Verknüpfungen setzen sich gegen alle Richtlinien darunter durch und ignorieren eine deaktivierte Vererbung. Sinnvoll für wenige Sicherheitsvorgaben - in größerer Zahl wird das Ergebnis schwer vorhersagbar.' `
    'Zur Kenntnis. Erzwingen sparsam einsetzen und dokumentieren.'

# ------------------------------------------------------------------ Bericht
$liste = $gpos | ForEach-Object {
    $g = $_
    [pscustomobject][ordered]@{
        Gruppenrichtlinie = $g.Name; Status = Status $g; 'Aktive Verknüpfungen' = @($aktiveLinks | Where-Object Guid -eq $g.Guid).Count
        Computereinstellungen = $(if ($g.InhaltBekannt) { $g.InhaltC -join ', ' } else { 'nicht lesbar' }); Benutzereinstellungen = $(if ($g.InhaltBekannt) { $g.InhaltB -join ', ' } else { 'nicht lesbar' })
        'Version C/B' = "$($g.VerC) / $($g.VerB)"; 'WMI-Filter' = $(if ($g.Filter -and $wmi.ContainsKey($g.Filter)) { $wmi[$g.Filter].Name } else { '' })
        Angelegt = Datum $g.Angelegt; Geändert = Datum $g.Geaendert; Kennung = $g.Guid
    }
}
$linkListe = $links | ForEach-Object { LZeile $_ }
$umgebung = [ordered]@{
    'Domäne (NetBIOS)'            = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Gruppenrichtlinien'          = "$($gpos.Count), davon $(@($gpos | Where-Object { @($aktiveLinks | Where-Object Guid -eq $_.Guid).Count }).Count) aktiv verknüpft"
    'Verknüpfungen (aktiv / gesamt)' = "$(@($links | Where-Object Aktiv).Count) / $($links.Count)"
    'Organisationseinheiten / Standorte' = "$(@($orte | Where-Object Art -eq 'OU').Count) / $(@($orte | Where-Object Art -eq 'Standort').Count)"
    'WMI-Filter'                  = $wmi.Count
    'Inhalt gelesen von'          = $(if ($inhaltVon) { $inhaltVon } else { 'nicht lesbar' })
    'SYSVOL verglichen auf'       = $(if ($svStand.Count) { ($svStand | ForEach-Object { $_.DC }) -join ', ' } else { '-' })
}
# Ohne Adminrechte sind Richtlinien, die das Konto nicht lesen darf, im Verzeichnis unsichtbar. Man erkennt sie nur an Verknüpfungen (F1) und SYSVOL-Ordnern (F4),
# zu denen kein Objekt sichtbar ist. Die inhaltlichen Prüfpunkte wissen nichts von ihnen: nicht als "ohne Befund" ausweisen.
$istAdmin = $false
if ($Anmeldung) {
    # Mit -Anmeldung: gehört das Anmeldekonto (auch verschachtelt) zu den Administratoren? Dann ist nicht Sichtbares sicher gelöscht, nicht unlesbar.
    try { $kn = ("$($Anmeldung.UserName)" -replace '^.*\\', '') -replace '@.*$', ''; $istAdmin = $adminSid.ContainsKey((Get-ADUser -Identity $kn @ad).SID.Value) } catch { }
} else { try { $istAdmin = @([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -in "$sid-512", 'S-1-5-32-544' }).Count -gt 0 } catch { } }
if (-not $istAdmin) {
    $unsichtbar = @(@($links | Where-Object { -not $_.Vorhanden -and -not $_.Fremd } | ForEach-Object { $_.Guid }) + @($f4 | ForEach-Object { $_.Ordner }) | Where-Object { $_ } | Select-Object -Unique)
    if ($unsichtbar.Count) {
        NichtGeprueft '^(F[5-8]|S[1-3]|G\d+|A\d+)$' $unsichtbar 'F1 und F4' 'Gruppenrichtlinie' 'Richtlinie für dieses Konto nicht lesbar oder gelöscht'
    }
}
InfoWennNurNichtGeprueft '^(S1|S3|F[5-8]|G\d+|A\d+)$'
$basis = BerichtSchreiben -Name 'GPO-Bericht Light' -Datei 'GPO-Bericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ 'Alle Gruppenrichtlinien' = ($liste | Select-Object * -ExcludeProperty Kennung, Angelegt); 'Verknüpfungen nach Ort (Reihenfolge 1 = höchste Priorität)' = $linkListe }) `
    -Fuss 'Light-Version mit 6 von 26 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/wdosl). Der Inhalt der Richtlinien wird aus den Dateien in SYSVOL abgeleitet; einzelne Einstellungen bewertet der Bericht nicht. Er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.'
if ($Csv) {
    $liste | Export-Csv -Path "${basis}_Gruppenrichtlinien.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    $linkListe | Export-Csv -Path "${basis}_Verknuepfungen.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
