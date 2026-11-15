<#
.SYNOPSIS
    LIGHT VERSION (6 of 26 checks, free). GPO report: lists all Group Policy objects in a domain with content and links and checks them for errors,
    security vulnerabilities and legacy issues. The result is an HTML report.

    Deutsch:
    LIGHT-VERSION (6 von 26 Prüfpunkten, kostenlos). GPO-Bericht: listet alle Gruppenrichtlinien einer Domäne mit Inhalt und Verknüpfungen und prüft sie auf Fehler,
    Sicherheitslücken und Altlasten. Ergebnis ist ein HTML-Bericht.

.DESCRIPTION
    The script operates exclusively in READ-ONLY mode. It changes no Group Policy object, no link, and nothing
    in Active Directory or SYSVOL, and it transfers no data. It writes exactly one HTML file (and, if
    requested, CSV files) to the specified output folder.

    Prerequisites: Windows PowerShell 5.1, the module "ActiveDirectory" and a domain account with read permissions.
    Group Policy Management (GPMC) is not required: The script reads the Group Policy objects directly from the
    directory and from the SYSVOL share. Administrator rights are not required; Group Policy objects that the
    account running the script cannot read are then missing from the report.

    Deutsch:
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Gruppenrichtlinie, keine Verknüpfung und nichts
    im Active Directory oder in SYSVOL und überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf
    Wunsch CSV-Dateien) in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" und ein Domänenkonto mit Leserechten.
    Die Gruppenrichtlinienverwaltung (GPMC) wird nicht benötigt: Das Skript liest die Richtlinien direkt aus dem
    Verzeichnis und aus der Freigabe SYSVOL. Administratorrechte sind nicht erforderlich; Richtlinien, die das
    ausführende Konto nicht lesen darf, fehlen dann im Bericht.

.PARAMETER Ausgabe
    Path to the HTML file. Default: GPO-Bericht_<Domäne>_<Datum>.html in the current folder.

    Deutsch:
    Pfad der HTML-Datei. Standard: GPO-Bericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER OhneDcVergleich
    Read SYSVOL only on one domain controller instead of on all (f faster, but without comparing the versions).

    Deutsch:
    SYSVOL nur auf einem Domänencontroller lesen statt auf allen (schneller, aber ohne Vergleich der Stände).

.PARAMETER Server
    Specific domain controller or domain (optional).

    Deutsch:
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Credentials for a domain account (Get-Credential), if the script is not running as a domain user.
    Then also specify -Server.

    Deutsch:
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft.
    Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Writes a CSV file with the list of all Group Policy objects, all links, and each check point with matches.

    Deutsch:
    Schreibt die Liste aller Richtlinien, alle Verknüpfungen und je Prüfpunkt mit Treffern eine CSV-Datei.

.PARAMETER NichtOeffnen
    Does not open the finished report automatically in the browser.

    Deutsch:
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Returns the findings additionally as objects (for custom analysis).

    Deutsch:
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.PARAMETER Language
    Language of the report and the console output: 'de' (German) or 'en' (English). Default: German if the Windows display language
    is German, otherwise English.

    Deutsch:
    Sprache von Bericht und Konsolenausgabe: 'de' (Deutsch) oder 'en' (Englisch). Standard: Deutsch, wenn die Anzeigesprache von
    Windows Deutsch ist, sonst Englisch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\GPO-Bericht.ps1

.EXAMPLE
    .\GPO-Bericht.ps1 -Csv -Ausgabe C:\Berichte\gpo.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' }),
    [Alias('Output')][string]$Ausgabe,
    [switch]$OhneDcVergleich,
    [string]$Server,
    [Alias('Credential')][System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [Alias('NoOpen')][switch]$NichtOeffnen,
    [switch]$PassThru
)
# Sprache des Berichts: de oder en (Parameter -Language). T 'deutsch' 'english' liefert den Text der gewählten Sprache.
$En = ($Language -eq 'en')
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

$ErrorActionPreference = 'Stop'
$Version = '1.1'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host (T 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.' 'Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services".')
    Write-Host (T 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell' 'Windows Server: Install-WindowsFeature RSAT-AD-PowerShell')
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

#@SPRACHE@
# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
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
        if ($alle.Count) { $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }   # leere Liste: keine Datei (sie hätte keine Kopfzeile)
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -ge 2) {
        $namen = New-Object System.Collections.Generic.List[string]
        foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
        if ($namen.Count -ne @($liste[0].PSObject.Properties.Name).Count) { $liste = @($liste | Select-Object -Property $namen) }
    }
    SpaltenAnzeige $liste
}
# Englische Berichte: Spaltenüberschriften aus der Übersetzungstabelle (intern bleiben die deutschen Namen, der Code liest sie weiter)
$SpaltenEn = @{
    'Abfrage' = 'Query'
    'Administrator' = 'Administrator'
    'Adresse' = 'Address'
    'Aktiv' = 'Active'
    'Aktiv verknüpft mit' = 'Active linked to'
    'Aktive Verknüpfungen' = 'Active links'
    'Alter in Tagen' = 'Age in days'
    'Angelegt' = 'Created'
    'Anmeldung' = 'Last logon'
    'Anmeldungen' = 'Logons'
    'Anteil (%)' = 'Share (%)'
    'Anzahl' = 'Count'
    'Art' = 'Account type'
    'Auf Domänencontroller' = 'On domain controller'
    'Aufräumen' = 'Cleanup'
    'Auslastung' = 'Utilization'
    'Auslösender Rechner' = 'Triggering computer'
    'Auslösender Rechner (Anzahl)' = 'Triggering computers (count)'
    'Aussteller' = 'Issuer'
    'Beispiele' = 'Examples'
    'Belegt' = 'Used'
    'Belegt (%)' = 'Used (%)'
    'Benutzer und Computer (auch verschachtelt)' = 'Users and computers (also nested)'
    'Benutzereinstellungen' = 'User settings'
    'Benutzername' = 'Username'
    'Berechtigter' = 'Principal'
    'Bereich' = 'Scope'
    'Bereiche' = 'Scopes'
    'Beschreibung' = 'Description'
    'Besitzer' = 'Owner'
    'Betriebssystem' = 'OS'
    'Betroffene Konten' = 'Affected accounts'
    'Bewertung' = 'Rating'
    'Bis' = 'To'
    'BitLocker' = 'BitLocker'
    'Computer' = 'Computer'
    'Computereinstellungen' = 'Computer settings'
    'Darf anwenden' = 'Can apply'
    'Darf delegieren an' = 'Can delegate to'
    'Darf sich hier als Benutzer ausgeben' = 'Can log on as user'
    'Datei' = 'File'
    'Dateien' = 'Files'
    'Dateisystem' = 'File system'
    'Dateityp' = 'File type'
    'Datenbank' = 'Database'
    'Detail' = 'Detail'
    'Details' = 'Details'
    'Direkte Mitglieder' = 'Direct members'
    'Domäne' = 'Domain'
    'Domänencontroller' = 'Domain controller'
    'Domänennamenmaster' = 'Domain naming master'
    'Dynamische Updates' = 'Dynamic updates'
    'E-Mail' = 'Email'
    'Eigenschaft' = 'Property'
    'Einstellung' = 'Setting'
    'Empfohlen' = 'Recommended'
    'Enthaltene Gruppen' = 'Included groups'
    'Ereignisse' = 'Events'
    'Erreichbar' = 'Reachable'
    'Erste' = 'First'
    'Erster' = 'First'
    'Erzwungen' = 'Forced'
    'Failover' = 'Failover'
    'Falsches Kennwort' = 'Wrong password'
    'Fehlanmeldungen am DC' = 'Failed logons at DC'
    'Fehlversuche' = 'Failed attempts'
    'Feststellung' = 'Finding'
    'Fingerabdruck' = 'Fingerprint'
    'Firewall' = 'Firewall'
    'Frei' = 'Free'
    'Freigabe' = 'Share'
    'Freigaberecht' = 'Share permission'
    'Funktion' = 'Function'
    'Gelesen von' = 'Read by'
    'Geprüft' = 'Checked'
    'Gesamtgröße' = 'Total size'
    'Geschützte Benutzer' = 'Protected users'
    'Gesperrt seit' = 'Locked since'
    'Geändert' = 'Changed'
    'Gilt' = 'Applies to'
    'Gilt für' = 'Applies to'
    'Globaler Katalog' = 'Global catalog'
    'Grenze' = 'Limit'
    'Groesse' = 'Size'
    'Grund' = 'Reason'
    'Gruppe' = 'Group'
    'Gruppen' = 'Groups'
    'Gruppen (auch verschachtelt)' = 'Groups (including nested)'
    'Gruppenrichtlinie' = 'Group policy'
    'Größe' = 'Size'
    'Größe (GB)' = 'Size (GB)'
    'Gültig ab' = 'Valid from'
    'Gültig bis' = 'Valid to'
    'Herkunft' = 'Origin'
    'Hersteller' = 'Vendor'
    'Hinweis' = 'Note'
    'Häufigster Grund' = 'Most common reason'
    'IP-Adresse' = 'IP address'
    'Im AD gespeichert' = 'Stored in AD'
    'In der Domäne vorhanden' = 'Present in domain'
    'Infrastrukturmaster' = 'Infrastructure master'
    'Inhalt' = 'Content'
    'Ist' = 'Is'
    'Kennung' = 'ID'
    'Kennwort gesetzt' = 'Password set'
    'Kennwort läuft nie ab' = 'Password never expires'
    'Kerberos' = 'Kerberos'
    'Konten' = 'Accounts'
    'Konten (auch verschachtelt)' = 'Accounts (also nested)'
    'Konto' = 'Account'
    'Konto für DNS-Einträge' = 'Account for DNS entries'
    'Kopie bleibt im Postfach' = 'Copy remains in mailbox'
    'LAPS' = 'LAPS'
    'LAPS-Ablauf' = 'LAPS expiry'
    'Laufwerk' = 'Drive'
    'Lease-Dauer' = 'Lease duration'
    'Leitet weiter an' = 'Forwards to'
    'Leseweg' = 'Read path'
    'Letzte Aktualisierung' = 'Last update'
    'Letzte Anmeldung' = 'Last logon'
    'Letzte Vollsicherung' = 'Last full backup'
    'Letzte inkrementelle Sicherung' = 'Last incremental backup'
    'Letzter' = 'Last'
    'Letzter Aufräumlauf' = 'Last cleanup run'
    'Letzter Start' = 'Last start'
    'Lokale Admins' = 'Local admins'
    'Mindestlänge' = 'Minimum length'
    'Mitglied' = 'Member'
    'Mitglieder' = 'Members'
    'NLA' = 'NLA'
    'NTLM' = 'NTLM'
    'Name' = 'Name'
    'Nr.' = 'No.'
    'Objekt' = 'Object'
    'Ordner' = 'Folder'
    'Organisationseinheit' = 'OU'
    'Ort' = 'Location'
    'PDC-Emulator' = 'PDC emulator'
    'Pfad' = 'Path'
    'Postfach' = 'Mailbox'
    'Postfach-Typ' = 'Mailbox type'
    'Postfachtyp' = 'Mailbox type'
    'Postfächer' = 'Mailboxes'
    'Privilegierte Gruppen' = 'Privileged groups'
    'Programm' = 'Program'
    'Prüfpunkt' = 'Checkpoint'
    'Quelle' = 'Source'
    'Quelle (Anzahl)' = 'Sources (count)'
    'RID-Master' = 'RID master'
    'Recht' = 'Permission'
    'Rechte' = 'Permissions'
    'Regel' = 'Rule'
    'Reihenfolge' = 'Order'
    'SPN' = 'SPN'
    'Schemamaster' = 'Schema master'
    'Schlüssel' = 'Key'
    'Schreibgeschützt' = 'Read-only'
    'Sendesperre ab' = 'Send blocked from'
    'Server' = 'Server'
    'Sid' = 'SID'
    'Signatur' = 'Signature'
    'Speicher' = 'Storage'
    'Sperrungen' = 'Lockouts'
    'Stand' = 'Status'
    'Standort' = 'Site'
    'Status' = 'Status'
    'Support-Ende' = 'End of support'
    'Support-Ende (spätestes)' = 'End of support (latest)'
    'Tage bis Ablauf' = 'Days until expiry'
    'Tage her' = 'Days ago'
    'Tage ohne Anmeldung' = 'Days without logon'
    'Tage seit Ablauf' = 'Days since expiry'
    'Treffer' = 'Hits'
    'Typ' = 'Type'
    'Vererbung' = 'Inheritance'
    'Verschiedene Konten' = 'Distinct accounts'
    'Verschlüsselt' = 'Encrypted'
    'Version' = 'Version'
    'Version C/B' = 'Version C/B'
    'Verweigert für' = 'Denied for'
    'Verwendung' = 'Use'
    'Virenschutz' = 'Antivirus'
    'Von' = 'From'
    'WMI-Filter' = 'WMI filter'
    'Weg' = 'Path'
    'Weiterleitungen' = 'Forwarding'
    'Wert' = 'Value'
    'Wirksame Richtlinie' = 'Effective policy'
    'Wirksames Recht' = 'Effective permission'
    'Wirkung' = 'Effect'
    'Zeit' = 'Time'
    'Zeitpunkt' = 'Time'
    'Zeitraum' = 'Period'
    'Zertifikat' = 'Certificate'
    'Zone' = 'Zone'
    'Zonen' = 'Zones'
    'Zonenübertragung' = 'Zone transfer'
    'Zugriff für große Gruppen' = 'Access for large groups'
    'Zugriffsbasierte Aufzählung' = 'Access-based enumeration'
    'Zuletzt' = 'Last'
    'Zustand' = 'State'
    'davon Größe (GB)' = 'Of which size (GB)'
    'davon aktiv' = 'Of which active'
    'davon inaktiv' = 'Of which inactive'
    'davon unbekannte Konten' = 'Of which unknown accounts'
    'ist Mitglied von' = 'Member of'
    'Älter als 5 Jahre' = 'Older than 5 years'
    'Älter als 5 Jahren' = 'Older than 5 years'
    'Ältester Eintrag' = 'Oldest entry'
    'Über' = 'Via'
    'Überwachungsprotokoll' = 'Audit log'
}
# Werte, die der Code intern auf Deutsch vergleicht (z. B. Art = 'Benutzer'), erscheinen im englischen Bericht übersetzt (nur Anzeige und CSV)
$WerteEn = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)   # Groß-/Kleinschreibung zählt (Verwaist / verwaist)
$WerteEn.Add('Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)', 'All extended rights (including password reset)')
$WerteEn.Add('Kein Serverbetriebssystem (Support nicht bewertet)', 'No server operating system (support not assessed)')
$WerteEn.Add('Rechte je Ordner (nur dort, wo sie gesetzt werden)', 'Permissions per folder (only where set)')
$WerteEn.Add('Mehrfach freigegebene Ordner (nur einmal gezählt)', 'Folders shared multiple times (counted only once)')
$WerteEn.Add('Übersprungene Verknüpfungen (Junctions/Symlinks)', 'Skipped links (Junctions/Symlinks)')
$WerteEn.Add('Der Ordner der Freigabe existiert nicht mehr.', 'The share folder no longer exists.')
$WerteEn.Add('DHCP-Überwachungsprotokoll ist ausgeschaltet', 'DHCP audit log is disabled')
$WerteEn.Add('Vollzugriff und "Senden als" im Überblick', 'Full access and "Send as" overview')
$WerteEn.Add('Ordner der Freigabe existiert nicht mehr', 'Share folder no longer exists')
$WerteEn.Add('Enthält außer Sicherheitseinstellungen:', 'Contains except security settings:')
$WerteEn.Add('Nicht geprüft - Postfach nicht gefunden', 'Not checked - mailbox not found')
$WerteEn.Add('WMI-Filter nicht lesbar - nicht geprüft', 'WMI filter not readable - not checked')
$WerteEn.Add('Abfrage fehlgeschlagen - nicht geprüft', 'Query failed - not checked')
$WerteEn.Add('Nicht im Active Directory gespeichert', 'Not stored in Active Directory')
$WerteEn.Add('keine im Active Directory autorisiert', 'None authorized in Active Directory')
$WerteEn.Add('Zugriff auf den Ordner nicht möglich', 'Access to folder not possible')
$WerteEn.Add('Zertifikate (öffentliche Schlüssel)', 'Certificates (public keys)')
$WerteEn.Add('Domänencontroller der Organisation', 'Organization domain controllers')
$WerteEn.Add('Remotedesktop erlaubt Verbindungen', 'Remote Desktop allows connections')
$WerteEn.Add('autorisierte DHCP-Server ermitteln', 'Determine authorized DHCP servers')
$WerteEn.Add('Windows Server 2008 R2 und älter', 'Windows Server 2008 R2 and older')
$WerteEn.Add('Konto deaktiviert oder gesperrt', 'Account disabled or locked')
$WerteEn.Add('Vollzugriff (Zusatz: ObjectType', 'Full access (additional: ObjectType')
$WerteEn.Add('Kennwort oder Konto abgelaufen', 'Password or account expired')
$WerteEn.Add('Lokale Administratorengruppen', 'Local administrator groups')
$WerteEn.Add('Berechtigungen/Besitz ändern', 'Change permissions/ownership')
$WerteEn.Add('Freigabepfade nicht sichtbar', 'Share paths not visible')
$WerteEn.Add('Aktive privilegierte Konten', 'Active privileged accounts')
$WerteEn.Add('Gruppe hat keine Mitglieder', 'Group has no members')
$WerteEn.Add('Keine Verbindung zum Server', 'No connection to server')
$WerteEn.Add('unerlaubte Zeichen im Namen', 'Illegal characters in name')
$WerteEn.Add('Geprüfte Domänencontroller', 'Checked domain controllers')
$WerteEn.Add('Authentifizierte Benutzer', 'Authenticated Users')
$WerteEn.Add('Schwellen dieses Berichts', 'Thresholds of this report')
$WerteEn.Add('Benutzer (inetOrgPerson)', 'User (inetOrgPerson)')
$WerteEn.Add('Datenbestand je Freigabe', 'Data inventory per share')
$WerteEn.Add('Kontosperrungsrichtlinie', 'Account lockout policy')
$WerteEn.Add('Sicherheitseinstellungen', 'Security settings')
$WerteEn.Add('Alle erweiterten Rechte', 'All extended rights')
$WerteEn.Add('Hinweise zur Auswertung', 'Notes for evaluation')
$WerteEn.Add('Nicht abgefragte Server', 'Servers not queried')
$WerteEn.Add('Unterordner und Dateien', 'Subfolders and files')
$WerteEn.Add('Bestätigtes Schreiben:', 'Validated write:')
$WerteEn.Add('Installierte Programme', 'Installed programs')
$WerteEn.Add('Konto für DNS-Einträge', 'Account for DNS records')
$WerteEn.Add('Kontosperrungsschwelle', 'Account lockout threshold')
$WerteEn.Add('Nicht lesbare Bereiche', 'Unreadable areas')
$WerteEn.Add('Berechtigungen ändern', 'Change permissions')
$WerteEn.Add('Hinweise zum Auslesen', 'Notes for reading')
$WerteEn.Add('Windows 8.1 und älter', 'Windows 8.1 and older')
$WerteEn.Add('Überwachungsprotokoll', 'Audit log')
$WerteEn.Add('Nicht berücksichtigt', 'Not considered')
$WerteEn.Add('Anonymous-Anmeldung', 'Anonymous logon')
$WerteEn.Add('Infrastrukturmaster', 'Infrastructure master')
$WerteEn.Add('Secure Boot ist aus', 'Secure Boot is off')
$WerteEn.Add('Domänennamenmaster', 'Domain naming master')
$WerteEn.Add('Kennwortrichtlinie', 'Password policy')
$WerteEn.Add('Komponentenwartung', 'Component servicing')
$WerteEn.Add('alle Eigenschaften', 'all properties')
$WerteEn.Add('Besitz übernehmen', 'Take ownership')
$WerteEn.Add('Domänencontroller', 'Domain Controllers')
$WerteEn.Add('Falsches Kennwort', 'Incorrect password')
$WerteEn.Add('Konten-Operatoren', 'Account Operators')
$WerteEn.Add('Nur dieser Ordner', 'Only this folder')
$WerteEn.Add('Domänen-Benutzer', 'Domain Users')
$WerteEn.Add('Format unbekannt', 'Format unknown')
$WerteEn.Add('Sonstige Dateien', 'Other files')
$WerteEn.Add('Ältester Eintrag', 'Oldest entry')
$WerteEn.Add('Domänencomputer', 'Domain Computers')
$WerteEn.Add('Konto unbekannt', 'Account unknown')
$WerteEn.Add('Standard (alle)', 'Default (all)')
$WerteEn.Add('Computerkonten', 'Computer accounts')
$WerteEn.Add('Konto gesperrt', 'Account locked')
$WerteEn.Add('Nicht erreicht', 'Not reached')
$WerteEn.Add('DHCP-Bereiche', 'DHCP scopes')
$WerteEn.Add('Dieser Ordner', 'This folder')
$WerteEn.Add('Gruppe/System', 'Group/system')
$WerteEn.Add('Remotedesktop', 'Remote Desktop')
$WerteEn.Add('Arbeitsplatz', 'Workstation')
$WerteEn.Add('Schemamaster', 'Schema master')
$WerteEn.Add('DHCP-Server', 'DHCP server')
$WerteEn.Add('Datenbanken', 'Databases')
$WerteEn.Add('Sonderkonto', 'Special account')
$WerteEn.Add('Unterordner', 'Subfolders')
$WerteEn.Add('Vollzugriff', 'Full control')
$WerteEn.Add('Zugriff von', 'Access from')
$WerteEn.Add('DNS-Server', 'DNS server')
$WerteEn.Add('Inaktiv ab', 'Inactive from')
$WerteEn.Add('Schreiben:', 'Write:')
$WerteEn.Add('Verweigern', 'Deny')
$WerteEn.Add('DNS-Zonen', 'DNS zones')
$WerteEn.Add('Schreiben', 'Write')
$WerteEn.Add('Sonstiges', 'Other')
$WerteEn.Add('Standorte', 'Sites')
$WerteEn.Add('Unbekannt', 'Unknown')
$WerteEn.Add('unbekannt', 'unknown')
$WerteEn.Add('(Wurzel)', '(root)')
$WerteEn.Add('Anlegen:', 'Create:')
$WerteEn.Add('Benutzer', 'User')
$WerteEn.Add('Erlauben', 'Allow')
$WerteEn.Add('Netzwerk', 'Network')
$WerteEn.Add('Verwaist', 'Orphaned')
$WerteEn.Add('verwaist', 'orphaned')
$WerteEn.Add('Dateien', 'Files')
$WerteEn.Add('Gruppen', 'Groups')
$WerteEn.Add('Anonym', 'Anonymous')
$WerteEn.Add('Domäne', 'Domain')
$WerteEn.Add('Gruppe', 'Group')
$WerteEn.Add('Umfang', 'Scope')
$WerteEn.Add('direkt', 'direct')
$WerteEn.Add('Ändern', 'Change')
$WerteEn.Add('Lesen', 'Read')
$WerteEn.Add('über', 'via')
$WerteMuster = @()
foreach ($k in ($WerteEn.Keys | Sort-Object Length -Descending)) { $WerteMuster += , @([regex]::new('(?<![\p{L}\d])' + [regex]::Escape($k) + '(?![\p{L}\d])'), $WerteEn[$k]) }
function WertAnzeige($v) {
    if (-not $script:En -or $v -isnot [string] -or -not $v) { return $v }
    if ($v.Contains('\')) { return $v }   # Kontonamen (DOMÄNE\Name) und Pfade bleiben, wie sie sind
    foreach ($m in $WerteMuster) { $v = $m[0].Replace($v, $m[1]) }
    $v
}
function SpaltenAnzeige($liste) {
    if (-not $script:En -or -not @($liste).Count) { return $liste }
    foreach ($o in @($liste)) {
        $n = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $k = $p.Name; if ($SpaltenEn.ContainsKey($k)) { $k = $SpaltenEn[$k] }; $i = 2; $k0 = $k; while ($n.Contains($k)) { $k = "$k0 $i"; $i++ }; $n[$k] = WertAnzeige $p.Value }
        [pscustomobject]$n
    }
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
# Deutsch und Englisch: Skripte erzeugen den Text je nach -Language, erkannt werden beide Fassungen
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft',
    'Query failed - not checked', 'Permissions not readable - not checked', 'SYSVOL not readable - not checked', 'WMI filter not readable - not checked', 'No domain controller found - SYSVOL not checked', 'Folder content not readable - policy not checked')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *') -or ("$($o.Feststellung)" -clike 'Not checked - *')
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
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = $(T 'Abfrage nicht möglich' 'query not possible')) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = (T "Nicht geprüft - $Grund (siehe $Verweis)" "Not checked - $Grund (see $Verweis)"); Details = '' } })
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
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = $(T 'Domäne' 'Domain'), [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
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
    [void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html "$env:USERDOMAIN\$env:USERNAME") $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); Info = (T 'Hinweise und nicht geprüft' 'notes and not checked'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html (WertAnzeige $k))</td><td>$(Html (WertAnzeige $Umgebung[$k]))</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html (WertAnzeige $k))</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>$(T 'Keine Einträge.' 'No entries.')</p>") }
    }

    [void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>$(T 'Keine Auffälligkeiten gefunden.' 'No anomalies found.')</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert.' 'The script only read and changed nothing.') $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host ((T 'Bericht' 'Report') + ": $ziel")
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

# ------------------------------------------------------------------ Daten aus dem Verzeichnis
Write-Host (T 'GPO-Bericht - es wird nur gelesen, nichts verändert.' 'GPO report - read-only, nothing is changed') -ForegroundColor Cyan
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
$jedermann = @{ 'S-1-1-0' = 'Jeder'; 'S-1-5-11' = (T 'Authentifizierte Benutzer' 'Authenticated Users'); 'S-1-5-7' = 'Anonymous-Anmeldung'; 'S-1-5-32-545' = (T 'Benutzer' 'User'); "$sid-513" = 'Domänen-Benutzer'; "$sid-515" = 'Domänencomputer'; 'S-1-5-32-554' = (T 'Prä-Windows 2000 kompatibler Zugriff' 'Pre-Windows 2000 compatible access') }
$bekannt = @{ 'S-1-5-18' = 'SYSTEM'; 'S-1-3-0' = (T 'ERSTELLER-BESITZER' 'Creator Owner'); 'S-1-5-9' = 'Domänencontroller der Organisation' }
foreach ($k in $jedermann.Keys) { $bekannt[$k] = $jedermann[$k] }
$sidCache = @{}
function Wer($s) {
    $s = "$s"
    if (-not $sidCache.ContainsKey($s)) {
        $o = $null
        if ($bekannt.ContainsKey($s)) { $sidCache[$s] = $bekannt[$s] }
        else {
            try { $o = Get-ADObject -LDAPFilter "(objectSid=$s)" -Properties sAMAccountName @ad } catch { }
            $sidCache[$s] = if ($o -and $o.sAMAccountName) { $o.sAMAccountName } elseif ($o) { $o.Name } elseif ($s -like 'S-1-5-21-*') { (T "$s (Konto gelöscht)" "$s (account deleted)") } else { $s }
        }
    }
    $sidCache[$s]
}

Write-Host (T '  Gruppenrichtlinien ...' '  Group policies ...')
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
                if (($r -band $R::WriteProperty) -and $ot -eq $leer) { $t += (T 'Einstellungen bearbeiten' 'Edit settings') }
                if ($r -band $R::WriteDacl) { $t += (T 'Berechtigungen ändern' 'Change permissions') }
                if ($r -band $R::WriteOwner) { $t += (T 'Besitz übernehmen' 'Take ownership') }
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
Write-Host (T '  Verknüpfungen ...' 'Links ...')
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
$einstellungName = @{ Drives = 'Laufwerke'; Printers = 'Drucker'; Files = 'Dateien'; Folders = (T 'Ordner' 'Folder'); Registry = 'Registrierung'; Shortcuts = (T 'Verknüpfungen' 'Links')
    Groups = (T 'Lokale Benutzer und Gruppen' 'Local users and groups'); ScheduledTasks = (T 'Geplante Aufgaben' 'Scheduled tasks'); Services = 'Dienste'; EnvironmentVariables = 'Umgebungsvariablen'
    IniFiles = (T 'INI-Dateien' 'INI files'); InternetSettings = 'Interneteinstellungen'; FolderOptions = 'Ordneroptionen'; PowerOptions = 'Energieoptionen'
    NetworkShares = 'Netzwerkfreigaben'; NetworkOptions = 'Netzwerkoptionen'; DataSources = 'Datenquellen'; Devices = (T 'Geräte' 'Devices')
    StartMenuTaskbar = (T 'Startmenü' 'Start menu'); RegionalOptions = (T 'Regionale Einstellungen' 'Regional Settings')
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
            if (-not $schluessel.Count -or @($schluessel | Where-Object { $_ -notlike 'Software\Policies\Microsoft\SystemCertificates*' }).Count) { (T 'Administrative Vorlagen' 'Administrative Templates') }
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
        } elseif ($rel -match 'Audit\\audit\.csv$') { if ($f.Length -gt 200) { (T 'Erweiterte Überwachung' 'Advanced monitoring') } }
        elseif ($rel -match '^Scripts\\(ps)?scripts\.ini$') { if ($f.Length -gt 10) { 'Skripte' } }
        elseif ($rel -match '^Scripts\\') { }
        elseif ($rel -match '^Preferences\\([^\\]+)\\.+\.xml$') {
            $art = $Matches[1]
            if (Select-String -LiteralPath $f.FullName -Pattern 'cpassword="[^"]+"' -Quiet) { $g.Kennwortdateien += "$seite\$rel" }
            (T 'Einstellungen: ' 'Settings:') + $(if ($einstellungName.ContainsKey($art)) { $einstellungName[$art] } else { $art })
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
    } catch { $svFehler += [pscustomobject]@{ Gruppenrichtlinie = (T '(alle)' '(all)'); Domänencontroller = $d.Name; Feststellung = (T 'SYSVOL nicht lesbar - nicht geprüft' 'SYSVOL not readable - not checked'); Details = Kurz $_.Exception.Message } }
}
if (-not $dcs.Count) { $svFehler += [pscustomobject]@{ Gruppenrichtlinie = (T '(alle)' '(all)'); Domänencontroller = '-'; Feststellung = (T 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft' 'No domain controller found - SYSVOL not checked'); Details = '' } }
foreach ($n in $laufwerke) { try { Remove-PSDrive -Name $n -Force } catch { } }
# Zeile für alle Prüfpunkte, die den Inhalt der Richtlinien brauchen. Einzelne nicht lesbare Richtlinien stehen unter F3.
$ohneInhalt = @()
if (-not $inhaltVon) { $ohneInhalt = @([pscustomobject]@{ Gruppenrichtlinie = (T '(alle)' '(all)'); Feststellung = (T 'SYSVOL nicht lesbar - nicht geprüft' 'SYSVOL not readable - not checked') }) }

function Status($g) { switch ($g.Flags -band 3) { 0 { 'Aktiv' } 1 { (T 'Benutzerteil aus' 'User Configuration disabled') } 2 { (T 'Computerteil aus' 'Computer Configuration disabled') } 3 { 'Deaktiviert' } } }
function GZeile($g, [System.Collections.IDictionary]$Zusatz = @{}) {
    $z = [ordered]@{ Gruppenrichtlinie = $g.Name; Status = Status $g; Geändert = Datum $g.Geaendert }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}
function Inhalt($g) {
    if (-not $g.InhaltBekannt) { return (T 'nicht lesbar' 'Not readable') }
    $t = @()
    if ($g.InhaltC.Count) { $t += (T 'Computer: ' 'Computer:') + ($g.InhaltC -join ', ') }
    if ($g.InhaltB.Count) { $t += (T 'Benutzer: ' 'User:') + ($g.InhaltB -join ', ') }
    if ($t.Count) { $t -join ' | ' } else { (T 'keine Einstellungen' 'No settings') }
}
function LZeile($l, [System.Collections.IDictionary]$Zusatz = @{}) {
    $z = [ordered]@{ Ort = $l.Ort; Gruppenrichtlinie = $l.Name; Reihenfolge = $l.Reihenfolge; Aktiv = JaNein $l.Aktiv; Erzwungen = JaNein $l.Erzwungen }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}
$aktiveLinks = @($links | Where-Object { $_.Aktiv -and $_.Vorhanden })
$domLinks = @($aktiveLinks | Where-Object Art -eq 'Domäne')

# ------------------------------------------------------------------ Prüfungen: Fehler
Write-Host (T '  Auswertung ...' '  Evaluation ...')
$f1 = @($links | Where-Object { -not $_.Vorhanden -and -not $_.Fremd } | ForEach-Object { LZeile $_ @{ Feststellung = (T 'Richtlinie gibt es nicht mehr oder sie ist für dieses Konto nicht lesbar' 'Policy no longer exists or is not readable for this account') } })
if ($standortFehler) { $f1 += [pscustomobject]@{ Ort = 'Standorte'; Gruppenrichtlinie = ''; Feststellung = (T 'Abfrage fehlgeschlagen - nicht geprüft' 'Query failed - not checked'); Details = $standortFehler } }
Befund 'F1' (T 'Fehler' 'Error') (T 'Verknüpfungen auf nicht vorhandene Gruppenrichtlinien' 'Links to nonexistent group policies') 'Mittel' $f1 `
    (T 'Die Verknüpfung zeigt auf eine Richtlinie, die es nicht mehr gibt - meist ein Überbleibsel nach dem Löschen. Läuft das Skript ohne Administratorrechte, kann es auch eine Richtlinie sein, die dieses Konto nicht lesen darf.' 'The link points to a policy that no longer exists - usually a leftover after deletion. If the script runs without administrator rights, it may also be a policy that this account is not allowed to read.') `
    (T 'Als Administrator gegenprüfen und verwaiste Verknüpfungen in der Gruppenrichtlinienverwaltung entfernen.' 'Check as an administrator and remove orphaned links in Group Policy Management.')

$f2 = @($svFehler)
$f3 = @()
$f4 = @()
foreach ($s in $svStand) {
    foreach ($g in $gpos) {
        if (-not $s.Version.ContainsKey($g.Guid)) { $f3 += [pscustomobject][ordered]@{ Gruppenrichtlinie = $g.Name; Domänencontroller = $s.DC; Feststellung = (T "Ordner $($g.Guid) fehlt in SYSVOL" "Folder $($g.Guid) missing in SYSVOL") }; continue }
        $sv = $s.Version[$g.Guid]
        if ($null -eq $sv) { $f3 += [pscustomobject][ordered]@{ Gruppenrichtlinie = $g.Name; Domänencontroller = $s.DC; Feststellung = (T "Datei GPT.INI fehlt oder ist nicht lesbar ($($g.Guid))" "GPT.INI file is missing or not readable ($($g.Guid))") }; continue }
        $svB = [int]($sv -shr 16); $svC = [int]($sv -band 0xFFFF)
        if ($svB -ne $g.VerB -or $svC -ne $g.VerC) {
            $f2 += [pscustomobject][ordered]@{ Gruppenrichtlinie = $g.Name; Domänencontroller = $s.DC; Feststellung = (T 'Stand in SYSVOL weicht vom Verzeichnis ab' 'State in SYSVOL differs from the directory')
                Details = (T "Verzeichnis: Computer $($g.VerC), Benutzer $($g.VerB) - SYSVOL: Computer $svC, Benutzer $svB" "Directory: computers $($g.VerC), users $($g.VerB) - SYSVOL: computers $svC, users $svB") }
        }
    }
    if ($s.DC -eq $inhaltVon) {
        $f3 += $gpos | Where-Object { -not $_.InhaltBekannt -and $s.Version.ContainsKey($_.Guid) } | ForEach-Object { [pscustomobject][ordered]@{ Gruppenrichtlinie = $_.Name; Domänencontroller = $s.DC; Feststellung = (T 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft' 'Folder content not readable - policy not checked') } }
    }
    foreach ($k in $s.Version.Keys) { if (-not $gpoNach.ContainsKey($k)) { $f4 += [pscustomobject]@{ Ordner = $k; DC = $s.DC } } }
}

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
$unlesbar = @($gpos | Where-Object { -not $_.Lesbar } | ForEach-Object { [pscustomobject][ordered]@{ Gruppenrichtlinie = $_.Name; Konto = ''; Rechte = (T 'Berechtigungen nicht lesbar - nicht geprüft' 'Permissions not readable - not checked'); 'Aktiv verknüpft mit' = '' } })
Befund 'S1' (T 'Sicherheit' 'Security') (T 'Jeder Benutzer darf die Richtlinie bearbeiten' 'All users may edit the policy') 'Hoch' ($s1 + $unlesbar) `
    (T 'Eine Sammelgruppe wie "Authentifizierte Benutzer" oder "Domänen-Benutzer" hat Schreibrechte auf diese Richtlinie. Jeder Angemeldete kann damit auf allen Rechnern, auf die sie wirkt, beliebige Programme mit Systemrechten ausführen.' 'A group such as "Authenticated Users" or "Domain Users" has write permissions on this policy. Any logged-on user can use it to run arbitrary programs with system privileges on all computers it applies to.') `
    (T 'Schreibrechte sofort entfernen (Registerkarte "Delegierung") und prüfen, ob die Richtlinie verändert wurde.' 'Remove write permissions immediately (tab "Delegation") and check whether the policy has been changed.')

# ------------------------------------------------------------------ Prüfungen: Aufräumen
$g1 = foreach ($g in $gpos) {
    $l = @($links | Where-Object Guid -eq $g.Guid)
    if (-not $l.Count) { GZeile $g ([ordered]@{ Inhalt = Inhalt $g; Feststellung = (T 'Nirgends verknüpft' 'Not linked anywhere') }) }
    elseif (-not @($l | Where-Object Aktiv).Count) { GZeile $g ([ordered]@{ Inhalt = Inhalt $g; Feststellung = (T 'Nur deaktivierte Verknüpfungen' 'Only disabled links') }) }
}
Befund 'G1' (T 'Aufräumen' 'Cleanup') (T 'Nicht verknüpfte Gruppenrichtlinien' 'Unlinked Group Policies') 'Niedrig' $g1 `
    (T 'Diese Richtlinien sind mit keiner Domäne, Organisationseinheit und keinem Standort aktiv verknüpft und wirken deshalb nirgends. Verknüpfungen aus anderen Domänen der Gesamtstruktur sieht das Skript nicht.' 'These policies are not actively linked to any domain, organizational unit, or site and therefore do not apply anywhere. Links from other domains in the forest are not visible to the script.') `
    (T 'Prüfen, ob die Richtlinie noch gebraucht wird (Vorlage, Test). Sonst sichern und löschen.' 'Check whether the policy is still needed (template, test). Otherwise, back it up and delete it.')

$g2 = @($ohneInhalt)
$g2 += $gpos | Where-Object { $_.InhaltBekannt -and -not $_.InhaltC.Count -and -not $_.InhaltB.Count } |
    ForEach-Object { GZeile $_ @{ Feststellung = $(if ($_.VerC -eq 0 -and $_.VerB -eq 0) { (T 'Wurde nie bearbeitet' 'Never edited') } else { (T 'Keine Einstellungen in SYSVOL gefunden' 'No settings found in SYSVOL') }) } }
Befund 'G2' (T 'Aufräumen' 'Cleanup') (T 'Leere Gruppenrichtlinien' 'Empty Group Policies') 'Niedrig' $g2 `
    (T 'In diesen Richtlinien wurden keine Einstellungen gefunden. Hinweis: WLAN-, IPsec- und Softwareeinschränkungs-Richtlinien liegen teils nur im Verzeichnis und werden hier nicht erkannt.' 'No settings were found in these policies. Note: WLAN, IPsec, and Software Restriction Policies are partly stored only in the directory and are not detected here.') `
    (T 'In der Gruppenrichtlinienverwaltung auf der Registerkarte "Einstellungen" gegenprüfen und leere Richtlinien löschen.' 'Check in Group Policy Management on the Settings tab and delete empty policies')

Befund 'G3' (T 'Aufräumen' 'Cleanup') (T 'Vollständig deaktivierte Gruppenrichtlinien' 'Fully disabled group policies') 'Niedrig' `
($gpos | Where-Object { ($_.Flags -band 3) -eq 3 } | ForEach-Object { GZeile $_ @{ Inhalt = Inhalt $_ } }) `
    (T 'Bei diesen Richtlinien sind Computer- und Benutzerteil abgeschaltet. Sie wirken nicht, auch wenn sie verknüpft sind.' 'For these policies, the computer and user portions are disabled. They do not apply even if they are linked.') `
    (T 'Wenn die Richtlinie nicht mehr gebraucht wird: sichern und löschen.' 'If the policy is no longer needed: back it up and delete it.')

$g5 = @(); $g6 = @()
$loopback = @($gpos | Where-Object Loopback)
foreach ($l in ($aktiveLinks | Where-Object Art -eq 'OU')) {
    $i = OuInhalt $l.OrtDN
    $g = $gpoNach[$l.Guid]
    if (-not $i.Benutzer -and -not $i.Computer) { $g5 += LZeile $l @{ Feststellung = (T 'Unterhalb liegen weder Benutzer noch Computer' 'No users or computers below') }; continue }
    if (-not $g.InhaltBekannt) { continue }
    $c = $g.InhaltC.Count -and -not ($g.Flags -band 2)
    $b = $g.InhaltB.Count -and -not ($g.Flags -band 1)
    if ($b -and -not $c -and -not $i.Benutzer) {
        $g6 += LZeile $l @{ Feststellung = (T 'Richtlinie enthält nur Benutzereinstellungen, unterhalb liegen nur Computer' 'Policy contains only user settings; only computers are located below') + $(if ($loopback.Count) { (T ' (wirkt nur mit Loopback-Verarbeitung, siehe A5)' '(applies only with loopback processing, see A5)') }) }
    } elseif ($c -and -not $b -and -not $i.Computer) { $g6 += LZeile $l @{ Feststellung = (T 'Richtlinie enthält nur Computereinstellungen, unterhalb liegen nur Benutzer' 'Policy contains only computer settings; only users are located below') } }
}

# ------------------------------------------------------------------ Aufbau (zur Kenntnis)
Befund 'A1' (T 'Aufbau' 'Structure') (T 'Erzwungene Verknüpfungen' 'Enforced links') 'Info' `
($links | Where-Object { $_.Erzwungen -and $_.Vorhanden } | ForEach-Object { LZeile $_ }) `
    (T 'Erzwungene Verknüpfungen setzen sich gegen alle Richtlinien darunter durch und ignorieren eine deaktivierte Vererbung. Sinnvoll für wenige Sicherheitsvorgaben - in größerer Zahl wird das Ergebnis schwer vorhersagbar.' 'Enforced links override all policies below them and ignore disabled inheritance. Useful for a few security requirements - with a larger number, the result becomes hard to predict') `
    (T 'Zur Kenntnis. Erzwingen sparsam einsetzen und dokumentieren.' 'Acknowledged. Use enforcement sparingly and document it.')

# ------------------------------------------------------------------ Bericht
$liste = $gpos | ForEach-Object {
    $g = $_
    [pscustomobject][ordered]@{
        Gruppenrichtlinie = $g.Name; Status = Status $g; 'Aktive Verknüpfungen' = @($aktiveLinks | Where-Object Guid -eq $g.Guid).Count
        Computereinstellungen = $(if ($g.InhaltBekannt) { $g.InhaltC -join ', ' } else { (T 'nicht lesbar' 'Not readable') }); Benutzereinstellungen = $(if ($g.InhaltBekannt) { $g.InhaltB -join ', ' } else { (T 'nicht lesbar' 'Not readable') })
        'Version C/B' = "$($g.VerC) / $($g.VerB)"; 'WMI-Filter' = $(if ($g.Filter -and $wmi.ContainsKey($g.Filter)) { $wmi[$g.Filter].Name } else { '' })
        Angelegt = Datum $g.Angelegt; Geändert = Datum $g.Geaendert; Kennung = $g.Guid
    }
}
$linkListe = $links | ForEach-Object { LZeile $_ }
$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)')            = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Gruppenrichtlinien' 'Group policies')          = (T "$($gpos.Count), davon $(@($gpos | Where-Object { @($aktiveLinks | Where-Object Guid -eq $_.Guid).Count }).Count) aktiv verknüpft" "$($gpos.Count), of which $(@($gpos | Where-Object { @($aktiveLinks | Where-Object Guid -eq $_.Guid).Count }).Count) actively linked")
    (T 'Verknüpfungen (aktiv / gesamt)' 'Links (active / total)') = "$(@($links | Where-Object Aktiv).Count) / $($links.Count)"
    (T 'Organisationseinheiten / Standorte' 'Organizational Units / Sites') = "$(@($orte | Where-Object Art -eq 'OU').Count) / $(@($orte | Where-Object Art -eq 'Standort').Count)"
    (T 'WMI-Filter' 'WMI filters')                  = $wmi.Count
    (T 'Inhalt gelesen von' 'Content read from')          = $(if ($inhaltVon) { $inhaltVon } else { (T 'nicht lesbar' 'Not readable') })
    (T 'SYSVOL verglichen auf' 'SYSVOL compared to')       = $(if ($svStand.Count) { ($svStand | ForEach-Object { $_.DC }) -join ', ' } else { '-' })
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
        NichtGeprueft '^(F[5-8]|S[1-3]|G\d+|A\d+)$' $unsichtbar 'F1 und F4' 'Gruppenrichtlinie' (T 'Richtlinie für dieses Konto nicht lesbar oder gelöscht' 'Policy not readable for this account or deleted')
    }
}
InfoWennNurNichtGeprueft '^(S1|S3|F[5-8]|G\d+|A\d+)$'
$basis = BerichtSchreiben -Name (T 'GPO-Bericht Light' 'GPO report Light') -Datei 'GPO-Bericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ (T 'Alle Gruppenrichtlinien' 'All Group Policies') = ($liste | Select-Object * -ExcludeProperty Kennung, Angelegt); (T 'Verknüpfungen nach Ort (Reihenfolge 1 = höchste Priorität)' 'Links by location (order 1 = highest priority)') = $linkListe }) `
    -Fuss (T 'Light-Version mit 6 von 26 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/wdosl). Der Inhalt der Richtlinien wird aus den Dateien in SYSVOL abgeleitet; einzelne Einstellungen bewertet der Bericht nicht. Er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.' 'Light version with 6 of 26 checks of the full version (https://mueller86.gumroad.com/l/wdosl). The contents of the policies are derived from files in SYSVOL; the report does not evaluate individual settings. It does not replace a security check and makes no claim to completeness.')
if ($Csv) {
    SpaltenAnzeige $liste | Export-Csv -Path "${basis}_Gruppenrichtlinien.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    SpaltenAnzeige $linkListe | Export-Csv -Path "${basis}_Verknuepfungen.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
