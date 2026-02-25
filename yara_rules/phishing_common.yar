/*
    PhishGuard Community YARA Rules — Phishing & Malware Indicators
    These rules detect common phishing patterns in email attachments.
*/

rule Phishing_HTML_Credential_Harvester
{
    meta:
        description = "HTML file with credential harvesting form elements"
        author = "PhishGuard"
        severity = "critical"
        category = "phishing"

    strings:
        $password_input = "<input" nocase
        $type_password = "type=\"password\"" nocase
        $type_password2 = "type='password'" nocase
        $form_tag = "<form" nocase
        $action = "action=" nocase
        $login_text = "login" nocase
        $signin_text = "sign in" nocase
        $verify_text = "verify" nocase

    condition:
        $form_tag and ($type_password or $type_password2) and $password_input and
        ($action or $login_text or $signin_text or $verify_text)
}

rule Phishing_HTML_Obfuscated_JS
{
    meta:
        description = "HTML file with obfuscated JavaScript commonly used in phishing kits"
        author = "PhishGuard"
        severity = "high"
        category = "phishing"

    strings:
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcharcode = "fromCharCode" nocase
        $atob = "atob(" nocase
        $document_write = "document.write(" nocase
        $base64_regex = /[A-Za-z0-9+\/]{50,}={0,2}/
        $hex_encoded = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/

    condition:
        ($eval or $document_write) and ($unescape or $fromcharcode or $atob or $base64_regex or $hex_encoded)
}

rule Phishing_HTML_Data_Exfil
{
    meta:
        description = "HTML file that sends form data to an external URL"
        author = "PhishGuard"
        severity = "critical"
        category = "phishing"

    strings:
        $form = "<form" nocase
        $method_post = "method=\"post\"" nocase
        $method_post2 = "method='post'" nocase
        $xhr = "XMLHttpRequest" nocase
        $fetch = "fetch(" nocase
        $ajax = "$.ajax" nocase
        $password = "password" nocase

    condition:
        ($form and ($method_post or $method_post2) and $password) or
        (($xhr or $fetch or $ajax) and $password)
}

rule Suspicious_VBA_AutoExec
{
    meta:
        description = "Office document with auto-execution VBA macros"
        author = "PhishGuard"
        severity = "high"
        category = "macro"

    strings:
        $auto1 = "Auto_Open" nocase
        $auto2 = "AutoOpen" nocase
        $auto3 = "AutoExec" nocase
        $auto4 = "Document_Open" nocase
        $auto5 = "Workbook_Open" nocase
        $auto6 = "AutoClose" nocase
        $vba = "VBA" nocase
        $shell = "Shell" nocase
        $wscript = "WScript" nocase
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase

    condition:
        $vba and any of ($auto*) and any of ($shell, $wscript, $powershell, $cmd)
}

rule Suspicious_VBA_Downloader
{
    meta:
        description = "VBA macro that downloads files from the internet"
        author = "PhishGuard"
        severity = "critical"
        category = "macro"

    strings:
        $vba = "VBA" nocase
        $urlmon = "URLDownloadToFile" nocase
        $xmlhttp = "XMLHTTP" nocase
        $winhttp = "WinHttp" nocase
        $inet = "InternetOpen" nocase
        $shell = "Shell" nocase
        $exec = "Exec" nocase
        $http = "http://" nocase
        $https = "https://" nocase

    condition:
        $vba and any of ($urlmon, $xmlhttp, $winhttp, $inet) and ($http or $https)
}

rule Suspicious_OLE_Embedded_Exe
{
    meta:
        description = "OLE document with embedded executable content"
        author = "PhishGuard"
        severity = "critical"
        category = "embedded"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $mz_header = "MZ"
        $pe_sig = "PE\x00\x00"
        $this_program = "This program cannot be run in DOS mode"

    condition:
        $ole_magic at 0 and ($mz_header and ($pe_sig or $this_program))
}

rule Suspicious_PDF_JavaScript
{
    meta:
        description = "PDF file containing JavaScript — potential exploit or redirect"
        author = "PhishGuard"
        severity = "high"
        category = "exploit"

    strings:
        $pdf_magic = "%PDF"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS " nocase
        $js3 = "/JS(" nocase
        $openaction = "/OpenAction" nocase
        $launch = "/Launch" nocase
        $aa = "/AA" nocase

    condition:
        $pdf_magic at 0 and any of ($js*) and any of ($openaction, $launch, $aa)
}

rule Suspicious_PDF_Embedded_File
{
    meta:
        description = "PDF with embedded file — potential dropper"
        author = "PhishGuard"
        severity = "medium"
        category = "embedded"

    strings:
        $pdf_magic = "%PDF"
        $ef = "/EmbeddedFile" nocase
        $filespec = "/Filespec" nocase
        $type = "/Type /Filespec" nocase

    condition:
        $pdf_magic at 0 and ($ef or ($filespec and $type))
}

rule Suspicious_Executable_Script
{
    meta:
        description = "Script file (JS/VBS/PS1) with suspicious patterns"
        author = "PhishGuard"
        severity = "high"
        category = "script"

    strings:
        $wscript_shell = "WScript.Shell" nocase
        $activex = "ActiveXObject" nocase
        $powershell_enc = "-EncodedCommand" nocase
        $powershell_bypass = "-ExecutionPolicy Bypass" nocase
        $hidden_window = "-WindowStyle Hidden" nocase
        $invoke_expr = "Invoke-Expression" nocase
        $iex = "IEX(" nocase
        $download = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $webclient = "Net.WebClient" nocase

    condition:
        any of ($wscript_shell, $activex) or
        ($powershell_enc or $powershell_bypass) and ($hidden_window or $invoke_expr or $iex) or
        ($webclient and ($download or $download2))
}

rule Phishing_HTML_Brand_Impersonation
{
    meta:
        description = "HTML file impersonating a well-known brand login page"
        author = "PhishGuard"
        severity = "high"
        category = "phishing"

    strings:
        $microsoft = "microsoft" nocase
        $office365 = "office365" nocase
        $outlook = "outlook" nocase
        $google = "google" nocase
        $gmail = "gmail" nocase
        $apple = "apple" nocase
        $paypal = "paypal" nocase
        $amazon = "amazon" nocase
        $netflix = "netflix" nocase
        $facebook = "facebook" nocase
        $password_field = "type=\"password\"" nocase
        $password_field2 = "type='password'" nocase
        $form = "<form" nocase

    condition:
        $form and ($password_field or $password_field2) and
        any of ($microsoft, $office365, $outlook, $google, $gmail,
                $apple, $paypal, $amazon, $netflix, $facebook)
}

rule Suspicious_ZIP_Bomb_Indicator
{
    meta:
        description = "Archive with suspicious compression ratio indicating possible zip bomb"
        author = "PhishGuard"
        severity = "medium"
        category = "evasion"

    strings:
        $pk_magic = { 50 4B 03 04 }
        $nested_zip = { 50 4B 03 04 [0-1024] 50 4B 03 04 [0-1024] 50 4B 03 04 }

    condition:
        $pk_magic at 0 and $nested_zip
}

rule Suspicious_RTF_Exploit
{
    meta:
        description = "RTF file with potential exploit (OLE objects or equation editor abuse)"
        author = "PhishGuard"
        severity = "critical"
        category = "exploit"

    strings:
        $rtf_magic = "{\\rtf" nocase
        $objdata = "\\objdata" nocase
        $objemb = "\\objemb" nocase
        $equation = "Equation" nocase
        $ole_package = "OLE2Link" nocase
        $d0cf = "d0cf11e0"

    condition:
        $rtf_magic at 0 and any of ($objdata, $objemb, $equation, $ole_package, $d0cf)
}
