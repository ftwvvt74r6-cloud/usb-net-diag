' ============================================================
'  USB-Net-Diag 停止器
'  界面右上角「退出」用不了时（比如浏览器已关），双击本文件即可
' ============================================================
Option Explicit

Dim fso, root, port, i, ok, http, url, pidFile, pid, shell

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

root = fso.GetParentFolderName(WScript.ScriptFullName)
port = 8787
ok = False

' ---- 1. 先试正常退出接口 ----
For i = 0 To 9
    url = "http://127.0.0.1:" & (port + i) & "/api/quit"
    On Error Resume Next
    Set http = CreateObject("MSXML2.XMLHTTP")
    http.Open "POST", url, False
    http.Send "{}"
    If Err.Number = 0 Then
        If http.Status = 200 Then ok = True
    End If
    Err.Clear
    On Error GoTo 0
    If ok Then Exit For
Next

' ---- 2. 兜底：按 PID 文件强杀 ----
pidFile = root & "\logs\netdiag.pid"
If Not ok Then
    If fso.FileExists(pidFile) Then
        On Error Resume Next
        pid = Trim(fso.OpenTextFile(pidFile, 1).ReadAll)
        If IsNumeric(pid) And Len(pid) > 0 Then
            shell.Run "taskkill /PID " & pid & " /F", 0, True
            ok = True
        End If
        Err.Clear
        On Error GoTo 0
    End If
End If

If ok Then
    MsgBox "本地诊断服务已停止。", vbInformation, "网络诊断工具"
Else
    MsgBox "没有检测到正在运行的服务（可能已经退出）。", vbInformation, "网络诊断工具"
End If
