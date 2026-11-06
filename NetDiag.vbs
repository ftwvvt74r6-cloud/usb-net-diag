' ============================================================
'  USB-Net-Diag 静默启动器
'  双击本文件即可：无控制台窗口 → 必要时代理提权 → 自动开浏览器
'  原理：用 pythonw.exe（无控制台的 Python）跑 core\app.py
' ============================================================
Option Explicit

Dim fso, shell, root, pyw, script, cmd

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

root = fso.GetParentFolderName(WScript.ScriptFullName)
pyw = root & "\tools\python\pythonw.exe"
script = root & "\core\app.py"

' ---- 前置检查 ----
If Not fso.FileExists(pyw) Then
    MsgBox "未找到便携 Python：" & vbCrLf & pyw & vbCrLf & vbCrLf & _
           "请确认 tools\python\ 目录完整，或重新解压整个工具包。", _
           vbCritical, "网络诊断工具"
    WScript.Quit 1
End If

If Not fso.FileExists(script) Then
    MsgBox "未找到启动脚本：" & vbCrLf & script, vbCritical, "网络诊断工具"
    WScript.Quit 1
End If

' ---- 静默拉起（0 = 隐藏窗口，False = 不等待）----
cmd = """" & pyw & """ """ & script & """"
On Error Resume Next
shell.CurrentDirectory = root
shell.Run cmd, 0, False
If Err.Number <> 0 Then
    MsgBox "启动失败：" & Err.Description & vbCrLf & vbCrLf & _
           "可尝试直接运行 start.bat 查看详细报错。", vbCritical, "网络诊断工具"
    WScript.Quit 1
End If
On Error GoTo 0

WScript.Quit 0
