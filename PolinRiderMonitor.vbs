' Launches the PolinRider Monitor app without a console window
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""C:\Development\polinrider-monitor\app.ps1""", 0, False
