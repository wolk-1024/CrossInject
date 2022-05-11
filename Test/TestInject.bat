start Notepad++.exe

..\Debug\CrossInject.exe --ProcessName Notepad++.exe --DllPath TestDll64.dll

pause

..\Debug\CrossInject.exe --ProcessName Notepad++.exe --DllPath TestDll64.dll --Unload

pause