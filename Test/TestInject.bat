set TargetProcess=Notepad++.exe

set TargetDll=TestDll64.dll

..\Debug\CrossInject.exe --ProcessName %TargetProcess% --DllPath %TargetDll%

pause

..\Debug\CrossInject.exe --ProcessName %TargetProcess% --DllPath %TargetDll% --Unload

pause