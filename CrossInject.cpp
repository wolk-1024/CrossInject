/*
*  Copyright (c) 2020 Wolk-1024 <wolk1024@gmail.com>
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "CrossInject.hpp"

//#define METHOD_INJECT1

/*
*/
static void RtlSetLastError(NTSTATUS NtStatus) // RtlSetLastWin32ErrorAndNtStatusFromNtStatus
{
	SetLastError(RtlNtStatusToDosError(NtStatus));
}

/*
*/
DWORD GetProcessBit(_In_ HANDLE ProcessHandle)
{
	typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE, PBOOL);

	BOOL IsWoW64 = FALSE;

	HMODULE hModule = GetModuleHandleW(L"kernel32");

	if (hModule)
	{
		pfnIsWow64Process IsWow64Process = (pfnIsWow64Process)GetProcAddress(hModule, "IsWow64Process");

		if (!IsWow64Process)
			return 32;

		if (IsWow64Process(ProcessHandle, &IsWoW64))
			return IsWoW64 ? 32 : 64;
	}
	return 0;
}

/*
*/
DWORD GetProcessBit2(_In_ DWORD ProcessID)
{
	DWORD Result = 0;

	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessID);

	if (ProcessHandle)
	{
		Result = GetProcessBit(ProcessHandle);

		CloseHandle(ProcessHandle);
	}
	return Result;
}

/*
*/
BOOLEAN Is64BitOS()
{
	SYSTEM_INFO SystemInfo = { 0 };

	GetNativeSystemInfo(&SystemInfo);

	return SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
}

/*
*/
BOOLEAN SetProcessPrivilege(_In_ HANDLE ProcessHandle, _In_ LPCWSTR PrivilegeName, _In_ BOOLEAN EnablePrivilege, _In_opt_ PBOOLEAN IsEnabled)
{
	BOOLEAN Result = FALSE;

	HANDLE TokenHandle = 0;

	if (OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		LUID Luid = { 0 };

		if (LookupPrivilegeValueW(NULL, PrivilegeName, &Luid))
		{
			TOKEN_PRIVILEGES PreviousState = { 0 }, NewState = { 0 };

			NewState.PrivilegeCount = 1;
			NewState.Privileges[0].Luid = Luid;
			NewState.Privileges[0].Attributes = EnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

			DWORD ReturnLength = 0;

			Result = AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), &PreviousState, &ReturnLength);

			if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
			{
				SetLastError(ERROR_PRIVILEGE_NOT_HELD);
				Result = FALSE;
			}
			else if (Result && IsEnabled)
			{
				if (PreviousState.PrivilegeCount == 0)
					*IsEnabled = EnablePrivilege;
				else
					*IsEnabled = (PreviousState.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) ? TRUE : FALSE;
			}
		}
		CloseHandle(TokenHandle);
	}
	return Result;
}

/*
*/
DWORD GetDllArch(_In_ LPCWSTR DllPath)
{
	DWORD Result = 0;

	HANDLE FileHandle = CreateFileW(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (FileHandle != INVALID_HANDLE_VALUE)
	{
		IMAGE_DOS_HEADER DosHeader = { 0 };

		IMAGE_NT_HEADERS64 NtHeaders = { 0 };

		ReadFile(FileHandle, &DosHeader, sizeof(DosHeader), NULL, NULL);

		SetFilePointer(FileHandle, DosHeader.e_lfanew, NULL, 0);

		ReadFile(FileHandle, &NtHeaders, sizeof(NtHeaders), NULL, NULL);

		if (NtHeaders.Signature == IMAGE_NT_SIGNATURE)
		{
			switch (NtHeaders.FileHeader.Machine)
			{
			case IMAGE_FILE_MACHINE_AMD64: Result = 64;
				break;
			case IMAGE_FILE_MACHINE_I386: Result = 32;
				break;
			}
		}
		CloseHandle(FileHandle);
	}
	return Result;
}

/*
*/
DWORD GetProcessIDByName(_In_ LPCWSTR ProcessName)
{
	DWORD ProcessID = 0;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W ProcessEntry = { 0 };

		ProcessEntry.dwSize = sizeof(ProcessEntry);

		if (Process32FirstW(hProcessSnap, &ProcessEntry))
		{
			do {
				if (_wcsicmp(ProcessEntry.szExeFile, ProcessName) == 0)
				{
					ProcessID = ProcessEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(hProcessSnap, &ProcessEntry));
		}
		CloseHandle(hProcessSnap);
	}
	return ProcessID;
}

/*
*/
DWORD GetProcessIDByWindow(_In_ LPCWSTR WindowName)
{
	HWND hWindow = FindWindowW(NULL, WindowName);

	DWORD ProcessID = 0;

	if (hWindow)
		GetWindowThreadProcessId(hWindow, &ProcessID);

	return ProcessID;
}

/*
*/
HANDLE OpenProcessByName(_In_ LPCWSTR ProcessName, _In_ ACCESS_MASK DesiredAccess)
{
	DWORD ProcessID = GetProcessIDByName(ProcessName);

	if (ProcessID)
		return OpenProcess(DesiredAccess, FALSE, ProcessID);
	else
		return NULL;
}

/*
*/
static void ExtractFileName(_In_ LPCWSTR FullPath, _Out_ LPWSTR OutBuffer, _In_ SIZE_T BufferCount)
{
	WCHAR TempName[_MAX_FNAME] = { 0 };

	WCHAR TempExt[_MAX_EXT] = { 0 };

	_wsplitpath_s(FullPath, NULL, 0, NULL, 0, TempName, _MAX_FNAME, TempExt, _MAX_EXT);

	_wmakepath_s(OutBuffer, BufferCount, NULL, NULL, TempName, TempExt);
}

/*
static HMODULE GetRemoteModuleHandle(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName)
{
	HMODULE ModuleHandle = 0;

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(ProcessHandle));

	if (hModuleSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32W ModuleEntry = { 0 };

		ModuleEntry.dwSize = sizeof(ModuleEntry);

		if (Module32FirstW(hModuleSnap, &ModuleEntry))
		{
			do {
				if ((_wcsicmp(ModuleName, ModuleEntry.szModule) == 0) ||
					(_wcsicmp(ModuleName, ModuleEntry.szExePath) == 0))
				{
					ModuleHandle = ModuleEntry.hModule;

					break;
				}
			} while (Module32NextW(hModuleSnap, &ModuleEntry));
		}
		CloseHandle(hModuleSnap);
	}
	return ModuleHandle;
}
*/

/*
   DllArch - разрядность искомой библиотеки. (32 или 64)
*/
static HMODULE GetRemoteModuleHandle(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName, _In_ DWORD DllArch)
{
	DWORD cbNeeded;

	HMODULE Result = NULL;

	DWORD Flags = (DllArch == 32) ? LIST_MODULES_32BIT : (DllArch == 64) ? LIST_MODULES_64BIT : LIST_MODULES_ALL;

	if (!EnumProcessModulesEx(ProcessHandle, NULL, NULL, &cbNeeded, Flags))
		return NULL;

	HMODULE* hModules = (HMODULE*)LocalAlloc(LPTR, cbNeeded);

	if (hModules)
	{
		if (EnumProcessModulesEx(ProcessHandle, hModules, cbNeeded, &cbNeeded, Flags))
		{
			for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
			{
				WCHAR FullDllName[MAX_PATH] = { 0 };

				if (!GetModuleFileNameExW(ProcessHandle, hModules[i], FullDllName, _countof(FullDllName)))
					break;

				WCHAR ShortDllName[_MAX_FNAME] = { 0 };

				ExtractFileName(FullDllName, ShortDllName, _countof(ShortDllName));

				if ((_wcsicmp(ModuleName, ShortDllName) == 0) ||
					(_wcsicmp(ModuleName, FullDllName) == 0))
				{
					Result = hModules[i];

					break;
				}
			}
		}
		LocalFree(hModules);
	}
	return Result;
}

/*
*/
static HMODULE GetRemoteModuleHandleA(_In_ HANDLE ProcessHandle, _In_ LPCSTR ModuleName, _In_ DWORD DllArch)
{
	WCHAR TempName[_MAX_PATH] = { 0 };

	int Length = MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, NULL, 0);

	MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, TempName, Length);

	return GetRemoteModuleHandle(ProcessHandle, TempName, DllArch);
}

/*
*/
#ifdef _M_IX86
static DWORD64 GetRemoteModuleHandleWoW64(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName)
{
	DWORD64 ModuleHandle = 0;

	PROCESS_BASIC_INFORMATION64 ProcessInformation = { 0 };

	NTSTATUS Status = NtWow64QueryInformationProcess64(ProcessHandle, ProcessWow64BasicInformation, &ProcessInformation, sizeof(ProcessInformation), NULL);

	if (NT_SUCCESS(Status))
	{
		PEB64 Peb = { 0 };

		Status = NtWow64ReadVirtualMemory64(ProcessHandle, ProcessInformation.PebBaseAddress, &Peb, sizeof(Peb), NULL);

		if (NT_SUCCESS(Status))
		{
			PEB_LDR_DATA64 Ldr = { 0 };

			Status = NtWow64ReadVirtualMemory64(ProcessHandle, Peb.Ldr, &Ldr, sizeof(Ldr), NULL);

			if (NT_SUCCESS(Status))
			{
				DWORD64 FirstModule = Ldr.InLoadOrderModuleList.Flink;

				DWORD64 NextModule = FirstModule;

				LDR_DATA_TABLE_ENTRY64 DataTableEntry = { 0 };

				do {
					Status = NtWow64ReadVirtualMemory64(ProcessHandle, NextModule, &DataTableEntry, sizeof(DataTableEntry), NULL);

					if (!NT_SUCCESS(Status))
						break;

					if (!ModuleName || !*ModuleName)
					{
						ModuleHandle = DataTableEntry.DllBase;
						break;
					}

					WCHAR FullDllName[MAX_PATH] = { 0 };

					Status = NtWow64ReadVirtualMemory64(ProcessHandle, DataTableEntry.FullDllName.Buffer, &FullDllName, DataTableEntry.FullDllName.MaximumLength, NULL);

					if (!NT_SUCCESS(Status))
						break;

					WCHAR ShortDllName[_MAX_FNAME] = { 0 };

					ExtractFileName(FullDllName, ShortDllName, _countof(ShortDllName));

					if ((_wcsicmp(ModuleName, ShortDllName) == 0) ||
						(_wcsicmp(ModuleName, FullDllName) == 0))
					{
						ModuleHandle = DataTableEntry.DllBase;

						break;
					}

					NextModule = DataTableEntry.InLoadOrderLinks.Flink;

				} while (FirstModule != NextModule);
			}
		}
	}
	RtlSetLastError(Status);

	return ModuleHandle;
}

static DWORD64 GetRemoteModuleHandleWoW64A(_In_ HANDLE ProcessHandle, _In_ LPCSTR ModuleName)
{
	WCHAR TempName[_MAX_PATH] = { 0 };

	int Length = MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, NULL, 0);

	MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, TempName, Length);

	return GetRemoteModuleHandleWoW64(ProcessHandle, TempName);
}
#endif

/*
	x64DllFrom32 - Поиск 64-битного dll в АП 32-х битного процесса. (ntdll.dll, wow64.dll, wow64cpu.dll etc)
*/
DWORD64 CrossGetRemoteModuleHandle(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName, _In_opt_ BOOLEAN x64DllFrom32 = FALSE)
{
	int ProcessBit = GetProcessBit(ProcessHandle);

	if (ProcessBit == 32)
	{
#ifdef _M_IX86
		if (x64DllFrom32 && IsWoW64())
			return GetRemoteModuleHandleWoW64(ProcessHandle, ModuleName);
#else
		if (x64DllFrom32)
			return (DWORD64)GetRemoteModuleHandle(ProcessHandle, ModuleName, 64);
#endif
		return (DWORD64)GetRemoteModuleHandle(ProcessHandle, ModuleName, 32);
	}
	else if (ProcessBit == 64)
	{
#ifdef _M_IX86
		if (IsWoW64())
			return GetRemoteModuleHandleWoW64(ProcessHandle, ModuleName);
#else
		return (DWORD64)GetRemoteModuleHandle(ProcessHandle, ModuleName, 64);
#endif
	}
	return 0;
}

/*
*/
static PVOID GetRemoteProcedureAddress(_In_ HANDLE ProcessHandle, _In_ HMODULE ModuleBase, _In_ LPCSTR ProcedureName)
{
	if (!ModuleBase)
		return 0;

	PVOID ProcedureAddress = 0;

	IMAGE_DOS_HEADER DosHeader = { 0 };

	if (ReadProcessMemory(ProcessHandle, ModuleBase, &DosHeader, sizeof(DosHeader), NULL))
	{
		if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		IMAGE_NT_HEADERS NtHeaders = { 0 };

		if (ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)ModuleBase + DosHeader.e_lfanew), &NtHeaders, sizeof(NtHeaders), NULL))
		{
			if (NtHeaders.Signature != IMAGE_NT_SIGNATURE)
				return 0;

			IMAGE_DATA_DIRECTORY DataDirectory = { 0 };

			switch (NtHeaders.FileHeader.Machine)
			{
			case IMAGE_FILE_MACHINE_AMD64: DataDirectory = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				break;

			case IMAGE_FILE_MACHINE_I386: DataDirectory = PIMAGE_NT_HEADERS32(&NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				break;

			default: return 0;
			}

			if (DataDirectory.VirtualAddress == 0)
				return 0;

			IMAGE_EXPORT_DIRECTORY ExportDirectory = { 0 };

			if (ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)ModuleBase + DataDirectory.VirtualAddress), &ExportDirectory, sizeof(ExportDirectory), NULL))
			{
				WORD FunctionIndex = -1;
				PVOID AddressOfNames = (PVOID)((LPBYTE)ModuleBase + ExportDirectory.AddressOfNames);
				PVOID AddressOfNameOrdinals = (PVOID)((LPBYTE)ModuleBase + ExportDirectory.AddressOfNameOrdinals);

				if (((SIZE_T)ProcedureName & 0xffff0000) == 0)
				{
					DWORD Ordinal = LOWORD(ProcedureName);

					if ((Ordinal < ExportDirectory.Base) || (Ordinal >= (ExportDirectory.Base + ExportDirectory.NumberOfFunctions))) // Если ординал меньше базого значения или больше количества экспортируемых функций.
						return 0;
					else
						FunctionIndex = (WORD)(Ordinal - ExportDirectory.Base);
				}
				else
				{
					DWORD NameRVA = 0;

					for (DWORD IndexName = 0; IndexName < ExportDirectory.NumberOfNames - 1; IndexName++)
					{
						if (ReadProcessMemory(ProcessHandle, ((LPBYTE)AddressOfNames + (IndexName * sizeof(IndexName))), &NameRVA, sizeof(NameRVA), NULL))
						{
							CHAR RemoteProcedureName[_MAX_FNAME] = { 0 };

							if (ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)ModuleBase + NameRVA), &RemoteProcedureName, sizeof(RemoteProcedureName), NULL))
							{
								if (strcmp(ProcedureName, RemoteProcedureName) == 0)
								{
									if (!ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)AddressOfNameOrdinals + (IndexName * sizeof(FunctionIndex))), &FunctionIndex, sizeof(FunctionIndex), NULL))
										return 0;
									else
										break;
								}
							}
						}
					}
				}
				if (FunctionIndex < 0)
					return 0;

				DWORD ProcedureRVA = 0;

				PVOID AddressOfFunctions = (PVOID)((LPBYTE)ModuleBase + ExportDirectory.AddressOfFunctions);

				if (ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)AddressOfFunctions + (FunctionIndex * sizeof(ProcedureRVA))), &ProcedureRVA, sizeof(ProcedureRVA), NULL))
				{
					ProcedureAddress = (PVOID)((LPBYTE)ModuleBase + ProcedureRVA);

					if ((SIZE_T)ProcedureAddress >= (DataDirectory.VirtualAddress + (SIZE_T)ModuleBase) && (SIZE_T)ProcedureAddress < (DataDirectory.VirtualAddress + (SIZE_T)ModuleBase + DataDirectory.Size)) // Forwarded export
					{
						CHAR ForwardedName[_MAX_FNAME] = { 0 };

						if (ReadProcessMemory(ProcessHandle, ProcedureAddress, &ForwardedName, sizeof(ForwardedName), NULL))
						{
							PCHAR ProcName = NULL;

							PCHAR ShortDllName = strtok_s(ForwardedName, ".", &ProcName);

							if (!ShortDllName || !ProcName)
								return 0;

							if (strchr(ProcName, '#')) // Ординал
							{
								PCHAR Temp = NULL;

								PCHAR Ordinal = strtok_s(ProcName, "#", &Temp);

								ProcName = (PCHAR)(WORD)atoi(Ordinal);
							}
							CHAR DllName[_MAX_FNAME] = { 0 };

							strcat_s(DllName, ShortDllName);

							strcat_s(DllName, ".DLL");

							ProcedureAddress = GetRemoteProcedureAddress(ProcessHandle, GetRemoteModuleHandleA(ProcessHandle, DllName, 0), ProcName);
						}
					}
				}
			}
		}
	}
	return ProcedureAddress;
}

#ifdef _M_IX86
/*
   Fixme: как-нибудь объеденить с GetRemoteProcedureAddress
*/
static DWORD64 GetRemoteProcedureAddressWoW64(_In_ HANDLE ProcessHandle, _In_ DWORD64 ModuleBase, _In_ LPCSTR ProcedureName)
{
	if (!ModuleBase)
		return 0;

	DWORD64 ProcedureAddress = 0;

	IMAGE_DOS_HEADER DosHeader = { 0 };

	NTSTATUS Status = NtWow64ReadVirtualMemory64(ProcessHandle, ModuleBase, &DosHeader, sizeof(DosHeader), NULL);

	if (NT_SUCCESS(Status))
	{
		if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		IMAGE_NT_HEADERS64 NtHeaders = { 0 };

		Status = NtWow64ReadVirtualMemory64(ProcessHandle, ModuleBase + DosHeader.e_lfanew, &NtHeaders, sizeof(NtHeaders), NULL);

		if (NT_SUCCESS(Status))
		{
			if (NtHeaders.Signature != IMAGE_NT_SIGNATURE)
				return 0;

			IMAGE_DATA_DIRECTORY DataDirectory = { 0 };

			switch (NtHeaders.FileHeader.Machine)
			{
			case IMAGE_FILE_MACHINE_AMD64: DataDirectory = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				break;

			case IMAGE_FILE_MACHINE_I386: DataDirectory = PIMAGE_NT_HEADERS32(&NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				break;

			default: return 0;
			}

			if (DataDirectory.VirtualAddress == 0)
				return 0;

			IMAGE_EXPORT_DIRECTORY ExportDirectory = { 0 };

			Status = NtWow64ReadVirtualMemory64(ProcessHandle, ModuleBase + DataDirectory.VirtualAddress, &ExportDirectory, sizeof(ExportDirectory), NULL);

			if (NT_SUCCESS(Status))
			{
				WORD FunctionIndex = -1;
				DWORD64 AddressOfNames = ModuleBase + ExportDirectory.AddressOfNames;
				DWORD64 AddressOfNameOrdinals = ModuleBase + ExportDirectory.AddressOfNameOrdinals;

				if (((DWORD)ProcedureName & 0xffff0000) == 0)
				{
					DWORD Ordinal = LOWORD(ProcedureName);

					if ((Ordinal < ExportDirectory.Base) || (Ordinal >= (ExportDirectory.Base + ExportDirectory.NumberOfFunctions)))
						return 0;
					else
						FunctionIndex = (WORD)(Ordinal - ExportDirectory.Base);
				}
				else
				{
					DWORD NameRVA = 0;

					for (DWORD IndexName = 0; IndexName < ExportDirectory.NumberOfNames - 1; IndexName++)
					{
						Status = NtWow64ReadVirtualMemory64(ProcessHandle, AddressOfNames + (IndexName * sizeof(IndexName)), &NameRVA, sizeof(NameRVA), NULL);

						if (NT_SUCCESS(Status))
						{
							CHAR RemoteProcedureName[_MAX_FNAME] = { 0 };

							Status = NtWow64ReadVirtualMemory64(ProcessHandle, ModuleBase + NameRVA, &RemoteProcedureName, sizeof(RemoteProcedureName), NULL);

							if (NT_SUCCESS(Status))
							{
								if (strcmp(ProcedureName, RemoteProcedureName) == 0)
								{
									Status = NtWow64ReadVirtualMemory64(ProcessHandle, AddressOfNameOrdinals + (IndexName * sizeof(FunctionIndex)), &FunctionIndex, sizeof(FunctionIndex), NULL);

									break;
								}
							}
						}
					}
				}
				if (NT_SUCCESS(Status) && FunctionIndex >= 0)
				{
					DWORD ProcedureRVA = 0;

					DWORD64 AddressOfFunctions = ModuleBase + ExportDirectory.AddressOfFunctions;

					Status = NtWow64ReadVirtualMemory64(ProcessHandle, AddressOfFunctions + (FunctionIndex * sizeof(ProcedureRVA)), &ProcedureRVA, sizeof(ProcedureRVA), NULL);

					if (NT_SUCCESS(Status))
					{
						ProcedureAddress = ModuleBase + ProcedureRVA;

						if (ProcedureAddress >= (DataDirectory.VirtualAddress + ModuleBase) && ProcedureAddress < (DataDirectory.VirtualAddress + ModuleBase + DataDirectory.Size))
						{
							CHAR ForwardedName[_MAX_FNAME] = { 0 };

							Status = NtWow64ReadVirtualMemory64(ProcessHandle, ProcedureAddress, &ForwardedName, sizeof(ForwardedName), NULL);

							if (NT_SUCCESS(Status))
							{
								PCHAR ProcName = NULL;

								PCHAR ShortDllName = strtok_s(ForwardedName, ".", &ProcName);

								if (!ShortDllName || !ProcName)
									return 0;

								if (strchr(ProcName, '#')) // Ординал
								{
									PCHAR Temp = NULL;

									PCHAR Ordinal = strtok_s(ProcName, "#", &Temp);

									ProcName = (PCHAR)(WORD)atoi(Ordinal);
								}
								CHAR DllName[_MAX_FNAME] = { 0 };

								strcat_s(DllName, ShortDllName);

								strcat_s(DllName, ".DLL");

								ProcedureAddress = GetRemoteProcedureAddressWoW64(ProcessHandle, GetRemoteModuleHandleWoW64A(ProcessHandle, DllName), ProcName);
							}
						}
					}
				}
			}
		}
	}
	RtlSetLastError(Status);

	return ProcedureAddress;
}
#endif

/*
   x64ProcFrom32 - Поиск 64-битной функции в АП 32-х битного процесса.
*/
DWORD64 CrossGetRemoteProcedureAddress(_In_ HANDLE ProcessHandle, _In_ DWORD64 ModuleBase, _In_ LPCSTR ProcedureName, _In_opt_ BOOLEAN x64ProcFrom32)
{
#ifdef _M_IX86
	if (x64ProcFrom32)
		return GetRemoteProcedureAddressWoW64(ProcessHandle, ModuleBase, ProcedureName);
#endif
	return (DWORD64)GetRemoteProcedureAddress(ProcessHandle, (HMODULE)ModuleBase, ProcedureName);
}

#ifdef METHOD_INJECT1
/*
*/
BOOLEAN InjectDll(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ PVOID* DllBase, _In_opt_ BOOLEAN UnloadDll)
{
	DWORD Result = FALSE;

	PVOID RemoteRoutine = GetRemoteProcedureAddress(ProcessHandle, GetRemoteModuleHandle(ProcessHandle, L"kernel32.dll"), UnloadDll ? "FreeLibrary" : "LoadLibraryW");

	if (RemoteRoutine)
	{
		PVOID RemoteParameter = 0;

		SIZE_T DllNameSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);

		if (!UnloadDll)
		{
			RemoteParameter = VirtualAllocEx(ProcessHandle, NULL, DllNameSize, MEM_COMMIT, PAGE_READWRITE);

			if (!RemoteParameter)
				return FALSE;

			WriteProcessMemory(ProcessHandle, RemoteParameter, (PVOID)DllPath, DllNameSize, NULL);
		}
		else
			RemoteParameter = GetRemoteModuleHandle(ProcessHandle, DllPath);

		if (RemoteParameter)
		{
			HANDLE ThreadHandle = 0;

			CLIENT_ID ClientID = { 0 };

			NTSTATUS Status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)RemoteRoutine, RemoteParameter, &ThreadHandle, &ClientID);

			if (NT_SUCCESS(Status))
			{
				if (WaitForSingleObject(ThreadHandle, INFINITE) != WAIT_FAILED)
				{
					if (!UnloadDll)
					{
						HMODULE RemoteDll = GetRemoteModuleHandle(ProcessHandle, DllPath);

						Result = ((SIZE_T)RemoteDll > 0);

						if (DllBase)
							*DllBase = RemoteDll;
					}
					else
						GetExitCodeThread((HANDLE)ThreadHandle, &Result);
				}
				CloseHandle(ThreadHandle);
			}
		}
		if (!UnloadDll && RemoteParameter)
			VirtualFreeEx(ProcessHandle, RemoteParameter, 0, MEM_RELEASE);
	}
	return Result > 0;
}

/*
   WoW64 -> x64
*/
#ifdef _M_IX86
static BOOLEAN InjectDllWoW64(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ PDWORD64 DllBase, _In_opt_ BOOLEAN UnloadDll)
{
	DWORD Result = FALSE;

	NTSTATUS Status = STATUS_SUCCESS;

	DWORD64 RemoteRoutine = GetRemoteProcedureAddressWoW64(ProcessHandle, GetRemoteModuleHandleWoW64(ProcessHandle, L"kernel32.dll"), UnloadDll ? "FreeLibrary" : "LoadLibraryW");

	if (RemoteRoutine)
	{
		DWORD64 RemoteParameter = 0;

		DWORD64 DllNameSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);

		if (!UnloadDll)
		{
			Status = NtWow64AllocateVirtualMemory64(ProcessHandle, &RemoteParameter, 0, &DllNameSize, MEM_COMMIT, PAGE_READWRITE);

			if (!NT_SUCCESS(Status))
				return FALSE;

			Status = NtWow64WriteVirtualMemory64(ProcessHandle, RemoteParameter, (PDWORD64)DllPath, DllNameSize, NULL);
		}
		else
			RemoteParameter = GetRemoteModuleHandleWoW64(ProcessHandle, DllPath);

		if (NT_SUCCESS(Status) && RemoteParameter)
		{
			HANDLE64 ThreadHandle = 0;

			WOW64_CLIENT_ID64 ClientID = { 0 };

			Status = RtlWow64CreateUserThread64(ProcessHandle, NULL, FALSE, 0, 0, 0, RemoteRoutine, RemoteParameter, &ThreadHandle, &ClientID);

			if (NT_SUCCESS(Status))
			{
				if (WaitForSingleObject((HANDLE)ThreadHandle, INFINITE) != WAIT_FAILED)
				{
					if (!UnloadDll)
					{
						DWORD64 RemoteDll = GetRemoteModuleHandleWoW64(ProcessHandle, DllPath);

						Result = (RemoteDll > 0);

						if (DllBase)
							*DllBase = RemoteDll;
					}
					else
						GetExitCodeThread((HANDLE)ThreadHandle, &Result);
				}
				CloseHandle((HANDLE)ThreadHandle);
			}
		}
		if (!UnloadDll && RemoteParameter)
		{
			DllNameSize = 0;

			NtWow64FreeVirtualMemory64(ProcessHandle, &RemoteParameter, &DllNameSize, MEM_RELEASE);
		}
	}
	return Result > 0;
}
#endif

#else

/*
*/
static BOOLEAN InjectDll(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ PVOID* DllBase, _In_opt_ BOOLEAN UnloadDll)
{
	BOOLEAN Result = FALSE;

	TDllLoader InjectData = { 0 };

	int ProcessBit = GetProcessBit(ProcessHandle);

	if (!ProcessBit)
		return FALSE;

	HMODULE hNtdll = GetRemoteModuleHandle(ProcessHandle, L"ntdll.dll", 0);

	if (!hNtdll)
		return FALSE;

	InjectData.LdrLoadDll = (DWORD64)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrLoadDll");

	if (!InjectData.LdrLoadDll)
		return FALSE;

	InjectData.LdrUnloadDll = (DWORD64)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrUnloadDll");

	if (!InjectData.LdrUnloadDll)
		return FALSE;

	InjectData.LdrGetDllHandle = (DWORD64)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrGetDllHandle");

	if (!InjectData.LdrGetDllHandle)
		return FALSE;

	InjectData.RtlInitUnicodeString = (DWORD64)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "RtlInitUnicodeString");

	if (!InjectData.RtlInitUnicodeString)
		return FALSE;

	InjectData.UnloadDll = UnloadDll;

	wcscpy_s(InjectData.DllPath, _countof(InjectData.DllPath), DllPath);

	PVOID ShellData = VirtualAllocEx(ProcessHandle, NULL, sizeof(InjectData), MEM_COMMIT, PAGE_READWRITE);

	if (ShellData)
	{
		if (WriteProcessMemory(ProcessHandle, ShellData, &InjectData, sizeof(InjectData), NULL))
		{
			int LoaderSize = (ProcessBit == 64) ? sizeof(LoaderDll64) : sizeof(LoaderDll32);

			PVOID ShellCode = VirtualAllocEx(ProcessHandle, NULL, LoaderSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (ShellCode)
			{
				PVOID pDllLoader = (ProcessBit == 64) ? (PVOID)&LoaderDll64 : &LoaderDll32;

				if (WriteProcessMemory(ProcessHandle, ShellCode, pDllLoader, LoaderSize, NULL))
				{
					HANDLE ThreadHandle = 0;

					CLIENT_ID ClientID = { 0 };

					NTSTATUS Status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)ShellCode, ShellData, &ThreadHandle, &ClientID);

					if (NT_SUCCESS(Status))
					{
						if (WaitForSingleObject(ThreadHandle, INFINITE) != WAIT_FAILED)
						{
							GetExitCodeThread(ThreadHandle, (PDWORD)&Status);

							if (!UnloadDll)
							{
								HMODULE RemoteDll = GetRemoteModuleHandle(ProcessHandle, DllPath, 0);

								Result = ((SIZE_T)RemoteDll > 0);

								if (DllBase)
									*DllBase = RemoteDll;
							}
							else
								Result = NT_SUCCESS(Status);
						}
						CloseHandle(ThreadHandle);
					}
					RtlSetLastError(Status);
				}
				VirtualFreeEx(ProcessHandle, ShellCode, 0, MEM_RELEASE);
			}
		}
		VirtualFreeEx(ProcessHandle, ShellData, 0, MEM_RELEASE);
	}
	return Result;
}

/*
   WoW64 -> x64
*/
#ifdef _M_IX86
BOOLEAN InjectDllWoW64(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ PDWORD64 DllBase, _In_opt_ BOOLEAN UnloadDll)
{
	BOOLEAN Result = FALSE;

	TDllLoader InjectData = { 0 };

	InjectData.UnloadDll = UnloadDll;

	wcscpy_s(InjectData.DllPath, _countof(InjectData.DllPath), DllPath);

	DWORD64 hNtdll = GetRemoteModuleHandleWoW64(ProcessHandle, L"ntdll.dll");

	if (!hNtdll)
		return FALSE;

	InjectData.LdrLoadDll = GetRemoteProcedureAddressWoW64(ProcessHandle, hNtdll, "LdrLoadDll");

	if (!InjectData.LdrLoadDll)
		return FALSE;

	InjectData.LdrUnloadDll = GetRemoteProcedureAddressWoW64(ProcessHandle, hNtdll, "LdrUnloadDll");

	if (!InjectData.LdrUnloadDll)
		return FALSE;

	InjectData.LdrGetDllHandle = GetRemoteProcedureAddressWoW64(ProcessHandle, hNtdll, "LdrGetDllHandle");

	if (!InjectData.LdrGetDllHandle)
		return FALSE;

	InjectData.RtlInitUnicodeString = GetRemoteProcedureAddressWoW64(ProcessHandle, hNtdll, "RtlInitUnicodeString");

	if (!InjectData.RtlInitUnicodeString)
		return FALSE;

	DWORD64 ShellData = 0;

	DWORD64 ShellSize = sizeof(InjectData);

	NTSTATUS Status = NtWow64AllocateVirtualMemory64(ProcessHandle, &ShellData, 0, &ShellSize, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(Status))
	{
		DWORD64 WriteBytes = 0;

		Status = NtWow64WriteVirtualMemory64(ProcessHandle, ShellData, &InjectData, ShellSize, &WriteBytes);

		if (NT_SUCCESS(Status))
		{
			DWORD64 ShellCode = 0;

			DWORD64 LoaderSize = sizeof(LoaderDll64);

			Status = NtWow64AllocateVirtualMemory64(ProcessHandle, &ShellCode, 0, &LoaderSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (NT_SUCCESS(Status))
			{
				WriteBytes = 0;

				Status = NtWow64WriteVirtualMemory64(ProcessHandle, ShellCode, &LoaderDll64, LoaderSize, &WriteBytes);

				if (NT_SUCCESS(Status))
				{
					HANDLE64 ThreadHandle = 0;

					WOW64_CLIENT_ID64 ClientID = { 0 };

					NTSTATUS Status = RtlWow64CreateUserThread64(ProcessHandle, NULL, FALSE, 0, 0, 0, ShellCode, ShellData, &ThreadHandle, &ClientID);

					if (NT_SUCCESS(Status))
					{
						if (WaitForSingleObject((HANDLE)ThreadHandle, INFINITE) != WAIT_FAILED)
						{
							GetExitCodeThread((HANDLE)ThreadHandle, (PDWORD)&Status);

							if (!UnloadDll)
							{
								DWORD64 RemoteDll = GetRemoteModuleHandleWoW64(ProcessHandle, DllPath);

								Result = (RemoteDll > 0);

								if (DllBase)
									*DllBase = RemoteDll;
							}
							else
								Result = NT_SUCCESS(Status);
						}
						CloseHandle((HANDLE)ThreadHandle);
					}
					RtlSetLastError(Status);
				}
				LoaderSize = 0;

				NtWow64FreeVirtualMemory64(ProcessHandle, &ShellCode, &LoaderSize, MEM_RELEASE);
			}
		}
		ShellSize = 0;

		NtWow64FreeVirtualMemory64(ProcessHandle, &ShellData, &ShellSize, MEM_RELEASE);
	}
	return Result;
}
#endif

#endif

/*
*/
BOOLEAN CrossInjectDll(_In_ DWORD ProcessID, _In_ LPCWSTR DllPath, _In_opt_ PDWORD64 DllBase, _In_opt_ BOOLEAN UnloadDll = FALSE)
{
	BOOLEAN Result = FALSE;

	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, ProcessID);

	if (ProcessHandle)
	{
		int ProcessBit = GetProcessBit(ProcessHandle);

		if (ProcessBit == 32)
		{
			Result = InjectDll(ProcessHandle, DllPath, (PVOID*)DllBase, UnloadDll);
		}
		else if (ProcessBit == 64)
		{
#ifdef _M_IX86
			if (IsWoW64())
				Result = InjectDllWoW64(ProcessHandle, DllPath, DllBase, UnloadDll);
#else
			Result = InjectDll(ProcessHandle, DllPath, (PVOID*)DllBase, UnloadDll);
#endif
		}
		CloseHandle(ProcessHandle);
	}
	return Result;
}

/*
*/
BOOLEAN CrossUnloadDll(_In_ DWORD ProcessID, _In_ LPCWSTR DllPath)
{
	return CrossInjectDll(ProcessID, DllPath, NULL, TRUE);
}

/*
*/
DWORD64 CreateProcessWithDll(_In_ LPCWSTR ProcessName, _In_opt_ LPWSTR CommandLine, _In_ LPCWSTR DllPath, _Out_opt_ PDWORD ResultPID)
{
	DWORD64 DllAddress = 0;

	SHELLEXECUTEINFOW ShellInfo = { 0 };

	ShellInfo.cbSize = sizeof(ShellInfo);

	ShellInfo.fMask = SEE_MASK_NOCLOSEPROCESS;

	ShellInfo.hwnd = NULL;

	ShellInfo.lpVerb = L"open";

	ShellInfo.lpFile = ProcessName;

	ShellInfo.lpParameters = CommandLine;

	ShellInfo.lpDirectory = NULL;

	ShellInfo.nShow = SW_RESTORE;

	ShellInfo.hInstApp = NULL;

	//CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ShellExecuteExW(&ShellInfo))
	{
		if (ShellInfo.hProcess)
		{
			DWORD ProcessID = GetProcessId(ShellInfo.hProcess);

			if (ProcessID > 0)
			{
				CloseHandle(ShellInfo.hProcess);

				if (CrossInjectDll(ProcessID, DllPath, &DllAddress, FALSE))
				{
					if (ResultPID)
						*ResultPID = ProcessID;
				}
			}
		}
	}
	//CoUninitialize();

	return DllAddress;
}