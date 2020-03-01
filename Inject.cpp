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

#include "Inject.hpp"

//#define CROSSINJECT1

/*
*/
DWORD GetProcessBit(_In_ HANDLE ProcessHandle)
{
	typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE, PBOOL);

	BOOL IsWoW64 = FALSE;

	pfnIsWow64Process IsWow64Process = (pfnIsWow64Process)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");

	if (!IsWow64Process)
		return 32;

	if (IsWow64Process(ProcessHandle, &IsWoW64))
		return IsWoW64 ? 32 : 64;

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
void RtlSetLastError(DWORD Status) // RtlSetLastWin32ErrorAndNtStatusFromNtStatus
{
	RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
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
BOOLEAN IsFileExists(_In_ PCWSTR Path)
{
	DWORD Attrib = GetFileAttributesW(Path);

	return (Attrib != INVALID_FILE_ATTRIBUTES && !(Attrib & FILE_ATTRIBUTE_DIRECTORY));
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

		ReadFile(FileHandle, &DosHeader, sizeof(DosHeader), NULL, NULL);

		SetFilePointer(FileHandle, DosHeader.e_lfanew, NULL, 0);

		IMAGE_NT_HEADERS64 NtHeaders = { 0 };

		ReadFile(FileHandle, &NtHeaders, sizeof(NtHeaders), NULL, NULL);

		CloseHandle(FileHandle);

		if (NtHeaders.Signature != IMAGE_NT_SIGNATURE)
			return Result;

		switch (NtHeaders.FileHeader.Machine)
		{
		    case IMAGE_FILE_MACHINE_AMD64 : Result = 64;
			    break;
		    case IMAGE_FILE_MACHINE_I386  : Result = 32;
			    break;
		}
	}
	return Result;
}

/*
*/
DWORD GetProcessIDByName(_In_ LPCWSTR ProcessName)
{
	DWORD ProcessID = 0;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap)
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
		return 0;
}

/*
*/
DWORD GetRemoteModuleHandle32(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName)
{
	DWORD ModuleHandle = 0;

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(ProcessHandle));

	if (hModuleSnap)
	{
		MODULEENTRY32W ModuleEntry = { 0 };

		ModuleEntry.dwSize = sizeof(ModuleEntry);

		if (Module32FirstW(hModuleSnap, &ModuleEntry))
		{
			do {
				if (_wcsicmp(ModuleName, ModuleEntry.szModule) == 0)
				{
					ModuleHandle = (DWORD)ModuleEntry.hModule;
					break;
				}
			} while (Module32NextW(hModuleSnap, &ModuleEntry));
		}
		CloseHandle(hModuleSnap);
	}
	return ModuleHandle;
}

/*
*/
DWORD64 GetRemoteModuleHandle64(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName)
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
				WCHAR BaseDllName[_MAX_FNAME] = { 0 };

				_wsplitpath_s(ModuleName, NULL, 0, NULL, 0, BaseDllName, _MAX_FNAME, NULL, 0);

				WCHAR RemoteModuleName[_MAX_FNAME];

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

					_wcsnset_s(RemoteModuleName, '\0', _MAX_PATH);

					Status = NtWow64ReadVirtualMemory64(ProcessHandle, DataTableEntry.BaseDllName.Buffer, &RemoteModuleName, DataTableEntry.BaseDllName.MaximumLength, NULL);

					if (!NT_SUCCESS(Status))
						break;

					_wsplitpath_s(RemoteModuleName, NULL, 0, NULL, 0, RemoteModuleName, _MAX_FNAME, NULL, 0);

					if (_wcsicmp(BaseDllName, RemoteModuleName) == 0)
					{
						ModuleHandle = DataTableEntry.DllBase;
						break;
					}

					NextModule = DataTableEntry.InLoadOrderLinks.Flink;

				} while (FirstModule != NextModule);
			}
		}
	}
	RtlSetLastWin32Error(RtlNtStatusToDosError(Status));

	return ModuleHandle;
}

/*
    IsDll64 - Поиск 64-битного dll в АП 32-х битного процесса. (ntdll.dll, wow64.dll, wow64cpu.dll etc)
*/
DWORD64 GetRemoteModuleHandle(_In_ HANDLE ProcessHandle, _In_ LPCWSTR ModuleName, _In_opt_ BOOLEAN IsDll64)
{
	switch (GetProcessBit(ProcessHandle))
	{
	    case 32 : {
			if (IsDll64)
				return GetRemoteModuleHandle64(ProcessHandle, ModuleName);
			else
				return GetRemoteModuleHandle32(ProcessHandle, ModuleName);
			break;
		}
		case 64 : return GetRemoteModuleHandle64(ProcessHandle, ModuleName);
			break;

		default : return 0;
	}
}

/*
*/
DWORD64 GetRemoteModuleHandleA(_In_ HANDLE ProcessHandle, _In_ LPCSTR ModuleName, _In_opt_ BOOLEAN IsDll64)
{
	WCHAR TempName[_MAX_PATH] = { 0 };

	int Length = MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, NULL, 0);

	MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, TempName, Length);

	return GetRemoteModuleHandle(ProcessHandle, TempName, IsDll64);
}

/*
*/
DWORD64 GetRemoteProcedureAddress64(_In_ HANDLE ProcessHandle, _In_ DWORD64 ModuleBase, _In_ LPCSTR ProcedureName)
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
#ifdef __cplusplus
			    case IMAGE_FILE_MACHINE_I386: DataDirectory = PIMAGE_NT_HEADERS32(&NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				   break;
#endif
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

					CHAR RemoteProcedureName[_MAX_FNAME];

					for (DWORD IndexName = 0; IndexName < ExportDirectory.NumberOfNames - 1; IndexName++)
					{
						Status = NtWow64ReadVirtualMemory64(ProcessHandle, AddressOfNames + (IndexName * sizeof(IndexName)), &NameRVA, sizeof(NameRVA), NULL);

						if (NT_SUCCESS(Status))
						{
							RtlSecureZeroMemory(&RemoteProcedureName, sizeof(RemoteProcedureName));

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

						if (ProcedureAddress >= DataDirectory.VirtualAddress && ProcedureAddress < (DataDirectory.VirtualAddress + DataDirectory.Size))
						{
							CHAR ForwardedName[_MAX_FNAME] = { 0 };

							Status = NtWow64ReadVirtualMemory64(ProcessHandle, ProcedureAddress, &ForwardedName, sizeof(ForwardedName), NULL);

							if (NT_SUCCESS(Status))
							{
								PCHAR pProcName = strchr(ForwardedName, '.');

								if (!pProcName)
									return 0;

								*pProcName++ = '\0';

								if (*pProcName == '#')
								{
									*pProcName++ = '\0';

									pProcName = (PCHAR)(WORD)atoi(pProcName);
								}
								ProcedureAddress = GetRemoteProcedureAddress64(ProcessHandle, GetRemoteModuleHandleA(ProcessHandle, ForwardedName, FALSE), pProcName);
							}
						}
					}
				}
			}
		}
	}
	RtlSetLastWin32Error(RtlNtStatusToDosError(Status));

	return ProcedureAddress;
}

/*
*/
DWORD GetRemoteProcedureAddress(_In_ HANDLE ProcessHandle, _In_ HANDLE ModuleBase, _In_ LPCSTR ProcedureName)
{
	if (!ModuleBase)
		return 0;

	DWORD ProcedureAddress = 0;

	IMAGE_DOS_HEADER ImageDosHeader = { 0 };

	if (ReadProcessMemory(ProcessHandle, ModuleBase, &ImageDosHeader, sizeof(ImageDosHeader), NULL))
	{
		if (ImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		IMAGE_NT_HEADERS ImageNtHeaders = { 0 };

		if (ReadProcessMemory(ProcessHandle, (PVOID)((LPBYTE)ModuleBase + ImageDosHeader.e_lfanew), &ImageNtHeaders, sizeof(ImageNtHeaders), NULL))
		{
			if (ImageNtHeaders.Signature != IMAGE_NT_SIGNATURE)
				return 0;

			IMAGE_DATA_DIRECTORY DataDirectory = ImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

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

					CHAR RemoteProcedureName[_MAX_FNAME];

					for (DWORD IndexName = 0; IndexName < ExportDirectory.NumberOfNames - 1; IndexName++)
					{
						if (ReadProcessMemory(ProcessHandle, ((LPBYTE)AddressOfNames + (IndexName * sizeof(IndexName))), &NameRVA, sizeof(NameRVA), NULL))
						{
							RtlSecureZeroMemory(&RemoteProcedureName, sizeof(RemoteProcedureName));

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
					ProcedureAddress = (DWORD)((LPBYTE)ModuleBase + ProcedureRVA);

					if ((SIZE_T)ProcedureAddress >= DataDirectory.VirtualAddress && (SIZE_T)ProcedureAddress < (DataDirectory.VirtualAddress + DataDirectory.Size))
					{
						CHAR ForwardedName[_MAX_FNAME] = { 0 };

						if (ReadProcessMemory(ProcessHandle, (PVOID)ProcedureAddress, &ForwardedName, sizeof(ForwardedName), NULL))
						{
							PCHAR pProcName = strchr(ForwardedName, '.'); //

							*pProcName++ = '\0';

							if (*pProcName == '#') //
							{
								*pProcName++ = '\0';

								pProcName = (PCHAR)(WORD)atoi(pProcName);
							}
							ProcedureAddress = GetRemoteProcedureAddress(ProcessHandle, (HANDLE)GetRemoteModuleHandleA(ProcessHandle, ForwardedName, FALSE), pProcName);
						}
					}
				}
			}
		}
	}
	return ProcedureAddress;
}

#ifdef CROSSINJECT1
/*
   WoW64 -> Win64
*/
BOOLEAN InjectDllWoW64(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ BOOLEAN UnloadDll, _In_opt_ PDWORD64 DllBase)
{
	DWORD Result = FALSE;

	NTSTATUS Status = STATUS_SUCCESS;

	DWORD64 RemoteRoutine = GetRemoteProcedureAddress64(ProcessHandle, GetRemoteModuleHandle64(ProcessHandle, L"kernel32.dll"), UnloadDll ? "FreeLibrary" : "LoadLibraryW");

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
			RemoteParameter = GetRemoteModuleHandle64(ProcessHandle, DllPath);

		if (NT_SUCCESS(Status) && RemoteParameter)
		{
			HANDLE64 ThreadHandle = 0;

			WOW64_CLIENT_ID64 ClientID = { 0 };

			NTSTATUS Status = RtlWow64CreateUserThread64(ProcessHandle, NULL, FALSE, 0, 0, 0, RemoteRoutine, RemoteParameter, &ThreadHandle, &ClientID);

			if (NT_SUCCESS(Status))
			{
				if (WaitForSingleObject((HANDLE)ThreadHandle, INFINITE) != WAIT_FAILED)
				{
					if (!UnloadDll && DllBase)
					{
						*DllBase = GetRemoteModuleHandle64(ProcessHandle, DllPath);

						if (*DllBase)
							Result = TRUE;
					} else
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
	return (BOOLEAN)Result;
}

/*
*/
BOOLEAN InjectDll(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ BOOLEAN UnloadDll, _In_opt_ PDWORD DllBase)
{
	BOOLEAN Result = FALSE;

	DWORD RemoteRoutine = GetRemoteProcedureAddress(ProcessHandle, (HANDLE)GetRemoteModuleHandle(ProcessHandle, L"kernel32.dll", FALSE), UnloadDll ? "FreeLibrary" : "LoadLibraryW");

	if (RemoteRoutine)
	{
		PVOID RemoteParameter = 0;

		DWORD DllNameSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);

		if (!UnloadDll)
		{
			RemoteParameter = VirtualAllocEx(ProcessHandle, NULL, DllNameSize, MEM_COMMIT, PAGE_READWRITE);

			if (!RemoteParameter)
				return FALSE;

			WriteProcessMemory(ProcessHandle, RemoteParameter, (PVOID)DllPath, DllNameSize, NULL);
		} 
		else
			RemoteParameter = (PVOID)GetRemoteModuleHandle(ProcessHandle, DllPath, FALSE);

		if (RemoteParameter)
		{
			HANDLE ThreadHandle = 0;

			CLIENT_ID ClientID = { 0 };

			NTSTATUS Status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)RemoteRoutine, RemoteParameter, &ThreadHandle, &ClientID);

			if (NT_SUCCESS(Status))
			{
				if (WaitForSingleObject(ThreadHandle, INFINITE) != WAIT_FAILED)
				{
					DWORD Temp = 0;

					GetExitCodeThread(ThreadHandle, (LPDWORD)&Temp);

					if (!UnloadDll && DllBase)
					{
						*DllBase = Temp;

						Result = Temp ? TRUE : FALSE;
					}
					else
						Result = (BOOLEAN)Temp;
				}
				CloseHandle(ThreadHandle);
			}
		}
		if (!UnloadDll && RemoteParameter)
			VirtualFreeEx(ProcessHandle, RemoteParameter, 0, MEM_RELEASE);
	}
	return Result;
}

#else

/*
   WoW64 -> Win64
*/
BOOLEAN InjectDllWoW64Ex(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ BOOLEAN UnloadDll, _In_opt_ PDWORD64 DllBase)
{
	// Shell64.asm
	static BYTE LoaderDll64[] =
	{
		0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0x53, 0x48, 0x89, 0xCB, 0x48, 0x83, 0xEC, 0x20,
		0x48, 0x8D, 0x4D, 0xE8, 0x48, 0x8D, 0x53, 0x28, 0xFF, 0x53, 0x20, 0x48, 0x83, 0xC4, 0x20, 0x48,
		0xC7, 0x45, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xC7, 0xC1, 0x00, 0x00,
		0x00, 0x00, 0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xE8, 0x4C, 0x8D, 0x4D,
		0xE0, 0xFF, 0x53, 0x18, 0x48, 0x83, 0xC4, 0x20, 0x80, 0x3B, 0x01, 0x75, 0x29, 0x48, 0x83, 0x7D,
		0xE0, 0x00, 0x76, 0x22, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x4D, 0xE0, 0xFF, 0x53, 0x10, 0x48,
		0x83, 0xC4, 0x20, 0x83, 0xF8, 0x00, 0x75, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8,
		0x00, 0x00, 0x00, 0x00, 0xEB, 0x3E, 0x80, 0x3B, 0x00, 0x75, 0x34, 0x48, 0x83, 0xEC, 0x20, 0x48,
		0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45,
		0xE8, 0x4C, 0x8D, 0x4D, 0xE0, 0xFF, 0x53, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x83, 0xF8, 0x00, 0x75,
		0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8,
		0x00, 0x00, 0x00, 0x00, 0x5B, 0xC9, 0xC3
	};

	DWORD Result = FALSE;

	TDllLoader64 InjectData = { 0 };

	InjectData.UnloadDll = UnloadDll;

	wcscpy_s(InjectData.DllPath, _countof(InjectData.DllPath), DllPath);

	DWORD64 hNtdll = GetRemoteModuleHandle64(ProcessHandle, L"ntdll.dll");

	if (!hNtdll)
		return FALSE;

	InjectData.LdrLoadDll = GetRemoteProcedureAddress64(ProcessHandle, hNtdll, "LdrLoadDll");

	if (!InjectData.LdrLoadDll)
		return FALSE;

	InjectData.LdrUnloadDll = GetRemoteProcedureAddress64(ProcessHandle, hNtdll, "LdrUnloadDll");

	if (!InjectData.LdrUnloadDll)
		return FALSE;

	InjectData.LdrGetDllHandle = GetRemoteProcedureAddress64(ProcessHandle, hNtdll, "LdrGetDllHandle");

	if (!InjectData.LdrGetDllHandle)
		return FALSE;

	InjectData.RtlInitUnicodeString = GetRemoteProcedureAddress64(ProcessHandle, hNtdll, "RtlInitUnicodeString");

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
							GetExitCodeThread((HANDLE)ThreadHandle, &Result);

							if (!UnloadDll && DllBase)
								*DllBase = GetRemoteModuleHandle64(ProcessHandle, DllPath);
						}
						CloseHandle((HANDLE)ThreadHandle);
					}
				}
				LoaderSize = 0;

				NtWow64FreeVirtualMemory64(ProcessHandle, &ShellCode, &LoaderSize, MEM_RELEASE);
			}
		}
		ShellSize = 0;

		NtWow64FreeVirtualMemory64(ProcessHandle, &ShellData, &ShellSize, MEM_RELEASE);
	}
	return (BOOLEAN)Result;
}

/*
*/
BOOLEAN InjectDllEx(_In_ HANDLE ProcessHandle, _In_ LPCWSTR DllPath, _In_opt_ BOOLEAN UnloadDll, _In_opt_ PDWORD DllBase)
{
	// Shell32.asm
	static BYTE LoaderDll32[] =
	{
		0x55, 0x89, 0xE5, 0x83, 0xEC, 0x0C, 0x53, 0x8B, 0x5D, 0x08, 0x8D, 0x53, 0x14, 0x52, 0x8D, 0x55,
		0xF8, 0x52, 0xFF, 0x53, 0x10, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x55, 0xF4, 0x52,
		0x8D, 0x55, 0xF8, 0x52, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x53, 0x0C, 0x80, 0x3B, 0x01, 0x75, 0x1F,
		0x83, 0x7D, 0xF4, 0x00, 0x76, 0x19, 0xFF, 0x75, 0xF4, 0xFF, 0x53, 0x08, 0x83, 0xF8, 0x00, 0x75,
		0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x23, 0x80,
		0x3B, 0x00, 0x75, 0x19, 0x8D, 0x55, 0xF4, 0x52, 0x8D, 0x55, 0xF8, 0x52, 0x6A, 0x00, 0x6A, 0x00,
		0xFF, 0x53, 0x04, 0x83, 0xF8, 0x00, 0x75, 0x03, 0x8B, 0x45, 0xF4, 0xEB, 0x05, 0xB8, 0x00, 0x00,
		0x00, 0x00, 0x5B, 0xC9, 0xC2, 0x04, 0x00
	};

	BOOLEAN Result = FALSE;

	TDllLoader InjectData = { 0 };

	InjectData.UnloadDll = UnloadDll;

	wcscpy_s(InjectData.DllPath, _countof(InjectData.DllPath), DllPath);

	HANDLE hNtdll = (HANDLE)GetRemoteModuleHandle(ProcessHandle, L"ntdll.dll", FALSE);

	if (!hNtdll)
		return FALSE;

	InjectData.LdrLoadDll = (pfnLdrLoadDll)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrLoadDll");

	if (!InjectData.LdrLoadDll)
		return FALSE;

	InjectData.LdrUnloadDll = (pfnLdrUnloadDll)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrUnloadDll");

	if (!InjectData.LdrUnloadDll)
		return FALSE;

	InjectData.LdrGetDllHandle = (pfnLdrGetDllHandle)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "LdrGetDllHandle");

	if (!InjectData.LdrGetDllHandle)
		return FALSE;

	InjectData.RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetRemoteProcedureAddress(ProcessHandle, hNtdll, "RtlInitUnicodeString");

	if (!InjectData.RtlInitUnicodeString)
		return FALSE;

	PVOID ShellData = VirtualAllocEx(ProcessHandle, NULL, sizeof(InjectData), MEM_COMMIT, PAGE_READWRITE);

	if (ShellData)
	{
		if (WriteProcessMemory(ProcessHandle, ShellData, &InjectData, sizeof(InjectData), NULL))
		{
			PVOID ShellCode = VirtualAllocEx(ProcessHandle, NULL, sizeof(LoaderDll32), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (ShellCode)
			{
				if (WriteProcessMemory(ProcessHandle, ShellCode, &LoaderDll32, sizeof(LoaderDll32), NULL))
				{
					HANDLE ThreadHandle = 0;

					CLIENT_ID ClientID = { 0 };

					NTSTATUS Status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)ShellCode, ShellData, &ThreadHandle, &ClientID);

					if (NT_SUCCESS(Status))
					{
						if (WaitForSingleObject(ThreadHandle, INFINITE) != WAIT_FAILED)
						{
							DWORD Temp = 0;

							GetExitCodeThread(ThreadHandle, (LPDWORD)&Temp);

							if (!UnloadDll && DllBase)
								*DllBase = Temp;

							Result = Temp ? TRUE : FALSE;
						}
						CloseHandle(ThreadHandle);
					}
				}
				VirtualFreeEx(ProcessHandle, ShellCode, 0, MEM_RELEASE);
			}
		}
		VirtualFreeEx(ProcessHandle, ShellData, 0, MEM_RELEASE);
	}
	return Result;
}
#endif

/*
*/
BOOLEAN CrossInjectDll(_In_ DWORD ProcessID, _In_ LPCWSTR DllPath, _In_opt_ BOOLEAN UnloadDll, _In_opt_ PDWORD64 DllBase)
{
	BOOLEAN Result = FALSE;

	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, ProcessID);

	if (ProcessHandle)
	{
		switch (GetProcessBit(ProcessHandle))
		{
#ifdef CROSSINJECT1
		    case 32: Result = InjectDll(ProcessHandle, DllPath, UnloadDll, (PDWORD)DllBase);
			    break;
		    case 64: Result = InjectDllWoW64(ProcessHandle, DllPath, UnloadDll, DllBase);
#else
		    case 32: Result = InjectDllEx(ProcessHandle, DllPath, UnloadDll, (PDWORD)DllBase);
			    break;
		    case 64: Result = InjectDllWoW64Ex(ProcessHandle, DllPath, UnloadDll, DllBase);
#endif
			    break;
		}
		CloseHandle(ProcessHandle);
	}
	return Result;
}

/*
*/
BOOLEAN GetFullPath(_In_ PWCHAR PartialPath, _Out_ PWCHAR FullPath)
{
	if (!FullPath)
		return FALSE;

	if (!PathIsRelativeW(PartialPath))
	{
		wcscpy_s(FullPath, _MAX_PATH, PartialPath);

		return IsFileExists(FullPath);
	}

	WCHAR TempPath[_MAX_PATH] = { 0 };

	if (_wfullpath(TempPath, PartialPath, _MAX_PATH))
	{
		if (IsFileExists(TempPath))
		{
			wcscpy_s(FullPath, _MAX_PATH, TempPath);

			return TRUE;
		}
	}

	_wcsnset_s(TempPath, '\0', _MAX_PATH);

	if (GetModuleFileNameW(NULL, TempPath, _MAX_PATH) > 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		WCHAR Disk[_MAX_DRIVE] = { 0 };

		WCHAR FileName[_MAX_FNAME] = { 0 };

		WCHAR Ext[_MAX_EXT] = { 0 };

		_wsplitpath_s(TempPath, Disk, _MAX_DRIVE, TempPath, _MAX_DIR, NULL, 0, NULL, 0);

		_wsplitpath_s(PartialPath, NULL, 0, NULL, 0, FileName, _MAX_FNAME, Ext, _MAX_EXT);

		_wmakepath_s(FullPath, _MAX_PATH, Disk, TempPath, FileName, Ext);

		return IsFileExists(FullPath);

		/*
		WCHAR NewPath[_MAX_PATH] = { 0 };

		PWCHAR Delimiter = wcsrchr(TempPath, L'\\') + 1;

		*Delimiter = '\0';

		wcscpy_s(NewPath, _MAX_PATH, TempPath);

		wcscat_s(NewPath, _MAX_PATH, PartialPath);

		if (IsFileExists(NewPath))
		{
			wcscpy_s(FullPath, _MAX_PATH, NewPath);

			return TRUE;
		}
		*/
	}
	return FALSE;
}

/*
*/
int main(int argc, char* argv[])
{
	setlocale(LC_CTYPE, "ru_RU.utf8");

	wprintf_s(L"Использование: CrossInject [Options] [DllPath]\n\n");

	wprintf_s(L"--ProcessID   Внедрение по ID процесса\n");
	wprintf_s(L"--ProcessName Внедрение по имени процесса\n");
	wprintf_s(L"--WindowName  Внедрение по имени окна процесса (Если оно есть)\n");
	wprintf_s(L"--DllPath     Полный путь к внедряемой библиотеке\n");
	wprintf_s(L"--Unload      Флаг для выгрузки библиотеки из памяти процесса\n\n");

	wprintf_s(L"Пример: CrossInject --ProcessName notepad++.exe --DllPath TestDll64.dll\n\n");

	int nArgs = 0;

	int ProcessID = -1;

	BOOLEAN UnloadDll = FALSE;

	WCHAR FullPath[_MAX_PATH] = { 0 };

	PWCHAR ProcessName = NULL, WindowName = NULL, DllPath = NULL;

	LPWSTR* ArgList = CommandLineToArgvW(GetCommandLineW(), &nArgs);

	if (nArgs > 1 && nArgs <= 6)
	{
		for (int i = 1; i < nArgs; ++i)
		{
			if (ProcessID < 0)
			{
				if (_wcsicmp(ArgList[i], L"--ProcessID") == 0)
				{
					ProcessID = _wtoi(ArgList[i + 1]);
				}
				else if (_wcsicmp(ArgList[i], L"--ProcessName") == 0)
				{
					ProcessName = ArgList[i + 1];

					ProcessID = GetProcessIDByName(ProcessName);

					wprintf_s(L"Имя процесса: %ws\n", ProcessName);
				}
				else if (_wcsicmp(ArgList[i], L"--WindowName") == 0)
				{
					WindowName = ArgList[i + 1];

					ProcessID = GetProcessIDByWindow(WindowName);

					wprintf_s(L"Имя окна: %ws\n", WindowName);
				}
			}

			if (!DllPath)
			{
				if (_wcsicmp(ArgList[i], L"--DllPath") == 0)
				{
					DllPath = ArgList[i + 1];

					GetFullPath(DllPath, FullPath);

					wprintf_s(L"Имя библиотеки: %ws\n", FullPath);
				}
			}

			if (_wcsicmp(ArgList[i], L"--Unload") == 0)
			{
				UnloadDll = TRUE;
			}
		}

		if (ProcessID > 0)
		{
			if (IsFileExists(FullPath))
			{
				wprintf_s(L"ID процесса: %d\n", ProcessID);
				wprintf_s(L"Разрядность процесса: x%d\n", GetProcessBit2(ProcessID));
				wprintf_s(L"Разрядность библиотеки: x%d\n", GetDllArch(FullPath));
				wprintf_s(L"Запрос отладочных привилегий...\n");

				if (SetProcessPrivilege(GetCurrentProcess(), L"SeDebugPrivilege", TRUE, NULL)) // Нужны права админа, иначе ошибка ERROR_PRIVILEGE_NOT_HELD
					wprintf_s(L"Успешно!\n");
				else
					wprintf_s(L"Ошибка! Возможно, недостаточно прав.\n");

				if (UnloadDll)
					wprintf_s(L"Выгрузка...\n");
				else
					wprintf_s(L"Внедрение...\n");

				DWORD64 DllBase = 0;

				if (CrossInjectDll(ProcessID, FullPath, UnloadDll, &DllBase))
				{
					if (UnloadDll)
						wprintf_s(L"Выгружено!\n");
					else
						wprintf_s(L"Адрес: 0x%I64x\n", DllBase);
				} 
				else
					wprintf_s(L"Ошибка!\n");
			} 
			else
				wprintf_s(L"Библиотека не найдена!\n");
		} 
		else
			wprintf_s(L"Процесс не найден!\n");
	} 
	else
		wprintf_s(L"Неверное количество параметров!");

	LocalFree(ArgList);

	return 0;
}