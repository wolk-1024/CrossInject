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

#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <locale.h>

#include "NTOS\ntos.h"
#include "WoW64Utils\WoW64Utils.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/*
#if defined(__cplusplus)
extern "C" {
#endif

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(
	PVOID ThreadParameter
	);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
	_In_ HANDLE Process,
	_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	_In_ BOOLEAN CreateSuspended,
	_In_ ULONG StackZeroBits,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ SIZE_T InitialStackSize,
	_In_ PUSER_THREAD_START_ROUTINE StartAddress,
	_In_opt_ PVOID Parameter,
	_Out_opt_ PHANDLE Thread,
	_Out_opt_ PCLIENT_ID ClientId);

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
	_In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
	_In_ LONG Win32Error);

#ifdef __cplusplus
}
#endif
*/

typedef NTSTATUS(NTAPI *pfnLdrLoadDll) (
	_In_opt_ PCWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_  PCUNICODE_STRING DllName,
	_Out_ PVOID *DllHandle
	);

typedef NTSTATUS(NTAPI *pfnLdrUnloadDll) (
	_In_ PVOID DllHandle
	);

typedef NTSTATUS(NTAPI *pfnLdrGetDllHandle) (
	_In_opt_ PCWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_ PCUNICODE_STRING DllName,
	_Out_ PVOID *DllHandle
	);

typedef VOID(NTAPI *pfnRtlInitUnicodeString) (
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR SourceString
	);

typedef struct TDllLoader
{
	BOOLEAN UnloadDll;
	pfnLdrLoadDll LdrLoadDll;
	pfnLdrUnloadDll LdrUnloadDll;
	pfnLdrGetDllHandle LdrGetDllHandle;
	pfnRtlInitUnicodeString RtlInitUnicodeString;
	WCHAR DllPath[_MAX_PATH];
} TDllLoader, *PDllLoader;

typedef struct TDllLoader64
{
	BOOLEAN UnloadDll;
	DWORD64 LdrLoadDll;
	DWORD64 LdrUnloadDll;
	DWORD64 LdrGetDllHandle;
	DWORD64 RtlInitUnicodeString;
	WCHAR DllPath[_MAX_PATH];
} TDllLoader64, *PDllLoader64;