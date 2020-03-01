/*
*  Copyright (c) 2016 Wolk-1024 <wolk1024@gmail.com>
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

#include "WoW64Utils.h"

/*
   @28
*/
NTSTATUS
NTAPI
NtWow64ReadVirtualMemory64(
	_In_      HANDLE ProcessHandle,
	_In_      DWORD64 BaseAddress,
	_Out_     PVOID Buffer,
	_In_      DWORD64 NumberOfBytesToRead,
	_Out_opt_ DWORD64 *NumberOfBytesRead OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtReadVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 5, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)Buffer, (DWORD64)NumberOfBytesToRead, (DWORD64)NumberOfBytesRead);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @28
*/
NTSTATUS
NTAPI
NtWow64WriteVirtualMemory64(
	_In_      HANDLE ProcessHandle,
	_In_      DWORD64 BaseAddress,
	_In_      PVOID Buffer,
	_In_      DWORD64 NumberOfBytesToWrite,
	_Out_opt_ DWORD64 *NumberOfBytesWritten OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtWriteVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 5, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)Buffer, (DWORD64)NumberOfBytesToWrite, (DWORD64)NumberOfBytesWritten);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @24
*/
NTSTATUS
NTAPI
NtWow64AllocateVirtualMemory64(
	_In_    HANDLE ProcessHandle,
	_Inout_ DWORD64 *BaseAddress,
	_In_    DWORD ZeroBits,
	_Inout_ DWORD64 *RegionSize,
	_In_    DWORD AllocationType,
	_In_    DWORD Protect
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtAllocateVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 6, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)ZeroBits, (DWORD64)RegionSize, (DWORD64)AllocationType, (DWORD64)Protect);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @16
*/
NTSTATUS
NTAPI
NtWow64FreeVirtualMemory64(
	_In_    HANDLE ProcessHandle,
	_Inout_ DWORD64 *BaseAddress,
	_Inout_ DWORD64 *RegionSize,
	_In_    DWORD FreeType
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtFreeVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 4, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)RegionSize, (DWORD64)FreeType);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @20
*/
NTSTATUS
NTAPI
NtWow64ProtectVirtualMemory64(
	_In_    HANDLE ProcessHandle,
	_Inout_ DWORD64 *BaseAddress,
	_Inout_ DWORD64 *NumberOfBytesToProtect,
	_In_    DWORD NewAccessProtection,
	_Out_   PDWORD OldAccessProtection
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtProtectVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 5, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)NumberOfBytesToProtect, (DWORD64)NewAccessProtection, (DWORD64)OldAccessProtection);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @32
*/
NTSTATUS
NTAPI
NtWow64QueryVirtualMemory64(
	_In_      HANDLE ProcessHandle,
	_In_      DWORD64 BaseAddress,
	_In_      MEMORY_INFORMATION_CLASS64 MemoryInformationClass,
	_Out_     PVOID Buffer,
	_In_      DWORD64 Length,
	_Out_opt_ PDWORD64 ReturnLength OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtQueryVirtualMemory") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 6, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)MemoryInformationClass, (DWORD64)Buffer, (DWORD64)Length, (DWORD64)ReturnLength);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @20
*/
NTSTATUS
NTAPI
NtWow64QueryInformationThread64(
	_In_      HANDLE ThreadHandle,
	_In_      THREAD_INFORMATION_CLASS64 ThreadInformationClass,
	_Out_     PVOID ThreadInformation,
	_In_      DWORD ThreadInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtQueryInformationThread") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 5, (DWORD64)ThreadHandle, (DWORD64)ThreadInformationClass, (DWORD64)ThreadInformation, (DWORD64)ThreadInformationLength, (DWORD64)ReturnLength);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @20
*/
NTSTATUS
NTAPI
NtWow64QueryInformationProcess64(
	_In_      HANDLE ProcessHandle,
	_In_      PROCESS_INFORMATION_CLASS64 ProcessInformationClass,
	_Out_     PVOID ProcessInformation,
	_In_      DWORD ProcessInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtQueryInformationProcess") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 5, (DWORD64)ProcessHandle, (DWORD64)ProcessInformationClass, (DWORD64)ProcessInformation, (DWORD64)ProcessInformationLength, (DWORD64)ReturnLength);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @16
*/
NTSTATUS
NTAPI
NtWow64SetInformationProcess64(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESS_INFORMATION_CLASS64 ProcessInformationClass,
	_In_ PVOID ProcessInformation,
	_In_ DWORD ProcessInformationLength
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtSetInformationProcess") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 4, (DWORD64)ProcessHandle, (DWORD64)ProcessInformationClass, (DWORD64)ProcessInformation, (DWORD64)ProcessInformationLength);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @16
*/
NTSTATUS
NTAPI
NtWow64GetNativeSystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS64 SystemInformationClass,
	_Out_     PVOID SystemInformation,
	_In_      DWORD SystemInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtQuerySystemInformation") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 4, (DWORD64)SystemInformationClass, (DWORD64)SystemInformation, (DWORD64)SystemInformationLength, (DWORD64)ReturnLength);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @8
*/
NTSTATUS
NTAPI
NtWow64GetContextThread64(
	_In_  HANDLE ThreadHandle,
	_Out_ PCONTEXT64 Context
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtGetContextThread") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 2, (DWORD64)ThreadHandle, (DWORD64)Context);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @8
*/
NTSTATUS
NTAPI
NtWow64SetContextThread64(
	_In_ HANDLE ThreadHandle,
	_In_ PCONTEXT64 Context
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "NtSetContextThread") : 0;
	if (Proc64)
		return (NTSTATUS)x64Call(Proc64, 2, (DWORD64)ThreadHandle, (DWORD64)Context);
	else
		return STATUS_NOT_IMPLEMENTED;
}

/*
   @48
*/
NTSTATUS
NTAPI
RtlWow64CreateUserThread64(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	_In_     BOOLEAN CreateSuspended,
	_In_     DWORD StackZeroBits,
	_Inout_  PDWORD StackReserved,
	_Inout_  PDWORD StackCommit,
	_In_     DWORD64 StartAddress,
	_In_opt_ DWORD64 StartParameter OPTIONAL,
	_Out_    PHANDLE64 ThreadHandle,
	_Out_    PWOW64_CLIENT_ID64 ClientID
    )
{
	DWORD64 Proc64 = IsWoW64() ? GetProcAddress64(GetNtdll64(), "RtlCreateUserThread") : 0;
	if (Proc64)
	{
		return (NTSTATUS)x64Call(Proc64, 10,
			(DWORD64)ProcessHandle,          //
			(DWORD64)SecurityDescriptor,     //
			(DWORD64)CreateSuspended,        //
			(DWORD64)StackZeroBits,          //
			(DWORD64)StackReserved,          //
			(DWORD64)StackCommit,            //
			(DWORD64)StartAddress,           //
			(DWORD64)StartParameter,         //
			(DWORD64)ThreadHandle,           //
			(DWORD64)ClientID);              //
	}
	return STATUS_NOT_IMPLEMENTED;
}