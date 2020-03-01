/*
*  Copyright (c) 2019 Wolk-1024 <wolk1024@gmail.com>
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

#ifdef __cplusplus
extern "C" {
#endif

DWORD64 asm_x64Call(_In_ DWORD64 pfnProc64, _In_ int nArgs, ...);

DWORD64 asm_GetModuleHandle64(_In_ LPCWSTR lpModuleName);

DWORD64 asm_GetProcAddress64(_In_ DWORD64 hModule, _In_ LPCSTR lpProcName);

void asm_memcpy64(_In_ DWORD64 Dest, _In_ DWORD64 Src, _In_ DWORD Size);

BOOLEAN asm_memcmp64(_In_ DWORD64 Dest, _In_ DWORD64 Src, _In_ DWORD Size);

void asm_memset64(_In_ DWORD64 Dest, _In_ char Val, _In_ DWORD Size);

DWORD64 asm_GetTeb64();

DWORD64 asm_GetPeb64();

BOOLEAN asm_IsWoW64();

#ifdef __cplusplus
}; // extern "C"
#endif