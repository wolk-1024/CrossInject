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

#include <Shlwapi.h>
#include <stdio.h>
#include <locale.h>

#include "CrossInject.hpp"

#pragma comment(lib, "Shlwapi.lib")

/*
*/
BOOLEAN IsFileExists(_In_ PCWSTR Path)
{
	DWORD Attrib = GetFileAttributesW(Path);

	return (Attrib != INVALID_FILE_ATTRIBUTES && !(Attrib & FILE_ATTRIBUTE_DIRECTORY));
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

		WCHAR Dir[_MAX_DIR] = { 0 };

		WCHAR FileName[_MAX_FNAME] = { 0 };

		WCHAR Ext[_MAX_EXT] = { 0 };

		_wsplitpath_s(TempPath, Disk, _MAX_DRIVE, Dir, _MAX_DIR, NULL, 0, NULL, 0);

		_wsplitpath_s(PartialPath, NULL, 0, NULL, 0, FileName, _MAX_FNAME, Ext, _MAX_EXT);

		_wmakepath_s(FullPath, _MAX_PATH, Disk, Dir, FileName, Ext);

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

					wprintf_s(L"Путь к библиотеке: %ws\n", FullPath);
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

				if (CrossInjectDll(ProcessID, FullPath, &DllBase, UnloadDll))
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