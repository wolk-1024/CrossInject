format PE GUI
entry Start

include 'win32ax.inc'

STATUS_SUCCESS equ 0x00000000
STATUS_DLL_NOT_FOUND equ 0xC0000135

section '.text' code readable executable

struc UNICODE_STRING
{
   .Length dw ?
   .MaximumLength dw ?
   .Buffer dd ?
}

struc TDllLoader
{
   .UnloadDll dd ?
   .LdrLoadDll dd ?
   .LdrUnloadDll dd ?
   .LdrGetDllHandle dd ?
   .RtlInitUnicodeString dd ?
   .DllPath dw MAX_PATH dup (?)
}

proc DllLoader32 uses ebx, Parameters

  local DllHandle dd ?

  local DllName UNICODE_STRING

     mov  ebx, dword [Parameters]

  virtual at ebx

     Loader TDllLoader

  end virtual

      invoke Loader.RtlInitUnicodeString, addr DllName, addr Loader.DllPath

      mov  dword [DllHandle], 0

      invoke Loader.LdrGetDllHandle, 0, 0, addr DllName, addr DllHandle

      .if ( byte [Loader.UnloadDll] = TRUE ) & ( dword [DllHandle] > 0 )

          invoke Loader.LdrUnloadDll, dword [DllHandle]

          .if eax = STATUS_SUCCESS
              mov  eax, TRUE
          .else
              mov  eax, FALSE
          .endif

      .elseif ( byte [Loader.UnloadDll] = FALSE )

         invoke Loader.LdrLoadDll, 0, 0, addr DllName, addr DllHandle

          .if eax = STATUS_SUCCESS
              mov  eax, dword [DllHandle]
          .endif

      .else
         mov  eax, FALSE
      .endif
.Exit:
      ret
endp

Start:

      invoke GetModuleHandleW, addr Ntdll

      mov  ebx, eax

      invoke GetProcAddress, ebx, addr LdrLoadDll

      mov dword [DataLoader.LdrLoadDll], eax

      invoke GetProcAddress, ebx, addr LdrUnloadDll

      mov dword [DataLoader.LdrUnloadDll], eax

      invoke GetProcAddress, ebx, addr LdrGetDllHandle

      mov dword [DataLoader.LdrGetDllHandle], eax

      invoke GetProcAddress, ebx, addr RtlInitUnicodeString

      mov dword [DataLoader.RtlInitUnicodeString], eax

      invoke lstrcpyW, DataLoader.DllPath, DllPath

      mov byte [DataLoader.UnloadDll], 0

      stdcall DllLoader32, DataLoader

      mov byte [DataLoader.UnloadDll], 1

      stdcall DllLoader32, DataLoader

      mov byte [DataLoader.UnloadDll], 0

      stdcall DllLoader32, DataLoader

      ret

section '.data' data readable writeable

      DataLoader TDllLoader

      Ntdll du 'ntdll.dll', 0h
      LdrLoadDll db 'LdrLoadDll', 0h
      LdrUnloadDll db 'LdrUnloadDll', 0h
      LdrGetDllHandle db 'LdrGetDllHandle', 0h
      RtlInitUnicodeString db 'RtlInitUnicodeString', 0h

      DllPath du 'C:\Users\Admin\Desktop\Inject\TestDll32.dll', 0h

section '.idata' import data readable writeable

      library kernel32,'KERNEL32.DLL'

      include 'api\kernel32.inc'




