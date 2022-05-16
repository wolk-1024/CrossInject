format PE GUI

entry DllLoader32

include 'win32ax.inc'

STATUS_SUCCESS equ 0x00000000

section '.text' code readable executable

struc UNICODE_STRING
{
   .Length dw ?
   .MaximumLength dw ?
   .Buffer dd ?
}

struc TDllLoader
{
   .UnloadDll dq ?
   .LdrLoadDll dq ?
   .LdrUnloadDll dq ?
   .LdrGetDllHandle dq ?
   .RtlInitUnicodeString dq ?
   .DllPath dw MAX_PATH dup (?)
}

proc DllLoader32 uses ebx, Parameters

  local DllHandle dd ?

  local DllName UNICODE_STRING

     mov  ebx, dword [Parameters]

  virtual at ebx

     Loader TDllLoader

  end virtual

      stdcall dword [Loader.RtlInitUnicodeString], addr DllName, addr Loader.DllPath

      mov  dword [DllHandle], 0

      stdcall dword [Loader.LdrGetDllHandle], 0, 0, addr DllName, addr DllHandle

      .if ( byte [Loader.UnloadDll] = TRUE ) & ( dword [DllHandle] > 0 )

          stdcall dword [Loader.LdrUnloadDll], dword [DllHandle]

      .elseif ( byte [Loader.UnloadDll] = FALSE )

         stdcall dword [Loader.LdrLoadDll], 0, 0, addr DllName, addr DllHandle

      .endif
.Exit:
      ret
endp