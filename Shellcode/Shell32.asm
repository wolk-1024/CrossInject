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