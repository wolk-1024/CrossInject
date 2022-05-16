format PE64 GUI

entry DllLoader64

include 'win64ax.inc'

STATUS_SUCCESS = 0x00000000

section '.text' code readable executable

struc UNICODE_STRING
{
   .Length dw ?
   .MaximumLength dw ?
   .Buffer dq ?
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

proc DllLoader64 c uses rbx

  local DllHandle dq ?

  local DllName UNICODE_STRING

     mov  rbx, rcx

  virtual at rbx

     Loader TDllLoader

  end virtual

      invoke Loader.RtlInitUnicodeString, addr DllName, addr Loader.DllPath

      mov  qword [DllHandle], 0

      invoke Loader.LdrGetDllHandle, 0, 0, addr DllName, addr DllHandle

      .if ( byte [Loader.UnloadDll] = TRUE ) & ( qword [DllHandle] > 0 )

          invoke Loader.LdrUnloadDll, qword [DllHandle]

      .elseif ( byte [Loader.UnloadDll] = FALSE )

         invoke Loader.LdrLoadDll, 0, 0, addr DllName, addr DllHandle

      .endif
.Exit:
      ret
endp