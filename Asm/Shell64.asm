format PE64 GUI
entry Start

include 'win64ax.inc'

STATUS_SUCCESS equ 0x00000000
STATUS_DLL_NOT_FOUND equ 0xC0000135

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

          .if eax = STATUS_SUCCESS
              mov  eax, TRUE
          .else
              mov  eax, FALSE
          .endif

      .elseif ( byte [Loader.UnloadDll] = FALSE )

         invoke Loader.LdrLoadDll, 0, 0, addr DllName, addr DllHandle

          .if eax = STATUS_SUCCESS
              mov  eax, TRUE
          .else
              mov  eax, FALSE
          .endif

      .else
         mov  eax, FALSE
      .endif
.Exit:
      ret
endp

Start:

      sub   rsp, 8

      invoke GetModuleHandleA, 'ntdll.dll'

      mov  rbx, rax

      invoke GetProcAddress, rbx, 'LdrLoadDll'

      mov qword [DataLoader.LdrLoadDll], rax

      invoke GetProcAddress, rbx, 'LdrUnloadDll'

      mov qword [DataLoader.LdrUnloadDll], rax

      invoke GetProcAddress, rbx, 'LdrGetDllHandle'

      mov qword [DataLoader.LdrGetDllHandle], rax

      invoke GetProcAddress, rbx, 'RtlInitUnicodeString'

      mov qword [DataLoader.RtlInitUnicodeString], rax

      invoke lstrcpyW, DataLoader.DllPath, DllPath

      mov byte [DataLoader.UnloadDll], 0

      stdcall DllLoader64, DataLoader

      mov byte [DataLoader.UnloadDll], 1

      stdcall DllLoader64, DataLoader

      mov byte [DataLoader.UnloadDll], 0

      stdcall DllLoader64, DataLoader

      add   rsp, 8

      ret

section '.data' data readable writeable

      DataLoader TDllLoader

      DllPath du 'C:\Users\Admin\Desktop\Inject\TestDll64.dll', 0h

section '.idata' import data readable writeable

      library kernel32,'KERNEL32.DLL'

      include 'api\kernel32.inc'




