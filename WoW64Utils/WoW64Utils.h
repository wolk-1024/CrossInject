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

#ifndef _WOW64UTILS_H
#define _WOW64UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_M_IX86
#error WoW64Utils.c must be compiled on x86!
#endif

#pragma comment(lib, "WoW64Utils.lib")

#include <Windows.h>

typedef long NTSTATUS;
typedef DWORD64 HANDLE64, *PHANDLE64;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_NOT_IMPLEMENTED (NTSTATUS)0xC0000002L

typedef struct _WOW64_CLIENT_ID64
{
	DWORD64 UniqueProcess;
	DWORD64 UniqueThread;
}  WOW64_CLIENT_ID64, *PWOW64_CLIENT_ID64;

typedef struct _WOW64_STRING
{
	WORD    Length;
	WORD    MaximumLength;
	DWORD64 Buffer;
} WOW64_STRING, *PWOW64_STRING;

typedef WOW64_STRING ANSI_STRING64, *PANSI_STRING64;
typedef WOW64_STRING UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _XSAVE_FORMAT64
{
	WORD  ControlWord;
	WORD  StatusWord;
	BYTE  TagWord;
	BYTE  Reserved1;
	WORD  ErrorOpcode;
	DWORD ErrorOffset;
	WORD  ErrorSelector;
	WORD  Reserved2;
	DWORD DataOffset;
	WORD  DataSelector;
	WORD  Reserved3;
	DWORD MxCsr;
	DWORD MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[16];
	BYTE  Reserved4[96];
} XSAVE_FORMAT64, *PXSAVE_FORMAT64;

typedef struct _CONTEXT64
{
	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;
	DWORD ContextFlags;
	DWORD MxCsr;
	WORD SegCs;
	WORD SegDs;
	WORD SegEs;
	WORD SegFs;
	WORD SegGs;
	WORD SegSs;
	DWORD EFlags;
	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;
	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	DWORD64 Rip;
	XSAVE_FORMAT64 FltSave;
	M128A Header[2];
	M128A Legacy[8];
	M128A Xmm0;
	M128A Xmm1;
	M128A Xmm2;
	M128A Xmm3;
	M128A Xmm4;
	M128A Xmm5;
	M128A Xmm6;
	M128A Xmm7;
	M128A Xmm8;
	M128A Xmm9;
	M128A Xmm10;
	M128A Xmm11;
	M128A Xmm12;
	M128A Xmm13;
	M128A Xmm14;
	M128A Xmm15;
	M128A VectorRegister[26];
	DWORD64 VectorControl;
	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} CONTEXT64, *PCONTEXT64;

typedef struct _PEB_LDR_DATA64
{
	DWORD Length;
	BOOLEAN Initialized;
	DWORD64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	DWORD64 EntryInProgress;
	BOOLEAN ShutdownInProgress;
	DWORD64 ShutdownThreadId;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	DWORD64 DllBase;
	DWORD64 EntryPoint;
	DWORD   SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	DWORD Flags;
	WORD  LoadCount;
	WORD  TlsIndex;
	union
	{
		LIST_ENTRY64 HashLinks;
		struct
		{
			DWORD64 SectionPointer;
			DWORD   CheckSum;
		};
	};
	union
	{
		DWORD  TimeDateStamp;
		DWORD64 LoadedImports;
	};
	DWORD64 EntryPointActivationContext;
	DWORD64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	DWORD64 ContextInformation;
	DWORD64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _RTL_DRIVE_LETTER_CURDIR64
{
	WORD Flags;
	WORD Length;
	DWORD TimeStamp;
	ANSI_STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, *PRTL_DRIVE_LETTER_CURDIR64;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
	DWORD        MaximumLength;                //
	DWORD        Length;                       //
	DWORD        Flags;                        //
	DWORD        DebugFlags;                   // 
	DWORD64      ConsoleHandle;                //  
	DWORD        ConsoleFlags;                 //           
	DWORD64      StdInputHandle;               // 
	DWORD64      StdOutputHandle;              //      
	DWORD64      StdErrorHandle;               //    
	UNICODE_STRING64 CurrentDirectoryPath;     //
	DWORD64      CurrentDirectoryHandle;       //  
	UNICODE_STRING64 DllPath;                  //      
	UNICODE_STRING64 ImagePathName;            //          
	UNICODE_STRING64 CommandLine;              //
	DWORD64      Environment;                  //
	DWORD        StartingX;                    //
	DWORD        StartingY;                    //               
	DWORD        Width;                        //
	DWORD        Height;                       //
	DWORD        CharWidth;                    //
	DWORD        CharHeight;                   //
	DWORD        ConsoleTextAttributes;        //
	DWORD        WindowFlags;                  //
	DWORD        ShowWindowFlags;              //
	UNICODE_STRING64 WindowTitle;              //
	UNICODE_STRING64 DesktopName;              //
	UNICODE_STRING64 ShellInfo;                //
	UNICODE_STRING64 RuntimeData;              //  
	RTL_DRIVE_LETTER_CURDIR64 DLCurrentDirectory[32];
	DWORD 	     EnvironmentSize;              // 
	DWORD 	     EnvironmentVersion;           //
	DWORD64 	 PackageDependencyData;        // 
	DWORD 	     ProcessGroupId;               //
	DWORD 	     LoaderThreads;                //
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _PROCESS_ENVIRONMENT_BLOCK64
{
	BOOLEAN InheritedAddressSpace;             //      
	BOOLEAN ReadImageFileExecOptions;          //
	BOOLEAN BeingDebugged;                     //
	union
	{
		BOOLEAN BitField;                      //
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	DWORD64 Mutant;                             //
	DWORD64 ImageBaseAddress;                   //
	DWORD64 Ldr;                                // PPEB_LDR_DATA64              
	DWORD64 ProcessParameters;                  // PRTL_USER_PROCESS_PARAMETERS64
	DWORD64 SubSystemData;                      //                     
	DWORD64 ProcessHeap;                        // 
	DWORD64 FastPebLock;                        //
	DWORD64 AtlThunkSListPtr;                   //         
	DWORD64 IFEOKey;                            //
	union
	{
		DWORD CrossProcessFlags;                //
		struct
		{
			DWORD ProcessInJob : 1;
			DWORD ProcessInitializing : 1;
			DWORD ProcessUsingVEH : 1;
			DWORD ProcessUsingVCH : 1;
			DWORD ProcessUsingFTH : 1;
			DWORD ReservedBits0 : 27;
		};
	};
	union
	{
		DWORD64 KernelCallbackTable;             //
		DWORD64 UserSharedInfoPtr;               //
	};
	DWORD   SystemReserved[1];                   //
	DWORD   AtlThunkSListPtr32;                  //
	DWORD64 ApiSetMap;                           //
	DWORD   TlsExpansionCounter;                 //
	DWORD64 TlsBitmap;                           //
	DWORD   TlsBitmapBits[2];                    //
	DWORD64 ReadOnlySharedMemoryBase;            // 
	DWORD64 HotpatchInformation;                 //
	DWORD64 ReadOnlyStaticServerData;            // DWORD64 *
	DWORD64 AnsiCodePageData;                    //
	DWORD64 OemCodePageData;                     //
	DWORD64 UnicodeCaseTableData;                //
	DWORD   NumberOfProcessors;                  //
	DWORD   NtGlobalFlag;                        //
	LARGE_INTEGER CriticalSectionTimeout;        //
	DWORD64 HeapSegmentReserve;                  //
	DWORD64 HeapSegmentCommit;                   //
	DWORD64 HeapDeCommitTotalFreeThreshold;      //
	DWORD64 HeapDeCommitFreeBlockThreshold;      //
	DWORD   NumberOfHeaps;                       //
	DWORD   MaximumNumberOfHeaps;                //
	DWORD64 ProcessHeaps;                        // DWORD64 *
	DWORD64 GdiSharedHandleTable;                //
	DWORD64 ProcessStarterHelper;                //
	DWORD64 GdiDCAttributeList;                  //
	DWORD64 LoaderLock;                          //
	DWORD   OSMajorVersion;                      //
	DWORD   OSMinorVersion;                      //
	WORD    OSBuildNumber;                       //
	WORD    OSCSDVersion;                        //
	DWORD   OSPlatformId;                        //
	DWORD   ImageSubsystem;                      //
	DWORD   ImageSubsystemMajorVersion;          //
	DWORD   ImageSubsystemMinorVersion;          //
	DWORD64 ActiveProcessAffinityMask;           //
	DWORD   GdiHandleBuffer[60];                 //
	DWORD64 PostProcessInitRoutine;              //
	DWORD64 TlsExpansionBitmap;                  //
	DWORD   TlsExpansionBitmapBits[32];          //
	DWORD64 SessionId;                           //
	ULARGE_INTEGER AppCompatFlags;               //
	ULARGE_INTEGER AppCompatFlagsUser;           //
	DWORD64 pShimData;                           //
	DWORD64 AppCompatInfo;                       //
	UNICODE_STRING64 CSDVersion;                 //
	DWORD64 ActivationContextData;               //
	DWORD64 ProcessAssemblyStorageMap;           //
	DWORD64 SystemDefaultActivationContextData;  //
	DWORD64 SystemAssemblyStorageMap;            //
	DWORD64 MinimumStackCommit;                  //
	DWORD64 FlsCallback;                         //
	LIST_ENTRY64 FlsListHead;                    //
	DWORD64 FlsBitmap;                           //
	DWORD   FlsBitmapBits[4];                    //
	DWORD   FlsHighIndex;                        //
	DWORD64 WerRegistrationData;                 //
	DWORD64 WerShipAssertPtr;                    //
	DWORD64 pContextData;                        //
	DWORD64 pImageHeaderHash;                    //
	union
	{
		DWORD TracingFlags;                      // 
		struct
		{
			DWORD HeapTracingEnabled : 1;
			DWORD CritSecTracingEnabled : 1;
			DWORD LibLoaderTracingEnabled : 1;
			DWORD SpareTracingBits : 29;
		};
	};
	DWORD64 CsrServerReadOnlySharedMemoryBase;   //
} PEB64, *PPEB64;

typedef struct _GDI_TEB_BATCH64
{
	DWORD    Offset;
	DWORD64  HDC;
	DWORD    Buffer[310];
} GDI_TEB_BATCH64, *PGDI_TEB_BATCH64;

typedef struct _THREAD_ENVIRONMENT_BLOCK64
{
	NT_TIB64    NtTib;                          //
	DWORD64     EnvironmentPointer;             //
	WOW64_CLIENT_ID64 ClientID;                 //
	DWORD64     ActiveRpcHandle;                //
	DWORD64     ThreadLocalStoragePointer;      //
	DWORD64     ProcessEnvironmentBlock;        // PPEB64
	DWORD       LastErrorValue;                 //
	DWORD       CountOfOwnedCriticalSections;   //
	DWORD64     CsrClientThread;                // 
	DWORD64     Win32ThreadInfo;                //
	DWORD       User32Reserved[26];             //
	DWORD       UserReserved[5];                //
	DWORD64     WOW32Reserved;                  //
	LCID        CurrentLocale;                  //
	DWORD       FpSoftwareStatusRegister;       //
	DWORD64     SystemReserved1[54];            //
	NTSTATUS    ExceptionCode;                  //
	DWORD64     ActivationContextStackPointer;  //
	BYTE        SpareBytes[24];                 //
	DWORD       TxFsContext;                    //
	GDI_TEB_BATCH64 GdiTebBatch;                //
	WOW64_CLIENT_ID64 RealClientId;             //
	DWORD64     GdiCachedProcessHandle;         //
	DWORD       GdiClientPID;                   //
	DWORD       GdiClientTID;                   //
	DWORD64     GdiThreadLocalInfo;             //
	DWORD64     Win32ClientInfo[62];            //
	DWORD64     glDispatchTable[233];           //
	DWORD64     glReserved1[29];                //
	DWORD64     glReserved2;                    //
	DWORD64     glSectionInfo;                  //
	DWORD64     glSection;                      //
	DWORD64     glTable;                        //
	DWORD64     glCurrentRC;                    //
	DWORD64     glContext;                      //
	NTSTATUS    LastStatusValue;                //
	UNICODE_STRING64 StaticUnicodeString;       //
	WCHAR       StaticUnicodeBuffer[261];       //
	DWORD64     DeallocationStack;              //
	DWORD64     TlsSlots[64];                   //
	LIST_ENTRY64 TlsLinks;                      //
	DWORD64     Vdm;                            //
	DWORD64     ReservedForNtRpc;               //
	DWORD64     DbgSsReserved[2];               //
	DWORD       HardErrorMode;                  //
	DWORD64     Instrumentation[11];            //
	GUID        ActivityId;                     //
	DWORD64     SubProcessTag;                  //
	DWORD64     EtwLocalData;                   //
	DWORD64     EtwTraceData;                   //
	DWORD64     WinSockData;                    //
	DWORD       GdiBatchCount;                  //
	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor; //
		DWORD   IdealProcessorValue;
		struct
		{
			WORD ReservedPad0;
			WORD ReservedPad1;
			WORD ReservedPad2;
			WORD IdealProcessor;
		};
	};
	DWORD   GuaranteedStackBytes;                //
	DWORD64 ReservedForPerf;                     //
	DWORD64 ReservedForOle;                      //
	DWORD   WaitingOnLoaderLock;                 //
	DWORD64 SavedPriorityState;                  // 
	DWORD64 SoftPatchPtr1;                       //
	DWORD64 ThreadPoolData;                      // 
	DWORD64 TlsExpansionSlots;                   // DWORD64 *
	DWORD64 DeallocationBStore;                  //
	DWORD64 BStoreLimit;                         // 
	DWORD   MuiGeneration;                       //  
	DWORD   IsImpersonating;                     //
	DWORD64 NlsCache;                            // 
	DWORD64 pShimData;                           //
	DWORD   HeapVirtualAffinity;                 //
	DWORD64 CurrentTransactionHandle;            // 
	DWORD64 ActiveFrame;                         //
	DWORD64 FlsData;                             //
	DWORD64 PreferredLanguages;                  //
	DWORD64 UserPrefLanguages;                   //
	DWORD64 MergedPrefLanguages;                 //
	DWORD   MuiImpersonation;                    //
	union
	{
		WORD CrossTebFlags;
		WORD SpareCrossTebBits : 16;
	};
	union
	{
		WORD SameTebFlags;                       //
		struct
		{
			WORD SafeThunkCall : 1;
			WORD InDebugPrint : 1;
			WORD HasFiberData : 1;
			WORD SkipThreadAttach : 1;
			WORD WerInShipAssertCode : 1;
			WORD RanProcessInit : 1;
			WORD ClonedThread : 1;
			WORD SuppressDebugMsg : 1;
			WORD DisableUserStackWalk : 1;
			WORD RtlExceptionAttached : 1;
			WORD InitialThread : 1;
			WORD SessionAware : 1;
			WORD SpareSameTebBits : 4;
		};
	};
	DWORD64 TxnScopeEnterCallback;               //
	DWORD64 TxnScopeExitCallback;                //
	DWORD64 TxnScopeContext;                     //
	DWORD   LockCount;                           //
	DWORD   SpareUlong0;                         //
	DWORD64 ResourceRetValue;                    //
} TEB64, *PTEB64;

typedef struct _SYSTEM_MODULE64
{
	DWORD64 Reserved1;
	DWORD64 Reserved2;
	DWORD64 ImageBaseAddress;
	DWORD   ImageSize;
	DWORD   Flags;
	WORD    Index;
	WORD    Unknown;
	WORD    LoadCount;
	WORD    ModuleNameOffset;
	CHAR    ModuleName[256];
} SYSTEM_MODULE64, *PSYSTEM_MODULE64;

typedef struct _SYSTEM_MODULE_INFORMATION64
{
	DWORD ModulesCount;
	SYSTEM_MODULE64 Modules[1];
} SYSTEM_MODULE_INFORMATION64, *PSYSTEM_MODULE_INFORMATION64;

typedef struct _RTL_PROCESS_MODULE_INFORMATION64
{
	DWORD64 Section;
	DWORD64  MappedBase;
	DWORD64  ImageBase;
	DWORD 	 ImageSize;
	DWORD 	 Flags;
	WORD 	 LoadOrderIndex;
	WORD 	 InitOrderIndex;
	WORD 	 LoadCount;
	WORD 	 OffsetToFileName;
	UCHAR    FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION64, *PRTL_PROCESS_MODULE_INFORMATION64;

typedef struct _RTL_PROCESS_MODULES64
{
	DWORD NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION64  Modules[1];
} RTL_PROCESS_MODULES64, *PRTL_PROCESS_MODULES64;

typedef long KPRIORITY;

typedef struct _SYSTEM_THREAD_INFORMATION64
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	DWORD WaitTime;
	DWORD64 StartAddress;
	WOW64_CLIENT_ID64 ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	DWORD ContextSwitchCount;
	DWORD State;
	DWORD WaitReason;
} SYSTEM_THREAD_INFORMATION64, *PSYSTEM_THREAD_INFORMATION64;

typedef struct _VM_COUNTERS64
{
	DWORD64 PeakVirtualSize;
	DWORD64 VirtualSize;
	DWORD 	PageFaultCount;
	DWORD64 PeakWorkingSetSize;
	DWORD64 WorkingSetSize;
	DWORD64 QuotaPeakPagedPoolUsage;
	DWORD64 QuotaPagedPoolUsage;
	DWORD64 QuotaPeakNonPagedPoolUsage;
	DWORD64 QuotaNonPagedPoolUsage;
	DWORD64 PagefileUsage;
	DWORD64 PeakPagefileUsage;
	DWORD64 PrivatePageCount;
} VM_COUNTERS64, *PVM_COUNTERS64;

typedef struct _IO_COUNTERS64
{
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} IO_COUNTERS64, PIO_COUNTERS64;

typedef struct _SYSTEM_PROCESS_INFORMATION64
{
	DWORD NextEntryOffset;
	DWORD NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	DWORD HardFaultCount;
	DWORD NumberOfThreadsHighWatermark;
	DWORD64 CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING64 ImageName;
	KPRIORITY BasePriority;
	DWORD64 UniqueProcessId;
	DWORD64 InheritedFromUniqueProcessId;
	DWORD HandleCount;
	DWORD SessionId;
	DWORD64 UniqueProcessKey;
	VM_COUNTERS64 VmCounters;
	IO_COUNTERS64 IoCounters;
	SYSTEM_THREAD_INFORMATION64 Threads[1];
} SYSTEM_PROCESS_INFORMATION64, *PSYSTEM_PROCESS_INFORMATION64;

typedef struct _THREAD_BASIC_INFORMATION64
{
	DWORD       ExitStatus;
	DWORD64     TebBaseAddress;      // PTEB64
	WOW64_CLIENT_ID64 ClientId;
	KAFFINITY   AffinityMask;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
} THREAD_BASIC_INFORMATION64, *PTHREAD_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION64
{
	DWORD     ExitStatus;
	DWORD64   PebBaseAddress;        // PPEB64
	DWORD64   AffinityMask;          // KAFFINITY
	KPRIORITY BasePriority;
	DWORD64   UniqueProcessId;
	DWORD64   InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

typedef enum _MEMORY_INFORMATION_CLASS64
{
	MemoryWow64BasicInformation,               // MEMORY_BASIC_INFORMATION64
	MemoryWow64MappedFilenameInformation = 2,  // UNICODE_STRING64
} MEMORY_INFORMATION_CLASS64;

typedef enum _THREAD_INFORMATION_CLASS64
{
	ThreadWow64BasicInformation,  // THREAD_BASIC_INFORMATION64
} THREAD_INFORMATION_CLASS64;

typedef enum _PROCESS_INFORMATION_CLASS64
{
	ProcessWow64BasicInformation, // PROCESS_BASIC_INFORMATION64  
} PROCESS_INFORMATION_CLASS64;

typedef enum _SYSTEM_INFORMATION_CLASS64
{
	SystemWow64ProcessInformation = 5, // SYSTEM_PROCESS_INFORMATION64
	SystemWow64ModuleInformation = 11, // SYSTEM_MODULE_INFORMATION64
} SYSTEM_INFORMATION_CLASS64;

#define WIN32_SEGMENT 0x1B
#define WOW64_SEGMENT 0x23
#define WIN64_SEGMENT 0x33

#define EMIT(a) __asm __emit(a)
#define REX_W EMIT(0x48) __asm

#define jmp33 \
{ \
    EMIT(0x6A) EMIT(WIN64_SEGMENT)                         \
    EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00) \
    EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)            \
    EMIT(0xCB)                                             \
};

#define jmp23 \
{ \
    EMIT(0x6A) EMIT(WOW64_SEGMENT)                         \
    EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00) \
    EMIT(0x48) EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x07) \
    EMIT(0x48) EMIT(0xCB)                                  \
};

DWORD64 __cdecl x64Call(_In_ DWORD64 pfnProc64, _In_ int nArgs, ...);
DWORD64 __cdecl GetModuleHandle64(_In_ LPCWSTR lpModuleName);
DWORD64 __cdecl GetProcAddress64(_In_ DWORD64 hModule, _In_ LPCSTR lpProcName);
void    __cdecl memcpy64(_In_ DWORD64 Dest, _In_ DWORD64 Src, _In_ DWORD Size);
BOOLEAN __cdecl memcmp64(_In_ DWORD64 Dest, _In_ DWORD64 Src, _In_ DWORD Size);
void    __cdecl memset64(_In_ DWORD64 Dest, _In_ char Val, _In_ DWORD Size);
DWORD64 __cdecl GetTeb64();
DWORD64 __cdecl GetPeb64();
BOOLEAN __cdecl IsWoW64();

//#define IsWoW64() (__readfsdword(0xC0) > 0)
#define GetNtdll64() GetModuleHandle64(L"ntdll.dll")

#define RtlWow64CopyMemory64(Destination, Source, Length)  memcpy64((DWORD64)Destination, (DWORD64)Source, (DWORD)Length)
#define RtlWow64EqualMemory64(Destination, Source, Length) memcmp64((DWORD64)Destination, (DWORD64)Source, (DWORD)Length)
#define RtlWoW64ZeroMemory64(Destination, Length) memset64((DWORD64)Destination, '\0', (DWORD)Length) 

/*
*/
NTSTATUS
NTAPI
NtWow64ReadVirtualMemory64(
	_In_      HANDLE ProcessHandle,
	_In_      DWORD64 BaseAddress,
	_Out_     PVOID Buffer,
	_In_      DWORD64 NumberOfBytesToRead,
	_Out_opt_ DWORD64 *NumberOfBytesRead OPTIONAL
    );

/*
*/
NTSTATUS
NTAPI
NtWow64WriteVirtualMemory64(
	_In_      HANDLE ProcessHandle,
	_In_      DWORD64 BaseAddress,
	_In_      PVOID Buffer,
	_In_      DWORD64 NumberOfBytesToWrite,
	_Out_opt_ DWORD64 *NumberOfBytesWritten OPTIONAL
    );

/*
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
    );

/*
*/
NTSTATUS
NTAPI
NtWow64FreeVirtualMemory64(
	_In_    HANDLE ProcessHandle,
	_Inout_ DWORD64 *BaseAddress,
	_Inout_ DWORD64 *RegionSize,
	_In_    DWORD FreeType
    );

/*
*/
NTSTATUS
NTAPI
NtWoW64ProtectVirtualMemory64(
	_In_    HANDLE ProcessHandle,
	_Inout_ DWORD64 *BaseAddress,
	_Inout_ DWORD64 *NumberOfBytesToProtect,
	_In_    DWORD NewAccessProtection,
	_Out_   PDWORD OldAccessProtection
    );

/*
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
    );

/*
*/
NTSTATUS
NTAPI
NtWow64QueryInformationThread64(
	_In_      HANDLE ThreadHandle,
	_In_      THREAD_INFORMATION_CLASS64 ThreadInformationClass,
	_Out_     PVOID ThreadInformation,
	_In_      DWORD ThreadInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    );

/*
*/
NTSTATUS
NTAPI
NtWow64QueryInformationProcess64(
	_In_      HANDLE ProcessHandle,
	_In_      PROCESS_INFORMATION_CLASS64 ProcessInformationClass,
	_Out_     PVOID ProcessInformation,
	_In_      DWORD ProcessInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    );

/*
*/
NTSTATUS
NTAPI
NtWow64SetInformationProcess64(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESS_INFORMATION_CLASS64 ProcessInformationClass,
	_In_ PVOID ProcessInformation,
	_In_ DWORD ProcessInformationLength
    );

/*
*/
NTSTATUS
NTAPI
NtWow64GetNativeSystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS64 SystemInformationClass,
	_Out_     PVOID SystemInformation,
	_In_      DWORD SystemInformationLength,
	_Out_opt_ PDWORD ReturnLength OPTIONAL
    );

/*
*/
NTSTATUS
NTAPI
NtWow64GetContextThread64(
	_In_  HANDLE ThreadHandle,
	_Out_ PCONTEXT64 Context
    );

/*
*/
NTSTATUS
NTAPI
NtWow64SetContextThread64(
	_In_ HANDLE ThreadHandle,
	_In_ PCONTEXT64 Context
    );

/*
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
    );


#ifdef __cplusplus
}; // extern "C"
#endif

#endif