#include "test_load_ntdll.h"

#include "peconv.h"
#include "file_helper.h"

#include <iostream>
#include "shellcodes.h"
#include "ntddk.h"

using namespace peconv;

int (_cdecl *ntdll_tolower) (int) = NULL;

NTSTATUS (NTAPI *ntdll_ZwAllocateVirtualMemory)(
  _In_    HANDLE    ProcessHandle,
  _Inout_ PVOID     *BaseAddress,
  _In_    ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T   RegionSize,
  _In_    ULONG     AllocationType,
  _In_    ULONG     Protect
) = NULL;

BOOL (WINAPI *kernel32_CreateProcessA)(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
    ) = NULL;

NTSTATUS (*ntdll_ZwOpenProcess)(
  _Out_    PHANDLE            ProcessHandle,
  _In_     ACCESS_MASK        DesiredAccess,
  _In_     POBJECT_ATTRIBUTES ObjectAttributes,
  _In_opt_ PCLIENT_ID         ClientId
) = NULL;

HANDLE  (WINAPI *kernel32_OpenProcess)(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ DWORD dwProcessId
    ) = NULL;

NTSTATUS (NTAPI *ntdll_ZwCreateThreadEx) (
    OUT  PHANDLE ThreadHandle, 
    IN  ACCESS_MASK DesiredAccess, 
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    IN  HANDLE ProcessHandle,
    IN  PVOID StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits, 
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL, 
    IN  PVOID AttributeList OPTIONAL
) = NULL;

BOOL (WINAPI *kernel32_WriteProcessMemory)(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T * lpNumberOfBytesWritten
    ) = NULL;

namespace test7 {

        class buffered_dlls_resolver : peconv::default_func_resolver {
        public:

        void add_hook(std::string dll_name, HMODULE dll_module ) 
        {
            hooks_map[dll_name] = dll_module;
        }

        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name)
        {
            std::map<std::string, HMODULE>::iterator itr = hooks_map.find(lib_name);
            if (itr != hooks_map.end()) {
                HMODULE dll_module = itr->second;
                FARPROC hProc = peconv::get_exported_func(dll_module, func_name);
#ifdef _DEBUG
                std::cout << ">>>>>>Replacing: " << func_name << " by: " << hProc << std::endl;
#endif
                return hProc;
            }
            return peconv::default_func_resolver::resolve_func(lib_name, func_name);
        }

        private:
        std::map<std::string, HMODULE> hooks_map;
    };
}; //namespace test7

bool create_suspended_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (kernel32_CreateProcessA == NULL) return false;
    printf("Trying to create: %s\n", path);
    if (!kernel32_CreateProcessA(
            path,
            NULL,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            FALSE, //bInheritHandles
            CREATE_SUSPENDED, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}


HMODULE load_ntdll()
{
    CHAR ntdllPath[MAX_PATH];
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\ntdll.dll", ntdllPath, MAX_PATH);

    size_t v_size = 0;
    BYTE *ntdll_module = peconv::load_pe_module(ntdllPath, v_size, true, true);
    if (!ntdll_module) {
        return NULL;
    }
    bool is64 = peconv::is64bit(ntdll_module);
    std::cout << "NTDLL loaded, is64:" << is64 << std::endl;
    printf("base: %p\n", ntdll_module);
    FARPROC n_offset = peconv::get_exported_func(ntdll_module, "tolower");
    if (n_offset == NULL) {
        return NULL;
    }
    std::cout << "Got tolower: " << n_offset << std::endl;
    ntdll_tolower = (int (_cdecl *) (int)) n_offset;
    int out = ntdll_tolower('C');
    std::cout << "To lower char: " << (char) out << std::endl;

    n_offset = peconv::get_exported_func(ntdll_module, "ZwAllocateVirtualMemory");
    if (n_offset == NULL) {
        return NULL;
    }
    ntdll_ZwAllocateVirtualMemory = (NTSTATUS (NTAPI *)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG)) n_offset;

   n_offset = peconv::get_exported_func(ntdll_module, "ZwCreateThreadEx");
    if (n_offset == NULL) {
        return NULL;
    }
    ntdll_ZwCreateThreadEx = (NTSTATUS (NTAPI *) (
      PHANDLE , 
      ACCESS_MASK , 
      POBJECT_ATTRIBUTES  , 
      HANDLE ,
      PVOID ,
      PVOID  ,
      ULONG ,
      ULONG_PTR , 
      SIZE_T  ,
      SIZE_T  , 
      PVOID  )) n_offset;

    return (HMODULE) ntdll_module;
}

HMODULE load_kernel32(peconv::t_function_resolver *my_resolver)
{
    CHAR path[MAX_PATH];
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\kernel32.dll", path, MAX_PATH);
    size_t v_size = 0;
    BYTE *module = peconv::load_pe_executable(path, v_size, my_resolver);
    if (!module) {
        return NULL;
    }
    printf("base: %p\n", module);
    FARPROC n_offset = peconv::get_exported_func(module, "CreateProcessA");
    if (n_offset == NULL) {
        return NULL;
    }
    printf("CreateProcessA: %p\n", n_offset);
    kernel32_CreateProcessA = (BOOL (WINAPI *) ( LPCSTR, LPSTR, 
        LPSECURITY_ATTRIBUTES, 
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, 
        LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION )) n_offset;

    n_offset = peconv::get_exported_func(module, "OpenProcess");
    if (n_offset == NULL) {
        return NULL;
    }
    printf("OpenProcess: %p\n", n_offset);
    kernel32_OpenProcess = (HANDLE  (WINAPI *)(
     DWORD ,
     BOOL ,
     DWORD 
    )) n_offset;


    n_offset = peconv::get_exported_func(module, "WriteProcessMemory");
    if (n_offset == NULL) {
        return NULL;
    }
    printf("WriteProcessMemory: %p\n", n_offset);
    kernel32_WriteProcessMemory = (BOOL (WINAPI *)( HANDLE ,LPVOID ,LPCVOID ,SIZE_T ,SIZE_T * )) n_offset;
    return (HMODULE) module;
}

bool run_shellcode_in_new_thread(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    NTSTATUS status = NULL;
    HANDLE hMyThread = NULL;
    //create a new thread for the injected code:
    if ((status = ntdll_ZwCreateThreadEx(&hMyThread, 0x1FFFFF, NULL, hProcess, remote_shellcode_ptr, NULL, DETACHED_PROCESS, 0, 0, 0, 0)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateThreadEx failed, status : %x\n", status);
        return false;
    }
    printf("Created Thread, id = %x\n", GetThreadId(hMyThread));
    return true;
}
//For now this is for manual tests only:
int tests::test_ntdll(char *arg)
{
    HMODULE ntdll_module = load_ntdll();
    if (!ntdll_module) {
        return -1;
    }
    test7::buffered_dlls_resolver my_resolver;
    my_resolver.add_hook("ntdll.dll", ntdll_module);
    HMODULE kernel32_module = load_kernel32((peconv::t_function_resolver*) &my_resolver);
    if (!kernel32_module) {
        return -1;
    }
    PVOID base_addr = 0;
    SIZE_T buffer_size = 0x200;
    BOOL isWow = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow);
    if (isWow) {
        printf("Wow64 not supported!\n");
        system("pause");
        return -1;
    }
    HWND hWnd = FindWindowA("Shell_TrayWnd", NULL);
    if (hWnd == NULL) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    printf("PID:\t%d\n", pid);

    HANDLE proc = kernel32_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return -1;
    printf("proc: %p\n", proc);

    NTSTATUS status = ntdll_ZwAllocateVirtualMemory(
        proc, &base_addr, 0, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );  
    if (status != S_OK) {
        printf("Failed to allocate!\n");
        system("pause");
        return -1;
    }
    BYTE* shellcode_ptr = NULL;
    SIZE_T shellcode_size = 0;
#ifndef _WIN64
    shellcode_ptr = messageBox32bit_sc;
    shellcode_size = sizeof(messageBox32bit_sc);
#else
    shellcode_ptr = messageBox64bit_sc;
    shellcode_size = sizeof(messageBox64bit_sc);
#endif
    SIZE_T written = 0;
    kernel32_WriteProcessMemory(proc,base_addr,shellcode_ptr, shellcode_size, &written);
    printf("written: %d\n", written);
    run_shellcode_in_new_thread(proc, base_addr);
    printf("allocated: %p\n", base_addr);
    system("pause");
    return 0;
}
