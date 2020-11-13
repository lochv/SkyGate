#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string>

#include "global_config.h"
#include "junk_asm.h"
#include "functions_table.h"

#include "common_utils.h"

#include "debug.h"

#include "function_table_core.h"

#pragma warning(disable:4996)

//

// Get PEB for WOW64 Process

// Current PEB for 64bit and 32bit processes accordingly
PVOID GetPEB()
{
    ASM_JUNK;

#ifdef _WIN64
        return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
        return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

PVOID GetPEB64()
{
    ASM_JUNK;

    PVOID pPeb = 0;

#ifndef _WIN64
    // 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
    // 2. PEB64 follows after PEB32
    // 3. This is true for versions lower than Windows 8, else __readfsdword returns address of real PEB64
    if (IsWin8OrHigher())
    {
        BOOL isWow64 = FALSE;
        
        
        if (l_IsWow64Process(l_GetCurrentProcess(), &isWow64))
        {
            if (isWow64)
            {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
            }
        }
    }
#endif
    return pPeb;
}





#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

static void CheckNtGlobalFlag()
{
    ASM_JUNK;

    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
    {
        DBG_MSG("CheckNtGlobalFlag() - 1\n");
       l_ExitProcess(-1);
    }
    if (pPeb64)
    {
        DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
        if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
        {
            DBG_MSG("CheckNtGlobalFlag() - 2\n");
           l_ExitProcess(-1);
        }
    }
}

/// <summary>
/// 
/// </summary>

PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
    ASM_JUNK;

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}

PIMAGE_SECTION_HEADER FindRDataSection(PBYTE pImageBase)
{
    ASM_JUNK;

    static const std::string rdata = ".rdata";
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
    int n = 0;
    for (; n < pImageNtHeaders->FileHeader.NumberOfSections; ++n)
    {
        if (rdata == (char*)pImageSectionHeader[n].Name)
        {
            break;
        }
    }
    
    return &pImageSectionHeader[n];
}
void CheckGlobalFlagsClearInProcess()
{
    ASM_JUNK;

    PBYTE pImageBase = (PBYTE)l_GetModuleHandleA(NULL);
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
        + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
    {
        DBG_MSG("CheckGlobalFlagsClearInProcess()\n");
       l_ExitProcess(-1);
    }
}
void CheckGlobalFlagsClearInFile()
{
    ASM_JUNK;

    HANDLE hExecutable = INVALID_HANDLE_VALUE;
    HANDLE hExecutableMapping = NULL;
    PBYTE pMappedImageBase = NULL;
    __try
    {
        PBYTE pImageBase = (PBYTE)l_GetModuleHandleA(NULL);
        PIMAGE_SECTION_HEADER pImageSectionHeader = FindRDataSection(pImageBase);
        TCHAR pszExecutablePath[MAX_PATH];
        DWORD dwPathLength = GetModuleFileName(NULL, pszExecutablePath, MAX_PATH);

        if (0 == dwPathLength) __leave;

        hExecutable = l_CreateFileW(pszExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        
        if (INVALID_HANDLE_VALUE == hExecutable) __leave;
        
        hExecutableMapping = l_CreateFileMappingW(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
        
        if (NULL == hExecutableMapping) __leave;
        
        pMappedImageBase = (PBYTE)l_MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0,
            pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);
        
        if (NULL == pMappedImageBase) __leave;
        
        PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pMappedImageBase);
        
        PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pMappedImageBase
            + (pImageSectionHeader->PointerToRawData
                + (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress - pImageSectionHeader->VirtualAddress)));
        
        if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
        {
            DBG_MSG("CheckGlobalFlagsClearInFile()\n");
           l_ExitProcess(-1);
        }
    }
    __finally
    {
        if (NULL != pMappedImageBase)
            l_UnmapViewOfFile(pMappedImageBase);
        if (NULL != hExecutableMapping)
            l_CloseHandle(hExecutableMapping);
        if (INVALID_HANDLE_VALUE != hExecutable)
            l_CloseHandle(hExecutable);
    }
}

///

int GetHeapFlagsOffset(bool x64)
{
    ASM_JUNK;

    return x64 ?
        IsVistaOrHigher() ? 0x70 : 0x14 : //x64 offsets
        IsVistaOrHigher() ? 0x40 : 0x0C; //x86 offsets
}
int GetHeapForceFlagsOffset(bool x64)
{
    ASM_JUNK;

    return x64 ?
        IsVistaOrHigher() ? 0x74 : 0x18 : //x64 offsets
        IsVistaOrHigher() ? 0x44 : 0x10; //x86 offsets
}
void CheckHeap()
{
    ASM_JUNK;

    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    PVOID heap = 0;
    DWORD offsetProcessHeap = 0;
    PDWORD heapFlagsPtr = 0, heapForceFlagsPtr = 0;
    BOOL x64 = FALSE;

#ifdef _WIN64
    x64 = TRUE;
    offsetProcessHeap = 0x30;

#else
    offsetProcessHeap = 0x18;

#endif
    heap = (PVOID) * (PDWORD_PTR)((PBYTE)pPeb + offsetProcessHeap);
    heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(x64));
    heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(x64));
    if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
    {
        DBG_MSG("CheckHeap() - 1\n");
       l_ExitProcess(-1);
    }
    if (pPeb64)
    {
        heap = (PVOID) * (PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
        heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(true));
        heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(true));
        if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
        {
            DBG_MSG("CheckHeap() - 2\n");
           l_ExitProcess(-1);
        }
    }
}


///
void checkTF() {
    ASM_JUNK;

    BOOL isDebugged = TRUE;
    __try
    {
        __asm
        {
            pushfd
            or dword ptr[esp], 0x100 // set the Trap Flag 
            popfd                    // Load the value into EFLAGS register
            nop
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // If an exception has been raised – debugger is not present
        isDebugged = FALSE;
    }
    if (isDebugged)
    {
        DBG_MSG("checkTF()\n");
       l_ExitProcess(-1);
    }
}

///
void check_remote_debugger() {
    ASM_JUNK;

    BOOL is_debugger_present = FALSE;

    //


    if (l_CheckRemoteDebuggerPresent(l_GetCurrentProcess(), &is_debugger_present))
    {
        if (is_debugger_present)
        {
            DBG_MSG("check_remote_debugger()\n");

           l_ExitProcess(-1);
        }
    }

}

/// <summary>
/// 
/// </summary>

void anti_debugging()
{
/*
    ASM_JUNK;

    if (l_IsDebuggerPresent())
    {
            DBG_MSG("anti_debugging(): IsDebuggerPresent() FOUND, get out now");
           l_ExitProcess(-1);
    }

    

    //CheckNtGlobalFlag(); // cause crash on windows 10 x64

    CheckGlobalFlagsClearInProcess();
    
    CheckGlobalFlagsClearInFile();
    
    //CheckHeap(); // cause crash on windows 10 x64
    //checkTF();     // TODO: not work on Win7 32 bits
    
    check_remote_debugger();
*/    
}