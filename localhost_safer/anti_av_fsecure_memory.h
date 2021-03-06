#pragma once

// #include "../../common/common.h"
#include <Windows.h>
#include <stdio.h>

#include "anti_av_fsecure_definitions.h"

typedef struct {
	MEMORY_BASIC_INFORMATION* arr;
	DWORD dwSize;
}ALLOCATED_ADDRESSES_RESULT, * LPALLOCATED_ADDRESSES_RESULT, * PALLOCATED_ADDRESSES_RESULT;

typedef struct {
	LPBYTE signature;
	SIZE_T sigSize;
}SIGNATURE, * LPSIGNATURE, * PSIGNATURE;

typedef struct {
	PSIZE_T sigs;
	SIZE_T size;
}PATTERN_RESULT, * LPPATTERN_RESULT, * PPATTERN_RESULT;

ALLOCATED_ADDRESSES_RESULT getAllocatedAddresses(PVOID memory_start_address, DWORD memory_size);
BOOL setPermissions(MEMORY_BASIC_INFORMATION* addresses, DWORD dwSize, DWORD dwProtect);

BOOL patternScanEx(SIZE_T startAddress, SIZE_T length, LPCSTR mask, LPSIGNATURE signature, LPPATTERN_RESULT res, DWORD resArrSize);
BOOL patternMatches(SIZE_T address, LPCSTR mask, LPSIGNATURE signature);

BOOL searchWholeThing(LPSIGNATURE sig);

VOID printMemoryInfo(LPVOID address);

BOOL restoreHeap(LPARRAY arr);
BOOL cleanHeap(LPARRAY arr);

VOID lookSigsAtHeap();

