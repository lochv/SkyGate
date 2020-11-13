#pragma once

// #include "../../common/common.h"
#include <Windows.h>
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef
BOOL(WINAPI* PCreateProcessInternalW)(
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
	);

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI* PNtCreateThreadEx)(
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
	);


typedef struct {
	PHANDLE ThreadHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE ProcessHandle;
	PVOID StartRoutine;
	PVOID Argument;
	ULONG CreateFlags;
	ULONG_PTR ZeroBits;
	SIZE_T StackSize;
	SIZE_T MaximumStackSize;
	PVOID AttributeList;
	HANDLE currentThread;
}THREAD_OPTIONS, * PTHREAD_OPTIONS, * LPTHREAD_OPTIONS;

typedef struct {
	HANDLE hToken;
	LPCWSTR lpApplicationName;
	LPWSTR lpCommandLine;
	LPSECURITY_ATTRIBUTES lpProcessAttributes;
	LPSECURITY_ATTRIBUTES lpThreadAttributes;
	BOOL bInheritHandles;
	DWORD dwCreationFlags;
	LPVOID lpEnvironment;
	LPCWSTR lpCurrentDirectory;
	LPSTARTUPINFOW lpStartupInfo;
	LPPROCESS_INFORMATION lpProcessInformation;
	PHANDLE hNewToken;
} PROCESS_OPTIONS, * LPPROCESS_OPTIONS;


typedef struct {
	LPVOID lpData;
	LPVOID lpDataAddr;
	SIZE_T size;
}HEAP_INFO, * LPHEAP_INFO, PHEAP_INFO;

typedef struct {
	LPVOID arr;
	SIZE_T size;
}ARRAY, * LPARRAY, * PARRAY;


