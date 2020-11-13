#include <windows.h>
#include "functions_table_constants.h"
#include "function_table_core.h"
#include "global_config.h"
#include "debug.h"

#include "crypto.h"

static int _LengthA(LPCSTR pstrStr)
{
    int c = 0;
    if (pstrStr != NULL) while (pstrStr[c] != 0) c++;

    return c;
}

static int _CompareA(LPCSTR pstrStr1, LPCSTR pstrStr2, int iSize1, int iSize2)
{
    //Checking the signs
    if (pstrStr1 == NULL && pstrStr2 != NULL)return -1;
    if (pstrStr1 != NULL && pstrStr2 == NULL)return 1;
    if (pstrStr1 == NULL && pstrStr2 == NULL)return 0;

    //If both dimensions are not defined.
    if (iSize1 == -1 && iSize2 == -1)
    {
        while ((iSize1 = *pstrStr1 - *pstrStr2) == 0 && *pstrStr2 != 0)
        {
            pstrStr1++;
            pstrStr2++;
        }
    }
    else
    {
        if (iSize1 == -1)iSize1 = _LengthA(pstrStr1);
        if (iSize2 == -1)iSize2 = _LengthA(pstrStr2);

        //If the dimensions are not equal, or even be one of them is 0.
        if (iSize1 != iSize2 || iSize1 == 0 || iSize2 == 0)iSize1 -= iSize2;

        //If the dimensions are equal.
        else for (int c = 0; c < iSize2; c++)
        {
            if ((iSize1 = *pstrStr1 - *pstrStr2) != 0)break;
            pstrStr1++;
            pstrStr2++;
        }
    }

    return (iSize1 == 0 ? 0 : (iSize1 > 0 ? 1 : -1));
}


FARPROC GetProcAddress_address()
{
    //
    HMODULE module = _getKernel32Handle();

    if (module == NULL) {
        return NULL;
    }

    //
#if defined _WIN64
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
    PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);

    PDWORD	FunctionNameAddressArray = (PDWORD)(((DWORD)ied->AddressOfNames) + ((PBYTE)module));
    PWORD	FunctionOrdinalAddressArray = (PWORD)((DWORD)ied->AddressOfNameOrdinals + (PBYTE)module);
    PDWORD	FunctionAddressArray = (PDWORD)((DWORD)ied->AddressOfFunctions + (PBYTE)module);

    //! search for function in exports table
    for (int i = 0; i < ied->NumberOfFunctions; i++)
    {
        LPSTR	FunctionName = (LPSTR)(FunctionNameAddressArray[i] + (PBYTE)module);

        if (_LengthA(FunctionName) == GetProcAddress_STRING_LEN) 
        {
            if (FunctionName[0] != 'G')
            {
                continue;
            }

            if (FunctionName[1] != 'e')
            {
                continue;
            }

            if (FunctionName[2] != 't')
            {
                continue;
            }

            if (FunctionName[3] != 'P')
            {
                continue;
            }

            if (FunctionName[4] != 'r')
            {
                continue;
            }

            if (FunctionName[5] != 'o')
            {
                continue;
            }

            if (FunctionName[6] != 'c')
            {
                continue;
            }

            if (FunctionName[7] != 'A')
            {
                continue;
            }

            if (FunctionName[8] != 'd')
            {
                continue;
            }

            if (FunctionName[9] != 'd')
            {
                continue;
            }

            if (FunctionName[10] != 'r')
            {
                continue;
            }

            if (FunctionName[11] != 'e')
            {
                continue;
            }

            if (FunctionName[12] != 's')
            {
                continue;
            }

            if (FunctionName[13] != 's')
            {
                continue;
            }
        }
        else {
            continue;
        }

        WORD Ordinal = FunctionOrdinalAddressArray[i];

        DWORD FunctionAddress = FunctionAddressArray[Ordinal];

        DWORD computed_real_function_adress = (DWORD)(FunctionAddress + (PBYTE)module);

        return (FARPROC)computed_real_function_adress;
    }

    //
    return NULL;
}


FARPROC l_GetProcAddress(
    HMODULE hModule,
    LPCSTR  lpProcName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = GetProcAddress_address();

    typedef FARPROC(__stdcall* FUNCTION_POINTER_CAST)
        (
            HMODULE,
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hModule,
            lpProcName
        );
    }
    else {
        return 0;
    }

    return 0;
}

FARPROC LoadLibraryA_address()
{
    //
    HMODULE module = _getKernel32Handle();

    if (module == NULL) {
        return NULL;
    }

    //
#if defined _WIN64
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
    PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);

    PDWORD	FunctionNameAddressArray = (PDWORD)(((DWORD)ied->AddressOfNames) + ((PBYTE)module));
    PWORD	FunctionOrdinalAddressArray = (PWORD)((DWORD)ied->AddressOfNameOrdinals + (PBYTE)module);
    PDWORD	FunctionAddressArray = (PDWORD)((DWORD)ied->AddressOfFunctions + (PBYTE)module);

    //! search for function in exports table
    for (int i = 0; i < ied->NumberOfFunctions; i++)
    {
        LPSTR	FunctionName = (LPSTR)(FunctionNameAddressArray[i] + (PBYTE)module);

        if (_LengthA(FunctionName) == LoadLibraryA_STRING_LEN)
        {
            if (FunctionName[0] != 'L')
            {
                continue;
            }

            if (FunctionName[1] != 'o')
            {
                continue;
            }

            if (FunctionName[2] != 'a')
            {
                continue;
            }

            if (FunctionName[3] != 'd')
            {
                continue;
            }

            if (FunctionName[4] != 'L')
            {
                continue;
            }

            if (FunctionName[5] != 'i')
            {
                continue;
            }

            if (FunctionName[6] != 'b')
            {
                continue;
            }

            if (FunctionName[7] != 'r')
            {
                continue;
            }

            if (FunctionName[8] != 'a')
            {
                continue;
            }

            if (FunctionName[9] != 'r')
            {
                continue;
            }

            if (FunctionName[10] != 'y')
            {
                continue;
            }

            if (FunctionName[11] != 'A')
            {
                continue;
            }
        }
        else {
            continue;
        }

        WORD Ordinal = FunctionOrdinalAddressArray[i];

        DWORD FunctionAddress = FunctionAddressArray[Ordinal];

        DWORD computed_real_function_adress = (DWORD)(FunctionAddress + (PBYTE)module);

        return (FARPROC)computed_real_function_adress;
    }

    //
    return NULL;
}


HMODULE l_LoadLibraryA(
    LPCSTR lpLibFileName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = LoadLibraryA_address();

    typedef HMODULE(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpLibFileName
        );
    }
    else {
        return 0;
    }

    return 0;
}


FARPROC GetModuleHandleA_address()
{
    //
    HMODULE module = _getKernel32Handle();

    if (module == NULL) {
        return NULL;
    }

    //
#if defined _WIN64
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
    PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);

    PDWORD	FunctionNameAddressArray = (PDWORD)(((DWORD)ied->AddressOfNames) + ((PBYTE)module));
    PWORD	FunctionOrdinalAddressArray = (PWORD)((DWORD)ied->AddressOfNameOrdinals + (PBYTE)module);
    PDWORD	FunctionAddressArray = (PDWORD)((DWORD)ied->AddressOfFunctions + (PBYTE)module);

    //! search for function in exports table
    for (int i = 0; i < ied->NumberOfFunctions; i++)
    {
        LPSTR	FunctionName = (LPSTR)(FunctionNameAddressArray[i] + (PBYTE)module);

        if (_LengthA(FunctionName) == GetModuleHandleA_STRING_LEN)
        {
            if (FunctionName[0] != 'G')
            {
                continue;
            }

            if (FunctionName[1] != 'e')
            {
                continue;
            }

            if (FunctionName[2] != 't')
            {
                continue;
            }

            if (FunctionName[3] != 'M')
            {
                continue;
            }

            if (FunctionName[4] != 'o')
            {
                continue;
            }

            if (FunctionName[5] != 'd')
            {
                continue;
            }

            if (FunctionName[6] != 'u')
            {
                continue;
            }

            if (FunctionName[7] != 'l')
            {
                continue;
            }

            if (FunctionName[8] != 'e')
            {
                continue;
            }

            if (FunctionName[9] != 'H')
            {
                continue;
            }

            if (FunctionName[10] != 'a')
            {
                continue;
            }

            if (FunctionName[11] != 'n')
            {
                continue;
            }

            if (FunctionName[12] != 'd')
            {
                continue;
            }

            if (FunctionName[13] != 'l')
            {
                continue;
            }

            if (FunctionName[14] != 'e')
            {
                continue;
            }

            if (FunctionName[15] != 'A')
            {
                continue;
            }
        }
        else {
            continue;
        }

        WORD Ordinal = FunctionOrdinalAddressArray[i];

        DWORD FunctionAddress = FunctionAddressArray[Ordinal];

        DWORD computed_real_function_adress = (DWORD)(FunctionAddress + (PBYTE)module);

        return (FARPROC)computed_real_function_adress;

    }

    //
    return NULL;
}


HMODULE l_GetModuleHandleA(
    LPCSTR lpModuleName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = GetModuleHandleA_address();

    typedef HMODULE(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpModuleName
        );
    }
    else {
        return 0;
    }

    return 0;
}


HMODULE _getKernel32Handle(void)
{
#if defined _WIN64
    return NULL; //FIXME
#else  
    __asm
    {
        cld                    //clear the direction flag for the loop

        mov edx, fs: [0x30]     //get a pointer to the PEB
        mov edx, [edx + 0x0C]  //get PEB-> Ldr
        mov edx, [edx + 0x14]  //get the first module from the InMemoryOrder module list

        next_mod :
        mov esi, [edx + 0x28]  //get pointer to modules name (unicode string)
        mov ecx, 24            //the length we want to check
        xor edi, edi           //clear edi which will store the hash of the module name

        loop_modname :
        xor eax, eax           //clear eax
            lodsb                  //read in the next byte of the name
            cmp al, 'a'            //some versions of Windows use lower case module names
            jl not_lowercase
            sub al, 0x20           //if so normalise to uppercase

            not_lowercase :
            ror edi, 13            //rotate right our hash value
            add edi, eax           //add the next byte of the name to the hash
            loop loop_modname      //loop until we have read enough

            cmp edi, 0x6A4ABC5B    //compare the hash with that of KERNEL32.DLL
            mov eax, [edx + 0x10]  //get this modules base address
            mov edx, [edx]         //get the next module
            jne next_mod           //if it doesn't match, process the next module
    };
#endif
}