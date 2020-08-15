#include "injector.hpp"

#ifdef __cplusplus
extern "C"
{
#endif

typedef HMODULE(__stdcall* LoadLibraryA_funcPtr_t)(LPCSTR);
typedef FARPROC(__stdcall* GetProcAddress_funcPtr_t)(HMODULE, LPCSTR);
typedef INT(__stdcall* DllMain_funcPtr_t)(HMODULE, DWORD, LPVOID);

typedef struct
{
	LPVOID						pBase;

	PIMAGE_NT_HEADERS			pNTHeaders;
	PIMAGE_BASE_RELOCATION		pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDescriptor;

	LoadLibraryA_funcPtr_t		pFuncLoadLibraryA;
	GetProcAddress_funcPtr_t	pFuncGetProcAddress;
} ImageLoaderData_t;

static DWORD __stdcall library_loader(LPVOID pMemory);
static DWORD __stdcall stub();

void inject(DWORD dwPID, LPCSTR cstrDLLFilePath)
{
	// Open the DLL
	HANDLE hFile = CreateFileA(cstrDLLFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	LPVOID pFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Read the DLL
	ReadFile(hFile, pFileBuffer, dwFileSize, NULL, NULL);

	PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pImageNTHeaders_DLL = (PIMAGE_NT_HEADERS)((LPBYTE)pFileBuffer + pImageDOSHeader->e_lfanew);

	// Open target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	// Allocate memory for the DLL
	LPVOID pExecutableImage = VirtualAllocEx(hProcess, NULL, pImageNTHeaders_DLL->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Copy the headers to target process
	WriteProcessMemory(hProcess, pExecutableImage, pFileBuffer, pImageNTHeaders_DLL->OptionalHeader.SizeOfHeaders, NULL);

	// Target DLL's Section Header
	PIMAGE_SECTION_HEADER pImageSectionHeader_DLL = (PIMAGE_SECTION_HEADER)(pImageNTHeaders_DLL + 1);

	// Copy sections of the DLL to the target process
	for (WORD i = 0; i < pImageNTHeaders_DLL->FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER imageSectionHeader = pImageSectionHeader_DLL[i];
		LPVOID pBaseAddress = (LPBYTE)pExecutableImage + imageSectionHeader.VirtualAddress;
		LPVOID pBuffer = (LPBYTE)pFileBuffer + imageSectionHeader.PointerToRawData;
		DWORD dwSize = imageSectionHeader.SizeOfRawData;

		WriteProcessMemory(hProcess, pBaseAddress, pBuffer, dwSize, NULL);
	}

	// Allocate memory for the loader code
	LPVOID pLoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	ImageLoaderData_t imageLoaderData =
	{
		pExecutableImage,
		(PIMAGE_NT_HEADERS)((LPBYTE)pExecutableImage + pImageDOSHeader->e_lfanew),
		(PIMAGE_BASE_RELOCATION)((LPBYTE)pExecutableImage + pImageNTHeaders_DLL->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		(PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pExecutableImage + pImageNTHeaders_DLL->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		LoadLibraryA,
		GetProcAddress
	};

	// Write the loader information to target process
	WriteProcessMemory(hProcess, pLoaderMemory, &imageLoaderData, sizeof(imageLoaderData), NULL);

	// Write the loader code to target process
	WriteProcessMemory(hProcess, (LPVOID)((ImageLoaderData_t*)pLoaderMemory + 1), library_loader, (DWORD)stub - (DWORD)library_loader, NULL);

	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((ImageLoaderData_t*)pLoaderMemory + 1), pLoaderMemory, 0, NULL);

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE);

	// Free the allocated loader code
	VirtualFreeEx(hProcess, pLoaderMemory, 0, MEM_RELEASE);
}

DWORD __stdcall library_loader(LPVOID pMemory)
{
	ImageLoaderData_t* pILD = (ImageLoaderData_t*)pMemory;

	PIMAGE_BASE_RELOCATION pIBR = pILD->pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR pIID = pILD->pImportDescriptor;

	DWORD dwDelta = (DWORD)((LPBYTE)pILD->pBase - pILD->pNTHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			LPWORD pList = (LPWORD)(pIBR + 1);

			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			for (int i = 0; i < count; i++)
			{
				if (pList[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)pILD->pBase + (pIBR->VirtualAddress + (pList[i] & 0xFFF)));
					*ptr += dwDelta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA pIFTOrg = (PIMAGE_THUNK_DATA)((LPBYTE)pILD->pBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pIFT = (PIMAGE_THUNK_DATA)((LPBYTE)pILD->pBase + pIID->FirstThunk);
		HMODULE hModule = pILD->pFuncLoadLibraryA((LPCSTR)pILD->pBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (pIFTOrg->u1.AddressOfData)
		{
			DWORD dwFunc;

			if (pIFTOrg->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{ // Import by ordinal
				dwFunc = (DWORD)pILD->pFuncGetProcAddress(hModule, (LPCSTR)(pIFTOrg->u1.Ordinal & 0xFFFF));
			}
			else
			{ // Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pILD->pBase + pIFTOrg->u1.AddressOfData);
				dwFunc = (DWORD)pILD->pFuncGetProcAddress(hModule, (LPCSTR)pIBN->Name);
			}

			if (!dwFunc)
			{
				return FALSE;
			}

			pIFT->u1.Function = dwFunc;
			pIFTOrg++;
			pIFT++;
		}
		pIID++;
	}

	if (pILD->pNTHeaders->OptionalHeader.AddressOfEntryPoint)
	{ // Call the entry point
		DllMain_funcPtr_t pFuncEntryPoint = (DllMain_funcPtr_t)((LPBYTE)pILD->pBase + pILD->pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		return pFuncEntryPoint((HMODULE)pILD->pBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

DWORD __stdcall stub()
{
	return 0;
}

#ifdef __cplusplus
}
#endif