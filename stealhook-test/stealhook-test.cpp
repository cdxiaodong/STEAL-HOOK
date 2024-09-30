#include <stdio.h>
#include <windows.h>

#define DEBUG_REGISTER_EXEC_DR0 0x1
#define DEBUG_REGISTER_EXEC_DR1 0x4
#define DEBUG_REGISTER_EXEC_DR2 0x10
#define DEBUG_REGISTER_EXEC_DR3 0x40

#define SINGLE_STEP_FLAG 0x100

#define MAXIMUM_STORED_ADDRESS_COUNT 1024

#define OVERWRITE_REFERENCE_ADDRESS_VALUE 1

#if _WIN64
#define NATIVE_VALUE ULONGLONG
#define CURRENT_EXCEPTION_STACK_PTR ExceptionInfo->ContextRecord->Rsp
#define CURRENT_EXCEPTION_INSTRUCTION_PTR ExceptionInfo->ContextRecord->Rip
#else
#define NATIVE_VALUE DWORD
#define CURRENT_EXCEPTION_STACK_PTR ExceptionInfo->ContextRecord->Esp
#define CURRENT_EXCEPTION_INSTRUCTION_PTR ExceptionInfo->ContextRecord->Eip
#endif

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct PEB_LDR_DATA
{
	DWORD Length;
	DWORD Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	PVOID Reserved5[3];
	PVOID Reserved6;
	ULONG TimeDateStamp;
};

struct PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[1];
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	// .....
};

DWORD dwGlobal_TraceStarted = 0;
DWORD dwGlobal_AddressCount = 0;
DWORD dwGlobal_SuccessfulHookCount = 0;
DWORD dwGlobal_CurrHookExecuted = 0;
NATIVE_VALUE dwGlobal_Wow64TransitionStub = 0;
NATIVE_VALUE dwGlobal_InitialStackPtr = 0;
NATIVE_VALUE dwGlobal_OriginalReferenceValue = 0;
NATIVE_VALUE dwGlobal_AddressList[MAXIMUM_STORED_ADDRESS_COUNT];
BYTE* pGlobal_ExeBase = NULL;

DWORD ExecuteTargetFunction();

DWORD ScanModuleForAddress(BYTE* pModuleBase, char* pModuleName, NATIVE_VALUE dwAddr, NATIVE_VALUE dwStackPtr)
{
	IMAGE_DOS_HEADER* pImageDosHeader = NULL;
	IMAGE_NT_HEADERS* pImageNtHeader = NULL;
	IMAGE_SECTION_HEADER* pCurrSectionHeader = NULL;
	DWORD dwReadOffset = 0;
	BYTE* pCurrPtr = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;
	DWORD dwStackDelta = 0;

	// get dos header
	pImageDosHeader = (IMAGE_DOS_HEADER*)pModuleBase;
	if (pImageDosHeader->e_magic != 0x5A4D)
	{
		return 1;
	}

	// get nt header
	pImageNtHeader = (IMAGE_NT_HEADERS*)(pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 1;
	}

	// loop through all sections
	for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

		// ignore executable sections
		if (pCurrSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			continue;
		}

		// scan current section for the target address
		dwReadOffset = pCurrSectionHeader->VirtualAddress;
		for (DWORD ii = 0; ii < pCurrSectionHeader->Misc.VirtualSize / sizeof(NATIVE_VALUE); ii++)
		{
			// check if the current value contains the target address
			pCurrPtr = pModuleBase + dwReadOffset;
			if (*(NATIVE_VALUE*)pCurrPtr == dwAddr)
			{
				// found target address - check memory protection
				memset((void*)&MemoryBasicInfo, 0, sizeof(MemoryBasicInfo));
				if (VirtualQuery(pCurrPtr, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) != 0)
				{
					// check if the current region is writable
					if (MemoryBasicInfo.Protect == PAGE_EXECUTE_READWRITE || MemoryBasicInfo.Protect == PAGE_READWRITE)
					{
						// ensure the address list is not full
						if (dwGlobal_AddressCount >= MAXIMUM_STORED_ADDRESS_COUNT)
						{
							printf("Error: Address list is full\n");
							return 1;
						}

						// store current address in list
						dwGlobal_AddressList[dwGlobal_AddressCount] = (NATIVE_VALUE)pCurrPtr;
						dwGlobal_AddressCount++;

						// calculate stack delta
						dwStackDelta = (DWORD)(dwGlobal_InitialStackPtr - dwStackPtr);

						printf("Instruction 0x%p referenced at %s!0x%p (sect: %s, virt_addr: 0x%X, stack delta: 0x%X)\n", (void*)dwAddr, pModuleName, (void*)pCurrPtr, pCurrSectionHeader->Name, dwReadOffset, dwStackDelta);
					}
				}
			}

			// increase read offset
			dwReadOffset += sizeof(NATIVE_VALUE);
		}
	}

	return 0;
}

DWORD ScanAllModulesForAddress(NATIVE_VALUE dwAddr, NATIVE_VALUE dwStackPtr)
{
	DWORD dwPEB = 0;
	PEB* pPEB = NULL;
	LDR_DATA_TABLE_ENTRY* pCurrEntry = NULL;
	LIST_ENTRY* pCurrListEntry = NULL;
	DWORD dwEntryOffset = 0;
	char szModuleName[512];
	DWORD dwStringLength = 0;

	// get PEB ptr
#if _WIN64
	pPEB = (PEB*)__readgsqword(0x60);
#else
	pPEB = (PEB*)__readfsdword(0x30);
#endif

	// get InMemoryOrderLinks offset in structure
	dwEntryOffset = (DWORD)((BYTE*)&pCurrEntry->InLoadOrderLinks - (BYTE*)pCurrEntry);

	// get first link
	pCurrListEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	// enumerate all modules
	for (;;)
	{
		// get ptr to current module entry
		pCurrEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pCurrListEntry - dwEntryOffset);

		// check if this is the final entry
		if (pCurrEntry->DllBase == 0)
		{
			// end of module list
			break;
		}

		// ignore main exe module
		if (pCurrEntry->DllBase != pGlobal_ExeBase)
		{
			// convert module name to ansi
			dwStringLength = pCurrEntry->BaseDllName.Length / sizeof(wchar_t);
			if (dwStringLength > sizeof(szModuleName) - 1)
			{
				dwStringLength = sizeof(szModuleName) - 1;
			}
			memset(szModuleName, 0, sizeof(szModuleName));
			wcstombs(szModuleName, pCurrEntry->BaseDllName.Buffer, dwStringLength);

			// scan current module
			ScanModuleForAddress((BYTE*)pCurrEntry->DllBase, szModuleName, dwAddr, dwStackPtr);
		}

		// get next module entry in list
		pCurrListEntry = pCurrListEntry->Flink;
	}

	return 0;
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	NATIVE_VALUE dwReturnAddress = 0;

	// check exception code
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (dwGlobal_TraceStarted == 0)
		{
			// trace not started - ensure the current eip is the target function
			if (CURRENT_EXCEPTION_INSTRUCTION_PTR != ExceptionInfo->ContextRecord->Dr0)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// store original stack pointer
			dwGlobal_InitialStackPtr = CURRENT_EXCEPTION_STACK_PTR;

			// set hardware breakpoint on the original return address
			ExceptionInfo->ContextRecord->Dr1 = *(NATIVE_VALUE*)dwGlobal_InitialStackPtr;

			// initial trace started
			dwGlobal_TraceStarted = 1;
		}

		// set debug control field
		ExceptionInfo->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;

		// check current instruction pointer
		if (CURRENT_EXCEPTION_INSTRUCTION_PTR == dwGlobal_Wow64TransitionStub)
		{
			// we have hit the wow64 transition stub - don't single step here, set a breakpoint on the current return address instead
			dwReturnAddress = *(NATIVE_VALUE*)CURRENT_EXCEPTION_STACK_PTR;
			ExceptionInfo->ContextRecord->Dr0 = dwReturnAddress;
			ExceptionInfo->ContextRecord->Dr7 |= DEBUG_REGISTER_EXEC_DR0;
		}
		else if (CURRENT_EXCEPTION_INSTRUCTION_PTR == ExceptionInfo->ContextRecord->Dr1)
		{
			// we have reached the original return address - remove all breakpoints
			ExceptionInfo->ContextRecord->Dr7 = 0;
		}
		else
		{
			// scan all modules for the current instruction pointer
			ScanAllModulesForAddress(CURRENT_EXCEPTION_INSTRUCTION_PTR, CURRENT_EXCEPTION_STACK_PTR);

			// single step
			ExceptionInfo->ContextRecord->EFlags |= SINGLE_STEP_FLAG;
		}

		// continue execution
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// access violation - check if the eip matches the expected value
		if (CURRENT_EXCEPTION_INSTRUCTION_PTR != OVERWRITE_REFERENCE_ADDRESS_VALUE)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// caught current hook successfully
		dwGlobal_CurrHookExecuted = 1;

		// restore correct instruction pointer
		CURRENT_EXCEPTION_INSTRUCTION_PTR = dwGlobal_OriginalReferenceValue;

		// continue execution
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD InitialiseTracer()
{
	NATIVE_VALUE dwWow64Transition = 0;
	PVOID(WINAPI * RtlAddVectoredExceptionHandler)(DWORD dwFirstHandler, void* pExceptionHandler) = NULL;
	HMODULE hNtdllBase = NULL;

	// store exe base
	pGlobal_ExeBase = (BYTE*)GetModuleHandleA(NULL);
	if (pGlobal_ExeBase == NULL)
	{
		return 1;
	}

	// get ntdll base
	hNtdllBase = GetModuleHandleA("ntdll.dll");
	if (hNtdllBase == NULL)
	{
		return 1;
	}

	// get RtlAddVectoredExceptionHandler function ptr
	RtlAddVectoredExceptionHandler = (void* (WINAPI*)(unsigned long, void*))GetProcAddress(hNtdllBase, "RtlAddVectoredExceptionHandler");
	if (RtlAddVectoredExceptionHandler == NULL)
	{
		return 1;
	}

	// add exception handler
	if (RtlAddVectoredExceptionHandler(1, (void*)ExceptionHandler) == NULL)
	{
		return 1;
	}

	// find Wow64Transition export
	dwWow64Transition = (NATIVE_VALUE)GetProcAddress(hNtdllBase, "Wow64Transition");
	if (dwWow64Transition != 0)
	{
		// get Wow64Transition stub address
		dwGlobal_Wow64TransitionStub = *(NATIVE_VALUE*)dwWow64Transition;
	}

	return 0;
}

DWORD BeginTrace(BYTE* pTargetFunction)
{
	CONTEXT DebugThreadContext;

	// reset values
	dwGlobal_TraceStarted = 0;
	dwGlobal_SuccessfulHookCount = 0;
	dwGlobal_AddressCount = 0;

	// set initial debug context - hardware breakpoint on target function
	memset((void*)&DebugThreadContext, 0, sizeof(DebugThreadContext));
	DebugThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	DebugThreadContext.Dr0 = (NATIVE_VALUE)pTargetFunction;
	DebugThreadContext.Dr7 = DEBUG_REGISTER_EXEC_DR0;
	if (SetThreadContext(GetCurrentThread(), &DebugThreadContext) == 0)
	{
		return 1;
	}

	// execute the target function
	ExecuteTargetFunction();

	return 0;
}

DWORD TestHooks()
{
	// attempt to hook the target function at all referenced instructions found earlier
	for (DWORD i = 0; i < dwGlobal_AddressCount; i++)
	{
		printf("\nOverwriting reference: 0x%p...\n", (void*)dwGlobal_AddressList[i]);

		// reset flag
		dwGlobal_CurrHookExecuted = 0;

		// store original value
		dwGlobal_OriginalReferenceValue = *(NATIVE_VALUE*)dwGlobal_AddressList[i];

		// overwrite referenced value with placeholder value
		*(NATIVE_VALUE*)dwGlobal_AddressList[i] = OVERWRITE_REFERENCE_ADDRESS_VALUE;

		printf("Calling target function...\n");

		// execute target function
		ExecuteTargetFunction();

		// restore original value
		*(NATIVE_VALUE*)dwGlobal_AddressList[i] = dwGlobal_OriginalReferenceValue;

		// check if the hook was executed
		if (dwGlobal_CurrHookExecuted == 0)
		{
			// hook wasn't executed - ignore
			printf("Failed to catch hook\n");
		}
		else
		{
			// hook was executed - this address can be used to hook the target function
			printf("Hook caught successfully!\n");
			dwGlobal_SuccessfulHookCount++;
		}
	}

	return 0;
}

DWORD ExecuteTargetFunction()
{
	// call the target function
	CreateFileA("temp_file.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	return 0;
}

// www.x86matthew.com
int main()
{

	// initialise tracer
	if (InitialiseTracer() != 0)
	{
		return 1;
	}

	printf("Searching for hooking points...\n\n");

	// begin trace
	if (BeginTrace((BYTE*)CreateFileA) != 0)
	{
		return 1;
	}

	// check if any referenced addresses were found
	if (dwGlobal_AddressCount == 0)
	{
		// none found
		printf("No potential hooking points found\n");
	}
	else
	{
		printf("\nFound %u potential hooking points, testing...\n", dwGlobal_AddressCount);

		// test all of the potential hooks
		if (TestHooks() != 0)
		{
			return 1;
		}
	}

	// finished
	printf("\nFinished - found %u successful hooking points\n\n", dwGlobal_SuccessfulHookCount);

	
	return 0;
}
