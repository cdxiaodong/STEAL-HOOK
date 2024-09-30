# Project Summary

### Summary

**English:**

### Project Description: StealHook Test

**Overview:**
The "StealHook Test" project is a C++ application designed to analyze and manipulate the execution flow of a target function within a Windows environment. The primary goal is to trace the execution of a target function, identify its references across various modules, and subsequently test the effectiveness of hooks placed at these references. The project leverages Windows API functions, PE (Portable Executable) file structures, and exception handling mechanisms to achieve its objectives.

**Key Components:**

1. **Debug Registers and Exception Handling:**
   - The project utilizes hardware breakpoints set via debug registers (`Dr0`, `Dr1`, `Dr7`) to monitor the execution of the target function.
   - An exception handler (`ExceptionHandler`) is registered to manage `EXCEPTION_SINGLE_STEP` and `EXCEPTION_ACCESS_VIOLATION` exceptions. This handler is crucial for tracing the function's execution and identifying its references.

2. **Module Scanning:**
   - The `ScanModuleForAddress` function scans a given module for references to a specific address. It iterates through the sections of the module, excluding executable sections, and checks for the presence of the target address.
   - The `ScanAllModulesForAddress` function enumerates all loaded modules using the Process Environment Block (PEB) and calls `ScanModuleForAddress` for each module to find references to the target address.

3. **Tracer Initialization:**
   - The `InitialiseTracer` function sets up the tracer by obtaining the base address of the executable, loading necessary libraries (like `ntdll.dll`), and registering the exception handler using `RtlAddVectoredExceptionHandler`.
   - It also identifies the `Wow64Transition` stub address, which is used to handle transitions between 32-bit and 64-bit code.

4. **Tracing Execution:**
   - The `BeginTrace` function initiates the tracing process by setting a hardware breakpoint on the target function and executing it. This function resets global variables and prepares the debug context for tracing.
   - During execution, the exception handler manages the flow, setting additional breakpoints and scanning modules for references to the current instruction pointer.

5. **Hook Testing:**
   - The `TestHooks` function iterates through the list of identified references and attempts to overwrite them with a placeholder value (`OVERWRITE_REFERENCE_ADDRESS_VALUE`). It then calls the target function to test the effectiveness of these hooks.
   - The success of each hook is monitored by checking for `EXCEPTION_ACCESS_VIOLATION`, which indicates that the hook has been successfully executed.

**Platform Support:**
- The project is designed to support both 32-bit and 64-bit environments. Conditional compilation (`#if _WIN64`) is used to handle differences in data types and register usage between the two architectures.

**Summary:**
The "StealHook Test" project is a sophisticated tool for analyzing and manipulating function execution in a Windows environment. It leverages advanced techniques in debugging, exception handling, and PE file analysis to trace function calls, identify references, and test the effectiveness of hooks. The project is versatile, supporting both 32-bit and 64-bit architectures, and provides a comprehensive framework for understanding and modifying program execution flow.

### Project Description

This project is a tool designed to detect and analyze potential hooking points within a target function. The primary goal is to identify addresses that can be used to hook the target function, ensuring that the hooking mechanism is effective. The project involves several key components:

1. **Initialization and Tracing**:
   - The tool begins by initializing the tracer using the `InitialiseTracer()` function. If initialization fails, the program exits.
   - The `BeginTrace()` function is then called to start tracing the target function, in this case, `CreateFileA`.

2. **Detection of Hooking Points**:
   - The tool searches for potential hooking points by analyzing the addresses referenced by the target function.
   - If no potential hooking points are found (`dwGlobal_AddressCount == 0`), a message is printed indicating that no points were found.

3. **Testing Hooks**:
   - If potential hooking points are found, the tool proceeds to test each one using the `TestHooks()` function.
   - For each potential hooking point, the tool executes the target function (`ExecuteTargetFunction()`), which in this case creates a temporary file.
   - After executing the target function, the tool checks if the hook was successfully executed by verifying the `dwGlobal_CurrHookExecuted` flag.
   - If the hook is successfully caught, the tool increments the `dwGlobal_SuccessfulHookCount` and prints a success message.

4. **Final Output**:
   - After testing all potential hooking points, the tool prints the total number of successful hooking points found.

### Key Functions:
- **`InitialiseTracer()`**: Initializes the tracer.
- **`BeginTrace((BYTE*)CreateFileA)`**: Starts tracing the `CreateFileA` function.
- **`TestHooks()`**: Tests each potential hooking point.
- **`ExecuteTargetFunction()`**: Calls the target function (`CreateFileA`) to create a temporary file.

### Summary:
This tool is useful for security researchers and developers who need to identify and validate hooking points within a target function. By detecting these points, the tool helps ensure that any hooking mechanisms implemented are effective and reliable.

**Chinese:**

### 项目描述：StealHook 测试

**概述：**
“StealHook 测试”项目是一个 C++ 应用程序，旨在分析和操纵 Windows 环境中目标函数的执行流程。其主要目标是跟踪目标函数的执行，识别其在各个模块中的引用，并随后测试在这些引用处放置的钩子的有效性。该项目利用 Windows API 函数、PE（可移植可执行文件）结构和异常处理机制来实现其目标。

**关键组件：**

1. **调试寄存器和异常处理：**
   - 该项目通过调试寄存器（`Dr0`、`Dr1`、`Dr7`）设置硬件断点来监控目标函数的执行。
   - 注册了一个异常处理程序（`ExceptionHandler`）来管理 `EXCEPTION_SINGLE_STEP` 和 `EXCEPTION_ACCESS_VIOLATION` 异常。该处理程序对于跟踪函数的执行和识别其引用至关重要。

2. **模块扫描：**
   - `ScanModuleForAddress` 函数扫描给定模块中对特定地址的引用。它遍历模块的各个节区，排除可执行节区，并检查目标地址的存在。
   - `ScanAllModulesForAddress` 函数使用进程环境块（PEB）枚举所有加载的模块，并调用 `ScanModuleForAddress` 为每个模块查找对目标地址的引用。

3. **跟踪器初始化：**
   - `InitialiseTracer` 函数通过获取可执行文件的基地址、加载必要的库（如 `ntdll.dll`）并使用 `RtlAddVectoredExceptionHandler` 注册异常处理程序来设置跟踪器。
   - 它还识别 `Wow64Transition` 存根地址，用于处理 32 位和 64 位代码之间的转换。

4. **跟踪执行：**
   - `BeginTrace` 函数通过在目标函数上设置硬件断点并执行它来启动跟踪过程。该函数重置全局变量并为跟踪准备调试上下文。
   - 在执行过程中，异常处理程序管理流程，设置额外的断点并扫描模块以查找对当前指令指针的引用。

5. **钩子测试：**
   - `TestHooks` 函数遍历已识别的引用列表，并尝试用占位符值（`OVERWRITE_REFERENCE_ADDRESS_VALUE`）覆盖它们。然后调用目标函数以测试这些钩子的有效性。
   - 通过检查 `EXCEPTION_ACCESS_VIOLATION` 来监控每个钩子的成功与否，这表明钩子已成功执行。

**平台支持：**
- 该项目设计为支持 32 位和 64 位环境。条件编译（`#if _WIN64`）用于处理两种架构之间数据类型和寄存器使用的差异。

**总结：**
“StealHook 测试”项目是一个复杂的工具，用于分析和操纵 Windows 环境中的函数执行。它利用调试、异常处理和 PE 文件分析的高级技术来跟踪函数调用、识别引用并测试钩子的有效性。该项目具有多功能性，支持 32 位和 64 位架构，并提供了一个全面的框架来理解和修改程序执行流程。

### 项目描述

该项目是一个工具，旨在检测和分析目标函数中潜在的钩子点。其主要目标是识别可用于钩住目标函数的地址，确保钩子机制有效。项目涉及几个关键组件：

1. **初始化和跟踪**：
   - 工具首先使用 `InitialiseTracer()` 函数初始化跟踪器。如果初始化失败，程序退出。
   - 然后调用 `BeginTrace()` 函数开始跟踪目标函数，在本例中为 `CreateFileA`。

2. **检测钩子点**：
   - 工具通过分析目标函数引用的地址来搜索潜在的钩子点。
   - 如果未找到潜在的钩子点（`dwGlobal_AddressCount == 0`），则打印一条消息，指示未找到任何点。

3. **测试钩子**：
   - 如果找到潜在的钩子点，工具使用 `TestHooks()` 函数对每个点进行测试。
   - 对于每个潜在的钩子点，工具执行目标函数（`ExecuteTargetFunction()`），在本例中创建一个临时文件。
   - 执行目标函数后，工具通过验证 `dwGlobal_CurrHookExecuted` 标志来检查钩子是否成功执行。
   - 如果钩子成功捕获，工具增加 `dwGlobal_SuccessfulHookCount` 并打印成功消息。

4. **最终输出**：
   - 在测试所有潜在的钩子点后，工具打印找到的成功钩子点的总数。

### 关键函数：
- **`InitialiseTracer()`**：初始化跟踪器。
- **`BeginTrace((BYTE*)CreateFileA)`**：开始跟踪 `CreateFileA` 函数。
- **`TestHooks()`**：测试每个潜在的钩子点。
- **`ExecuteTargetFunction()`**：调用目标函数（`CreateFileA`）创建临时文件。

### 总结：
该工具对安全研究人员和开发者非常有用，他们需要识别和验证目标函数中的钩子点。通过检测这些点，工具有助于确保任何实现的钩子机制都是有效和可靠的。

### Content

## File: stealhook-test.cpp

```
﻿#include <stdio.h>
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

```

----------------------------------------

