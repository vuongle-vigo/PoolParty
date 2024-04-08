import ctypes
from ctypes import *
from ctypes.wintypes import *

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_OVERLAPPED = 0x40000000


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("maximum_length", ctypes.c_ushort),
        ("buffer", ctypes.POINTER(ctypes.c_wchar))
    ]


class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", POINTER(ULONG)),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", WCHAR * MAX_PATH)
    ]

    def __init__(self):
        # Make sure the size of the structure is set correctly before use
        self.dwSize = sizeof(self)


LPPROCESSENTRY32W = POINTER(PROCESSENTRY32W)


class PROCESS_HANDLE_SNAPSHOT_INFORMATION(Structure):
    _fields_ = [
        ("number_of_handles", c_size_t),  # ULONG_PTR
        ("reversed", c_size_t)  # ULONG_PTR
        # pub handles:  PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];,
        # don' t use because python not support dynamic struct
    ]


class PROCESS_HANDLE_TABLE_ENTRY_INFO(Structure):
    _fields_ = [
        ("handle_value", HANDLE),
        ("handle_count", c_size_t),
        ("pointer_count", c_size_t),
        ("granted_access", ULONG),
        ("object_type_index", ULONG),
        ("handle_attributes", ULONG),
        ("reserved", ULONG)
    ]


class PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = [
        ("type_name", UNICODE_STRING),
        ("reversed", ULONG)
    ]


class FILE_COMPLETION_INFORMATION(Structure):
    _fields_ = [
        ("port", HANDLE),
        ("key", LPVOID)
    ]


class UINICODE_STRING(Structure):
    _fields_ = [
        ("length", USHORT),
        ("maximum_length", USHORT),
        ("buffer", LPWSTR)
    ]


PUNICODE_STRING = POINTER(UINICODE_STRING)


class OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("length", ULONG),
        ("root_directory", HANDLE),
        ("object_name", POINTER(UNICODE_STRING)),
        ("attributes", ULONG),
        ("security_descriptor", LPVOID),
        ("security_quality_of_service", LPVOID)
    ]


class ALPC_PORT_ASSOCIATE_COMPLETION_PORT(Structure):
    _fields_ = [
        ("completion_key", LPVOID),
        ("completion_port", HANDLE)
    ]


class JOBOBJECT_ASSOCIATE_COMPLETION_PORT(Structure):
    _fields_ = [
        ("completion_key", LPVOID),
        ("completion_port", HANDLE)
    ]



# Define CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = HANDLE
CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]

# Define Process32FirstW
Process32FirstW = windll.kernel32.Process32FirstW
Process32FirstW.restype = BOOL
Process32FirstW.argtypes = [HANDLE, LPPROCESSENTRY32W]

# Define Process32NextW
Process32NextW = windll.kernel32.Process32NextW
Process32NextW.restype = BOOL
Process32NextW.argtypes = [HANDLE, LPPROCESSENTRY32W]

# Define OpenProcess
OpenProcess = windll.kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = [DWORD, BOOL, DWORD]

# Define NtQueryInformationProcess
NtQueryInformationProcess = windll.ntdll.NtQueryInformationProcess
NtQueryInformationProcess.restype = DWORD  # NTSTATUS
NtQueryInformationProcess.argtypes = [HANDLE, DWORD, LPVOID, ULONG, PULONG]

# Define DuplicateHandle
DuplicateHandle = windll.kernel32.DuplicateHandle
DuplicateHandle.restype = BOOL
DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD]

# Define GetCurrentProcess
GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = HANDLE
GetCurrentProcess.argtypes = []

# Define NtQueryObject
NtQueryObject = windll.ntdll.NtQueryObject
NtQueryObject.restype = DWORD  # NTSTATUS
NtQueryObject.argtypes = [HANDLE, DWORD,  # enum OBJECT_INFORMATION_CLASS
                          LPVOID, ULONG, PULONG]

# Define VirtualAllocEx
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAllocEx.restype = LPVOID
VirtualAllocEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD, DWORD]

# Define WriteProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]

# Define ReadProcessMemory
ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = BOOL
ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]

# Define CreateThreadpoolWait
CreateThreadpoolWait = windll.kernel32.CreateThreadpoolWait
CreateThreadpoolWait.restype = LPVOID
CreateThreadpoolWait.argtypes = [LPVOID, LPVOID, LPVOID]

# Define CreateEventW
CreateEventW = windll.kernel32.CreateEventW
CreateEventW.restype = HANDLE
CreateEventW.argtypes = [LPVOID, BOOL, BOOL, LPCWSTR]

# Define ZwAssociateWaitCompletionPacket
ZwAssociateWaitCompletionPacket = windll.ntdll.ZwAssociateWaitCompletionPacket
ZwAssociateWaitCompletionPacket.restype = DWORD  # NTSTATUS
ZwAssociateWaitCompletionPacket.argtypes = [HANDLE, HANDLE, HANDLE, LPVOID, LPVOID, DWORD,  # NTSTATUS
                                            ctypes.c_size_t, PBOOLEAN]

# Define SetEvent
SetEvent = windll.kernel32.SetEvent
SetEvent.restype = BOOL
SetEvent.argtypes = [HANDLE]

# Define NtQueryInformationWorkerFactory
NtQueryInformationWorkerFactory = windll.ntdll.NtQueryInformationWorkerFactory
NtQueryInformationWorkerFactory.restype = DWORD  # NTSTATUS
NtQueryInformationWorkerFactory.argtypes = [HANDLE, DWORD,  # enum WORKERFACTORYINFOCLASS
                                            LPVOID, ULONG, PULONG]

# Define NtSetInformationWorkerFactory
NtSetInformationWorkerFactory = windll.ntdll.NtSetInformationWorkerFactory
NtSetInformationWorkerFactory.restype = DWORD  # NTSTATUS
NtSetInformationWorkerFactory.argtypes = [HANDLE, DWORD,  # enum WORKERFACTORYINFOCLASS
                                          LPVOID, ULONG]

# Define CreateThreadpoolWork
CreateThreadpoolWork = windll.kernel32.CreateThreadpoolWork
CreateThreadpoolWork.restype = LPVOID
CreateThreadpoolWork.argtypes = [LPVOID, LPVOID, LPVOID]

# Define CreateFileW
CreateFileW = windll.kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = [LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]

# Define CreateThreadpoolIo
CreateThreadpoolIo = windll.kernel32.CreateThreadpoolIo
CreateThreadpoolIo.restype = LPVOID
CreateThreadpoolIo.argtypes = [HANDLE, LPVOID, LPVOID, LPVOID]

# Define ZwSetInformationFile
ZwSetInformationFile = windll.ntdll.ZwSetInformationFile
ZwSetInformationFile.restype = DWORD  # NTSTATUS
ZwSetInformationFile.argtypes = [HANDLE, LPVOID, LPVOID, ULONG, DWORD]  # FILE_INFORMATION_CLASS

# Define WriteFile
WriteFile = windll.kernel32.WriteFile
WriteFile.restype = BOOL
WriteFile.argtypes = [HANDLE, LPCVOID, DWORD, POINTER(DWORD), POINTER(c_ubyte)]  # LPOVERLAPPED struct

# Define NtAlpcCreatePort
NtAlpcCreatePort = windll.ntdll.NtAlpcCreatePort
NtAlpcCreatePort.restype = DWORD  # NTSTATUS
NtAlpcCreatePort.argtypes = [PHANDLE, LPVOID, LPVOID]

# Define TpAllocAlpcCompletion
TpAllocAlpcCompletion = windll.ntdll.TpAllocAlpcCompletion
TpAllocAlpcCompletion.restype = DWORD  # NTSTATUS
TpAllocAlpcCompletion.argtypes = [POINTER(LPVOID), HANDLE, LPVOID, LPVOID, LPVOID]

# Define NtAlpcSetInformation
NtAlpcSetInformation = windll.ntdll.NtAlpcSetInformation
NtAlpcSetInformation.restype = DWORD # NTSTATUS
NtAlpcSetInformation.argtypes = [HANDLE, DWORD, # ALPC_PORT_INFORMATION_CLASS
                                 LPVOID, ULONG]

# Define NtAlpcConnectPort
NtAlpcConnectPort = windll.ntdll.NtAlpcConnectPort
NtAlpcConnectPort.restype = DWORD   # NTSTATUS
NtAlpcConnectPort.argtypes = [PHANDLE, LPVOID, POINTER(OBJECT_ATTRIBUTES), LPVOID, ULONG, LPVOID, LPVOID, PSIZE, LPVOID, LPVOID, LPVOID]

# Define CreateJobObjectW
CreateJobObjectW = windll.kernel32.CreateJobObjectW
CreateJobObjectW.restype = HANDLE
CreateJobObjectW.argtypes = [LPVOID, LPCWSTR]

# Define TpAllocJobNotification
TpAllocJobNotification = windll.ntdll.TpAllocJobNotification
TpAllocJobNotification.restype = DWORD # NTSTATUS
TpAllocJobNotification.argtypes = [POINTER(LPVOID), HANDLE, LPVOID, LPVOID, LPVOID]

# Define SetInformationJobObject
SetInformationJobObject = windll.kernel32.SetInformationJobObject
SetInformationJobObject.restype = BOOL
SetInformationJobObject.argtypes = [HANDLE, DWORD, # JOBOBJECTINFOCLASS
                                    LPVOID, DWORD]

# Define AssignProcessToJobObject
AssignProcessToJobObject = windll.kernel32.AssignProcessToJobObject
AssignProcessToJobObject.restype = BOOL
AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]

# Define ZwSetIoCompletion
ZwSetIoCompletion = windll.ntdll.ZwSetIoCompletion
ZwSetIoCompletion.restype = DWORD # NTSTATUS
ZwSetIoCompletion.argtypes = [HANDLE, LPVOID, LPVOID, DWORD, c_size_t]

# Define CreateThreadpoolTimer
CreateThreadpoolTimer = windll.kernel32.CreateThreadpoolTimer
CreateThreadpoolTimer.restype = LPVOID
CreateThreadpoolTimer.argtypes = [LPVOID, LPVOID, LPVOID]

# Define NtSetTimer2
NtSetTimer2 = windll.ntdll.NtSetTimer2
NtSetTimer2.restype = DWORD # NTSTAUS
NtSetTimer2.argtypes = [HANDLE, LPVOID, LPVOID, LPVOID]