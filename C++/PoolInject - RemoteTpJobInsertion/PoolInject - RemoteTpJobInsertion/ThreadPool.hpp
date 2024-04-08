#pragma once
#include "Misc.hpp"

/* https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00499 */

//line 522 ntpsapi.h process hacker
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

//line 533 ntpsapi.h process hacker
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

typedef enum _QUERY_WORKERFACTORYINFOCLASS
{
    WorkerFactoryBasicInformation = 7,
} QUERY_WORKERFACTORYINFOCLASS, * PQUERY_WORKERFACTORYINFOCLASS;

//typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {
//
//    UNICODE_STRING TypeName;
//    ULONG Reserved[22];    // reserved for internal use
//
//} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationWorkerFactoryPtr)(
    HANDLE WorkerFactoryHandle,
    QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
    );

typedef enum _SET_WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout = 0,
    WorkerFactoryRetryTimeout = 1,
    WorkerFactoryIdleTimeout = 2,
    WorkerFactoryBindingCount = 3,
    WorkerFactoryThreadMinimum = 4,
    WorkerFactoryThreadMaximum = 5,
    WorkerFactoryPaused = 6,
    WorkerFactoryAdjustThreadGoal = 8,
    WorkerFactoryCallbackType = 9,
    WorkerFactoryStackInformation = 10,
    WorkerFactoryThreadBasePriority = 11,
    WorkerFactoryTimeoutWaiters = 12,
    WorkerFactoryFlags = 13,
    WorkerFactoryThreadSoftMaximum = 14,
    WorkerFactoryMaxInfoClass = 15 /* Not implemented */
} SET_WORKERFACTORYINFOCLASS, * PSET_WORKERFACTORYINFOCLASS;

typedef NTSTATUS(NTAPI* NtSetInformationWorkerFactoryPtr)(
    HANDLE hWorkerFactory,
    SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
    );

typedef NTSTATUS(NTAPI* ZwAssociateWaitCompletionPacketPtr)(
    _In_ HANDLE 		WaitCompletionPacketHandle,
    _In_ HANDLE 		IoCompletionHandle,
    _In_ HANDLE 		TargetObjectHandle,
    _In_opt_ PVOID 		KeyContext,
    _In_opt_ PVOID 		ApcContext,
    _In_ NTSTATUS 		IoStatus,
    _In_ ULONG_PTR 		IoStatusInformation,
    _Out_opt_ PBOOLEAN 	AlreadySignaled
    );

typedef NTSTATUS(NTAPI* ZwSetInformationFilePtr)(
    HANDLE hFile,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
    );
typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;

typedef enum
{
    FileReplaceCompletionInformation = 61
} FILE_INFOCLASS;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    unsigned long Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    unsigned __int64 MaxMessageLength;
    unsigned __int64 MemoryBandwidth;
    unsigned __int64 MaxPoolUsage;
    unsigned __int64 MaxSectionSize;
    unsigned __int64 MaxViewSize;
    unsigned __int64 MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

EXTERN_C
NTSTATUS NTAPI NtAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
    PVOID CompletionKey;
    HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

EXTERN_C
NTSTATUS NTAPI NtAlpcSetInformation(
    _In_ HANDLE PortHandle,
    _In_ ULONG PortInformationClass,
    _In_opt_ PVOID PortInformation,
    _In_ ULONG Length
);

typedef enum
{
    AlpcAssociateCompletionPortInformation = 2
} ALPC_PORT_INFOCLASS;


typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
        ULONG CallbackId; // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE PortHeader;
    BYTE PortMessage[1000]; // Hard limit for this is 65488. An Error is thrown if AlpcMaxAllowedMessageLength() is exceeded
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

EXTERN_C
NTSTATUS NTAPI NtAlpcConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ DWORD ConnectionFlags,
    _In_opt_ PSID RequiredServerSid,
    _In_opt_ PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T ConnectMessageSize,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);