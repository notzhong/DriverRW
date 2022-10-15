#pragma once
#include <ntddk.h>


typedef struct ProcessStru
{
	ULONG64 nPID;
    ULONG64 pSorceAddr;
    ULONG64 pTargetAddr;
	ULONG64 nSize;
}PS, * pPS;

#define ID_Read			CTL_CODE(FILE_DEVICE_UNKNOWN,0x6001,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define ID_Write		CTL_CODE(FILE_DEVICE_UNKNOWN,0x6002,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define ID_Protect		CTL_CODE(FILE_DEVICE_UNKNOWN,0x6003,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define ID_ProcessLink	CTL_CODE(FILE_DEVICE_UNKNOWN,0x6004,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)


extern NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern NTSTATUS PsLookupProcessByProcessId
(
	HANDLE ProcessId,
	PEPROCESS* pEprocess
);


extern NTSTATUS ReadVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
extern NTSTATUS WriteVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
extern void ProtectProcess(PEPROCESS eProcess, int bEnable);
extern void ProcessLink(PEPROCESS);