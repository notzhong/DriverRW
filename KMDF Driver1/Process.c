#include "Driver.h"

//�������ڴ������
NTSTATUS ReadVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	DbgPrint("Source %p, Target %p, Target %llu\n", SourceAddress, TargetAddress, Size);
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

//�������ڴ�д����
NTSTATUS WriteVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	DbgPrint("Source %p, Target %p, Target %d,lenth%llu\n", SourceAddress, TargetAddress, *(int*)TargetAddress, Size);

	PEPROCESS pTest = PsGetCurrentProcess();

	DbgPrint("PID:%llu", *(PULONG64)((ULONG64)pTest + 0x2e8));

	NTSTATUS result = MmCopyVirtualMemory(pTest, SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes);

	DbgPrint("ִ�з����룺%lu\n", result);

	if (NT_SUCCESS(result))
	{
		DbgPrint("д��ɹ�\n");
		return STATUS_SUCCESS;
	}
	else
	{
		DbgPrint("д��failed \n");
		return STATUS_ACCESS_DENIED;
	}
}

//�����رս��̱���
void ProtectProcess(PEPROCESS eProcess, int bEnable)
{
	DbgPrint("���̱�������");
	*(UCHAR*)((ULONG64)eProcess + 0x6fa) = bEnable ? 0x72 : 0x0;
}

//���̶�������
void ProcessLink(PEPROCESS eProcess)
{
	DbgPrint("�������̶�������\n");
	PLIST_ENTRY pCurent = (PLIST_ENTRY)((ULONG64)eProcess + 0x2f0);
	PLIST_ENTRY pre = NULL, next = NULL;
	pre = pCurent->Flink;
	next = pCurent->Blink;
	
	pre->Blink = next;
	next->Flink = pre;

	pCurent->Flink = pCurent;
	pCurent->Blink = pCurent;
}