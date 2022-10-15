#include "Driver.h"

//�������ӷ�
UNICODE_STRING dev, dos;

//����ж��
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("����ж��");
	//ɾ�����ӷ���
	IoDeleteSymbolicLink(&dos);
	//ɾ�������豸
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

//��������
NTSTATUS Create(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//�رչ���
NTSTATUS Close(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//�������Ʒ���
NTSTATUS IoContrl(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	//����״̬
	NTSTATUS status = 0;
	ULONG BytesIO = 0;

	//��ȡIO_STACK_LOCATION
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	//��ȡ�豸������
	ULONG IoCtlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	//��ȡR3�����buffer��Ϣ
	pPS input = (pPS)Irp->AssociatedIrp.SystemBuffer;
	PEPROCESS Process = NULL;

	//����pid��ȡEPROCESS��
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)input->nPID, &Process)))
	{
		DbgPrint("��ȡEPROCESS��ṹʧ�ܣ�����");
		return STATUS_SUCCESS;
	}
	switch (IoCtlCode)
	{
	case ID_Read:
	{
		ReadVirtualProcessMemory(Process, (PVOID)input->pSorceAddr, (PVOID)input->pTargetAddr, input->nSize);
		BytesIO = sizeof(pPS);
		status = STATUS_SUCCESS;
		break;
	}
	case ID_Write:
	{
		DbgPrint("Size:%llu\n", input->nSize);
		WriteVirtualProcessMemory(Process, (PVOID)input->pSorceAddr, (PVOID)input->pTargetAddr, input->nSize);
		BytesIO = sizeof(pPS);
		status = STATUS_SUCCESS;
		break;
	}
	case ID_Protect:
	{
		static int bEnable = 1;
		DbgPrint("���̱���������");
		if (bEnable)
		{
			ProtectProcess(Process, bEnable);
			bEnable = 0;
		}
		else {
			ProtectProcess(Process, bEnable);
			bEnable = 1;
		}
		break;
	}
	case ID_ProcessLink:
	{
		DbgPrint("���̶���������");
		ProcessLink(Process);
		break;
	}
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//������ڷ���
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("��������");

	//�����������÷���
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoContrl;
	
	//��ʼ�����ӷ���
	RtlInitUnicodeString(&dev, L"\\Device\\RW64");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\RW64");

	//���������豸
	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDriverObject->DeviceObject);

	//�������ӷ���
	IoCreateSymbolicLink(&dos, &dev);

	return STATUS_SUCCESS;

}