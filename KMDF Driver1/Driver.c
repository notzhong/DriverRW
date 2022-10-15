#include "Driver.h"

//创建链接符
UNICODE_STRING dev, dos;

//驱动卸载
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("驱动卸载");
	//删除链接符号
	IoDeleteSymbolicLink(&dos);
	//删除驱动设备
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

//创建过程
NTSTATUS Create(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//关闭过程
NTSTATUS Close(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//驱动控制方法
NTSTATUS IoContrl(PDEVICE_OBJECT pDerviceObject, PIRP Irp)
{
	//驱动状态
	NTSTATUS status = 0;
	ULONG BytesIO = 0;

	//获取IO_STACK_LOCATION
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	//获取设备控制码
	ULONG IoCtlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	//获取R3传入的buffer信息
	pPS input = (pPS)Irp->AssociatedIrp.SystemBuffer;
	PEPROCESS Process = NULL;

	//根据pid获取EPROCESS表
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)input->nPID, &Process)))
	{
		DbgPrint("获取EPROCESS表结构失败！！！");
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
		DbgPrint("进程保护！！！");
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
		DbgPrint("进程断链！！！");
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

//驱动入口方法
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("驱动加载");

	//分配驱动调用方法
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoContrl;
	
	//初始化链接符号
	RtlInitUnicodeString(&dev, L"\\Device\\RW64");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\RW64");

	//创建驱动设备
	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDriverObject->DeviceObject);

	//创建连接符号
	IoCreateSymbolicLink(&dos, &dev);

	return STATUS_SUCCESS;

}