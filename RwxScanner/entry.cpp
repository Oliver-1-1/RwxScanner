#include <ntifs.h>
#include <ntimage.h>
#include <ntifs.h>
#include <intrin.h>
#include "ia32.hpp"
#include <ntddk.h>

extern "C" __declspec(dllimport) PCSTR PsGetProcessImageFileName(PEPROCESS);
extern "C" __declspec(dllimport) BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS);

UINT64 GetProcessCr3(UINT64 eprocess)
{
	// _EPROCESS -> _KPROCESS -> 0x28;
	return *(UINT64*)(eprocess + 0x28);
}

BOOLEAN IsAdminProcess(PEPROCESS eprocess)
{
	BOOLEAN admin = FALSE;
	PACCESS_TOKEN token = PsReferencePrimaryToken(eprocess);

	admin = SeTokenIsAdmin(token);

	ObDereferenceObject(token);

	return admin;
}

void WalkPages(UINT64 eprocess)
{
	cr3 ctx;
	ctx.flags = GetProcessCr3(eprocess);
	UINT8 supervisor = ctx.flags == __readcr3();
	PHYSICAL_ADDRESS physical_addr;
	physical_addr.QuadPart = ctx.address_of_page_directory << PAGE_SHIFT;

	pml4e_64 pml4[512];
	SIZE_T size;
	NTSTATUS status = MmCopyMemory(&pml4, *(MM_COPY_ADDRESS*)&physical_addr, sizeof(pml4), MM_COPY_MEMORY_PHYSICAL, &size);

	if (status != STATUS_SUCCESS)
	{
		return;
	}

	for (UINT64 pml4_i = 0; pml4_i < 512; pml4_i++)
	{
		physical_addr.QuadPart = pml4[pml4_i].page_frame_number << PAGE_SHIFT;

		if (!pml4[pml4_i].present || pml4[pml4_i].supervisor == supervisor)
		{
			continue;
		}

		pdpte_64 pdpt[512];
		status = MmCopyMemory(&pdpt, *(MM_COPY_ADDRESS*)&physical_addr, sizeof(pdpt), MM_COPY_MEMORY_PHYSICAL, &size);

		if (status != STATUS_SUCCESS)
		{
			continue;
		}

		for (UINT64 pdpt_i = 0; pdpt_i < 512; pdpt_i++)
		{
			physical_addr.QuadPart = pdpt[pdpt_i].page_frame_number << PAGE_SHIFT;

			if (!pdpt[pdpt_i].present || pdpt[pdpt_i].large_page || pdpt[pdpt_i].supervisor == supervisor)
			{
				continue;
			}


			pde_64 pd[512];
			status = MmCopyMemory(&pd, *(MM_COPY_ADDRESS*)&physical_addr, sizeof(pd), MM_COPY_MEMORY_PHYSICAL, &size);

			if (status != 0)
			{
				continue;
			}

			for (UINT64 pde_i = 0; pde_i < 512; pde_i++)
			{
				physical_addr.QuadPart = pd[pde_i].page_frame_number << PAGE_SHIFT;

				if (!pd[pde_i].present || pd[pde_i].large_page || pd[pde_i].supervisor == supervisor)
				{
					continue;
				}

				pte_64 pt[512];
				status = MmCopyMemory(&pt, *(MM_COPY_ADDRESS*)&physical_addr, sizeof(pt), MM_COPY_MEMORY_PHYSICAL, &size);

				if (status != STATUS_SUCCESS)
				{
					continue;
				}

				for (UINT64 pte_i = 0; pte_i < 512; pte_i++)
				{
					physical_addr.QuadPart = pt[pte_i].page_frame_number << PAGE_SHIFT;

					if (pt[pte_i].execute_disable == FALSE && pt[pte_i].present == TRUE && pt[pte_i].write == TRUE && pt[pte_i].supervisor == !supervisor)
					{
						UINT64 virtual_address = (pml4_i << 39) | (pdpt_i << 30) | (pde_i << 21) | (pte_i << 12);

						DbgPrintEx(0, 0, "rwx region: phys: %p virt: %p name: %s admin: %d \n", physical_addr.QuadPart, virtual_address, PsGetProcessImageFileName((PEPROCESS)eprocess), IsAdminProcess((PEPROCESS)eprocess));
						//return;
					}
				}
			}
		}
	}
}

void GetEProcesses()
{
	UINT64 process;
	UINT64 entry;

	UINT32 g = *(UINT32*)((UINT8*)PsGetProcessId + 3) + 8;
	process = (UINT64)PsInitialSystemProcess;

	entry = process;
	do {
		if (PsGetProcessExitProcessCalled((PEPROCESS)entry))
			goto L0;

		if (PsGetProcessImageFileName((PEPROCESS)entry))
		{
			WalkPages(entry);
		}
	L0:
		entry = *(UINT64*)(entry + g) - g;
	} while (entry != process);

}

VOID DriverUnload(DRIVER_OBJECT* DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrintEx(0, 0, "Unload\n");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	GetEProcesses();

	return STATUS_SUCCESS;
}
