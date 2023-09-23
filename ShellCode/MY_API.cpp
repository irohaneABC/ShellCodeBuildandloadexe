#include "TOOL.h"

 
#include <iostream>
#include<windows.h>


//字符串哈希算法
DWORD Hash_GetDigest(char* strFunName)
{
	//字符串长度大于3保证Hash值中不包含0
	DWORD dwDigest = 0;
	while (*strFunName)
	{
		dwDigest = (dwDigest << 25 | dwDigest >> 7);
		dwDigest += *strFunName;
		strFunName++;
	}
	return dwDigest;
}

bool Hash_CmpString(char* strFunName, int nHash)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = ((nDigest << 25) | (nDigest >> 7));
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nHash == nDigest ? true : false;
}



bool _Is_64Peformat(char* lpPeBufer)
{
	PIMAGE_FILE_HEADER _File = (PIMAGE_FILE_HEADER) & ((PIMAGE_NT_HEADERS)((((PIMAGE_DOS_HEADER)lpPeBufer)->e_lfanew) + lpPeBufer))->FileHeader;
	if (_File->Machine == IMAGE_FILE_MACHINE_AMD64 ||
		_File->Machine == IMAGE_FILE_MACHINE_IA64) // may be IMAGE_FILE_MACHINE_I386
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}


DWORD64 GetFunAddrByHash(int nHashDigest, HMODULE hModule)
{

	// 1. 获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	// 2. 获取导出表项
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;

	pDos_Header = (PIMAGE_DOS_HEADER)hModule;
	if (_Is_64Peformat((char*)(hModule)) == TRUE)
	{
		PIMAGE_NT_HEADERS64 pNt_Header;
		pNt_Header = (PIMAGE_NT_HEADERS64)((DWORD64)hModule + pDos_Header->e_lfanew);
		pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;

	}
	else
	{
		PIMAGE_NT_HEADERS pNt_Header;
		pNt_Header = (PIMAGE_NT_HEADERS)((DWORD64)hModule + pDos_Header->e_lfanew);
		pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	}




	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)hModule + pDataDir->VirtualAddress);



	// 3. 获取导出表详细信息
	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + (DWORD64)hModule);
	PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + (DWORD64)hModule);
	PWORD  pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD64)hModule);

	// 4. 处理以函数名查找函数地址的请求，循环获取ENT中的函数名（因为是以函数名
	//    为基准，因此不考虑无函数名的情况），并与传入值对比，如能匹配上则在EAT
	//    中以指定序号作为索引，并取出其地址值。
	DWORD64 dwFunAddr;
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfNames[i] + (DWORD64)hModule);
		if (Hash_CmpString(lpFunName, nHashDigest))
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + (DWORD64)hModule;
			break;
		}
		if (i == pExport->NumberOfNames - 1)
			return 0;
	}

	return dwFunAddr;
}


char* RetX32RunExeAdr(char* pExeAddr, HMODULE Kernel32)
{
	// 1. 局部字符串
	CHAR szUser32[] = { 'u','s','e','r','3','2','.','d','l','l','\0' };
	CHAR szKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
	CHAR szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
	CHAR szCMD[] = { 'c','m','d','.','e','x','e','\0' };
	CHAR csVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c' ,'\0' };



	CHAR csVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
	CHAR csGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
	CHAR csCreateThread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d' ,'\0' };
	CHAR csWaitForSingleObject[] = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t','\0' };


	// 2. 获取关键模块基址
	HMODULE hKernel32By64 = 0;
	HMODULE hNtDll = 0;
	DWORD ImageBase = 0;
	HMODULE hUser32 = 0;



	// 3. 获取关键模块基址
	DefineFuncPtr(LoadLibraryExA, Kernel32);
	hKernel32By64 = My_LoadLibraryExA(szKernel32, 0, 0);
	hNtDll = My_LoadLibraryExA(szntdll, 0, 0);
	hUser32 = My_LoadLibraryExA(szUser32, 0, 0);

	
	DefineFuncPtr(VirtualAlloc, hKernel32By64);
	DefineFuncPtr(VirtualProtect, hKernel32By64);
	DefineFuncPtr(CreateThread, hKernel32By64);
	DefineFuncPtr(WaitForSingleObject, hKernel32By64);
	DefineFuncPtr(GetProcAddress, hKernel32By64);


	//User32
	DefineFuncPtr(MessageBoxA, hUser32);

	//ntdll
	DefineFuncPtr(memcpy, hNtDll);
	DefineFuncPtr(sprintf, hNtDll);



	HANDLE hFile = NULL;
	HANDLE hFileMaping = NULL;
	//获取一些基本变量
	//PE初始化
	// 	   PIMAGE_NT_HEADERS
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pExeAddr;
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	PIMAGE_SECTION_HEADER pSectionHdr = NULL;
	int SectionCount = 0;
	int SectionAlignment = 0;
	int FileAlignment = 0;


	//--------------------------------------------------------------------------------------------------------------------------------------申请新内存
	pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)pExeAddr + ((PIMAGE_DOS_HEADER)pExeAddr)->e_lfanew);
	pSectionHdr = (PIMAGE_SECTION_HEADER)((DWORD)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);	

	SectionCount = pNtHdr->FileHeader.NumberOfSections;				//区段数
	SectionAlignment = pNtHdr->OptionalHeader.SectionAlignment;		//内存对其方式
	FileAlignment = pNtHdr->OptionalHeader.FileAlignment;			//文件对其方式


	//申请一个载入 内存后大小的空间
	PVOID pNewPe = My_VirtualAlloc(NULL, pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);		
	if (pNewPe == NULL)
	{
		return 0;
	}

	//拉伸PE 扩展块
	My_memcpy((void*)pNewPe, (void*)pDosHdr, pNtHdr->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < SectionCount; i++)
	{
		My_memcpy(
			(void*)((DWORD)pNewPe + pSectionHdr[i].VirtualAddress),			//VirtualAddress Rva 直接 加PE Va即可
			(void*)((DWORD)pExeAddr + pSectionHdr[i].PointerToRawData),		//直接从文件区段读取即可
			pSectionHdr[i].SizeOfRawData);									//拷贝区段大小
	}



	//-------------------------------------------------------------------------------------------------------------------------------------修复导入表

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pNewPe + pNtHdr->OptionalHeader.DataDirectory[1].VirtualAddress);

	do
	{
		const char* pDllPath = (const char*)(pImportTable->Name + (DWORD)pNewPe);
		PDWORD pIat = (PDWORD)(pImportTable->FirstThunk + (DWORD)pNewPe);
		if (*pIat == NULL)
		{
			pImportTable++;
			continue;
		}
		HMODULE hModule = My_LoadLibraryExA(pDllPath, 0, 0);
		if (hModule == NULL)
		{
			return 0;
		}
		else
		{
			do
			{
				if (((*pIat) >> 31) != 1)
				{
					PIMAGE_IMPORT_BY_NAME Name = (PIMAGE_IMPORT_BY_NAME)((DWORD)pNewPe + *pIat);
					*pIat = (DWORD)My_GetProcAddress(hModule, Name->Name);
				}
				else
				{
					*pIat = (DWORD)My_GetProcAddress(hModule, (const char*)((*pIat) & 0x7fffffff));
				}
				pIat++;
			} while (*pIat);
		}
		pImportTable++;
	} while (pImportTable->Name != NULL);



	//--------------------------------------------------------------------------------------------------------------------------------------修复重定位表
	DWORD Offset = NULL;
	int BaseTableSize = NULL;
	int NowSize = NULL;
	PIMAGE_BASE_RELOCATION pBaseTable = NULL;
	Offset = (DWORD)pNewPe - pNtHdr->OptionalHeader.ImageBase;//计算需要重定位的值
	if (pNtHdr->OptionalHeader.DataDirectory[5].VirtualAddress == 0)
	{
		return 0;
	}
	pBaseTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewPe + pNtHdr->OptionalHeader.DataDirectory[5].VirtualAddress);
	BaseTableSize = pNtHdr->OptionalHeader.DataDirectory[5].Size;

	while ((NowSize < BaseTableSize) && (pBaseTable->VirtualAddress != 0))
	{
		PWORD pBase = (PWORD)((DWORD)pBaseTable + sizeof(IMAGE_BASE_RELOCATION));
		PDWORD pAageBase = (PDWORD)((DWORD)pNewPe + pBaseTable->VirtualAddress);
		int Count = (pBaseTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < Count; i++)
		{
			if (pBase[i] >= 0x3000)//1修改高16位 2修改低16位
			{
				PDWORD UpdataAddr = (PDWORD)((pBase[i] & 0xfff) + (DWORD)pAageBase);
				*UpdataAddr = Offset + *UpdataAddr;
			}
		}
		NowSize += pBaseTable->SizeOfBlock;
		pBaseTable = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseTable + pBaseTable->SizeOfBlock);
	}

	char* mapadd = ((char*)pNewPe + pNtHdr->OptionalHeader.AddressOfEntryPoint);

	return mapadd;
}



char* RetX64RunExeAdr(char* pExeAddr, HMODULE Kernel32)
{
	// 1. 局部字符串
	CHAR szUser32[] = { 'u','s','e','r','3','2','.','d','l','l','\0' };
	CHAR szKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
	CHAR szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
	CHAR szCMD[] = { 'c','m','d','.','e','x','e','\0' };
	CHAR csVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c' ,'\0' };



	CHAR csVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
	CHAR csGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
	CHAR csCreateThread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d' ,'\0' };
	CHAR csWaitForSingleObject[] = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t','\0' };


	// 2. 获取关键模块基址
	HMODULE hKernel32By64 = 0;
	HMODULE hNtDll = 0;
	DWORD ImageBase = 0;
	HMODULE hUser32 = 0;

	// 3. 获取关键模块基址
	DefineFuncPtr(LoadLibraryExA, (HMODULE)Kernel32);
	hKernel32By64 = My_LoadLibraryExA(szKernel32, 0, 0);
	hNtDll = My_LoadLibraryExA(szntdll, 0, 0);
	hUser32 = My_LoadLibraryExA(szUser32, 0, 0);
	DefineFuncPtr(VirtualAlloc, hKernel32By64);
	DefineFuncPtr(VirtualProtect, hKernel32By64);
	DefineFuncPtr(CreateThread, hKernel32By64);
	DefineFuncPtr(WaitForSingleObject, hKernel32By64);
	DefineFuncPtr(GetProcAddress, hKernel32By64);


	//User32
	DefineFuncPtr(MessageBoxA, hUser32);

	//ntdll
	DefineFuncPtr(memcpy, hNtDll);
	DefineFuncPtr(sprintf, hNtDll);


	DWORD64 SectionCount = 0;
	DWORD64 SectionAlignment = 0;
	DWORD64 FileAlignment = 0;

	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
	//申请新内存
	pNtHdr = (PIMAGE_NT_HEADERS64)((char*)pExeAddr + ((PIMAGE_DOS_HEADER)pExeAddr)->e_lfanew);
	SectionCount = pNtHdr->FileHeader.NumberOfSections;
	SectionAlignment = pNtHdr->OptionalHeader.SectionAlignment;
	FileAlignment = pNtHdr->OptionalHeader.FileAlignment;


	LPVOID pNewPe = My_VirtualAlloc(NULL, pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pNewPe == NULL)
	{
		return 0;
	}

	//拉伸PE
	My_memcpy((void*)pNewPe, (void*)pExeAddr, pNtHdr->OptionalHeader.SizeOfHeaders);


	PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHdr);
	for (int i = 0; i < SectionCount; i++)
	{
		My_memcpy((char*)((DWORD64)pNewPe + pSectionHdr[i].VirtualAddress),
			(char*)((DWORD64)pExeAddr + pSectionHdr[i].PointerToRawData),
			pSectionHdr[i].SizeOfRawData);

	}




	//修复导入表
	PIMAGE_DOS_HEADER pDos64 = (PIMAGE_DOS_HEADER)pNewPe;

	PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)(pDos64->e_lfanew + (char*)pNewPe);

	PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pNewPe + pNt64->OptionalHeader.DataDirectory[1].VirtualAddress);
	//printf("Nt%x---ImportTable=%x---%x\n", pNt64, ImportTable, pNt64->OptionalHeader.DataDirectory[1].VirtualAddress);

	//遍历导入表 以全0结构体结尾
	while (ImportTable->Name != 0)
	{
		//计算出DLL名称通过LoadLibrary
		CHAR* DllName = (CHAR*)(ImportTable->Name + ((char*)pNewPe));
		//加载DLL
		HMODULE hModule = My_LoadLibraryExA(DllName, 0, 0);

		//获取IAT表
		PIMAGE_THUNK_DATA64 Iat = (PIMAGE_THUNK_DATA64)(ImportTable->FirstThunk + ((char*)pNewPe));

		//检测是否有效
		while (Iat->u1.AddressOfData)
		{
			ULONGLONG  FunctionAddr = 0;
			
			
			//最高位为0
			if (!IMAGE_SNAP_BY_ORDINAL(Iat->u1.AddressOfData))
			{
				PIMAGE_IMPORT_BY_NAME Name = (PIMAGE_IMPORT_BY_NAME)(Iat->u1.Function + ((char*)pNewPe));
				FunctionAddr = (ULONGLONG)My_GetProcAddress(hModule, Name->Name);
			}
			else
			{
				//如果没有名字，低16位就是序号
				FunctionAddr = (ULONGLONG)My_GetProcAddress(hModule, (LPCSTR)(Iat->u1.Ordinal & 0xffff));

			}
			Iat->u1.Function = (ULONGLONG)FunctionAddr;
			++Iat;
		}
		ImportTable++;
	}



	//-------------------------------------------------修复重定位表
	DWORD64 Offset = NULL;
	int BaseTableSize = NULL;
	int NowSize = NULL;
	PIMAGE_BASE_RELOCATION pBaseTable = NULL;
	Offset = (DWORD64)pNewPe - pNt64->OptionalHeader.ImageBase;//计算需要重定位的值
	if (pNt64->OptionalHeader.DataDirectory[5].VirtualAddress == 0)
	{
		return 0 ;
	}
	pBaseTable = (PIMAGE_BASE_RELOCATION)((DWORD64)(pNewPe)+pNt64->OptionalHeader.DataDirectory[5].VirtualAddress);
	BaseTableSize = pNt64->OptionalHeader.DataDirectory[5].Size;

	while ((NowSize < BaseTableSize) && (pBaseTable->VirtualAddress != 0))
	{
		PWORD pBase = (PWORD)((DWORD64)pBaseTable + sizeof(IMAGE_BASE_RELOCATION));
		PDWORD64 pAageBase = (PDWORD64)((DWORD64)(pNewPe)+pBaseTable->VirtualAddress);
		int Count = (pBaseTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < Count; i++)
		{
			if (pBase[i] >= 0x3000)//1修改高16位 2修改低16位
			{
				PDWORD64 UpdataAddr = (PDWORD64)((pBase[i] & 0xfff) + (DWORD64)pAageBase);
				*UpdataAddr = Offset + *UpdataAddr;
			}
		}
		NowSize += pBaseTable->SizeOfBlock;
		pBaseTable = (PIMAGE_BASE_RELOCATION)((DWORD64)pBaseTable + pBaseTable->SizeOfBlock);
	}

	char* mapadd = ((char*)pNewPe + pNtHdr->OptionalHeader.AddressOfEntryPoint);

	return mapadd;
}