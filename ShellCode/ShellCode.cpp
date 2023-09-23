#include <winsock2.h>   
#include <windows.h>
#include <iostream>

#include "TOOL.h"




using Pmemcpy = void* (WINAPI*)(
	void* dest,
	const void* src,
	size_t count
	);



typedef const void* (*MEMCPY)(
	void* dest,
	const void* src,
	size_t count
	);


extern "C" DWORD Debug_PEBBegingDebug();		//PEB+2 debug

#ifdef _WIN64

extern "C" DWORD64 Mymemcpy64(DWORD64 Des, DWORD64 Src, DWORD64 MemSize);
extern "C" DWORD64 GetImageBase64();
extern "C" DWORD64 GetModuleBase64();
extern "C" DWORD64 MySetMemZero64();
extern "C" DWORD64 GetPc();
extern "C" DWORD64 GetPebLdr64();
extern "C" DWORD64 GetPc64();


#else
extern "C" DWORD Memcpy32(DWORD Des, DWORD Src, DWORD MemSize);
extern "C" DWORD GetImageBase32();
extern "C" DWORD GetKernel32Base32();
extern "C" DWORD GetLdrModuleBase32();
extern "C" DWORD SetMemZero32();
extern "C" DWORD GetPc32();

#endif // _WIN32

extern "C"







typedef struct _SHAREDATA
{
	DWORD FirstExe = 0;			//ShellCode引导
	DWORD OldExeSize = 0;		//未压缩前的大小
	DWORD NowExeSize = 0;		//压缩后的大小
	DWORD DllSize = 0;			//当前把DLL中的代码导出后的大小 其实可以直接算出偏移，确保正确直接使用大小


	struct {
		DWORD Start;
		DWORD Size;
		BYTE Key;
	} Xor;


} SHAREDATA, * PSHAREDATA;


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}UNICODE_STRING, * PUNICODE_STRING;


// ---------------------------注意生成 模式 自选shellcode 模式， 从函数开始复制到main 差不多就好了
// ---------------------------采用宏取获取 对应加密的hash 如果想使用就得生成hash 然后放入 TOOL 中注意格式，使用根据示例格式即可





void EntryPoint()
{
	
	DWORD64 TextEip;
	//GetPC从必须要获取最开始的   -1E  确保必须是最前面
#ifdef _WIN64
	TextEip = GetPc64();
	
#else
	TextEip = GetPc32()
#endif // _WIN32

	
	;

	//共享字段
	CHAR OldExeSize[] = { '2','2','2','2' };					//未压缩前的大小
	CHAR NowExeSize[] = { '3','3','3','3' };					//压缩后的大小
	CHAR ShellRva[] =	{ '4','4','4','4' };					//PE压缩后的文件放入shellcode之后


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
	CHAR cscllmsyk[] = { 'c','l','l','m','s','y','k','\0' };

	// 2. 获取关键模块基址
	HMODULE hKernel32By64 = 0;
	HMODULE hNtDll = 0;
	DWORD ImageBase = 0;
	HMODULE hUser32 = 0;
	HMODULE hKernel32;


#ifdef _WIN64
	// 64 应该取消注释
	ImageBase = GetImageBase64();
	DWORD64 ModuleLdr = GetModuleBase64();
	UNICODE_STRING* FullName = NULL;
	LIST_ENTRY* pNode = (LIST_ENTRY*)ModuleLdr;

#else
	ImageBase = GetImageBase32();
	hKernel32 = (HMODULE)GetKernel32Base32();
#endif // _WIN32


	



#ifdef _WIN64


	//获取64模块  应取消注释
	while (true)
	{
		FullName = (UNICODE_STRING*)((BYTE*)pNode + 0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
		if (*(FullName->Buffer + 12) == '\0')
		{
			hKernel32 = (HMODULE)(*((ULONG64*)((BYTE*)pNode + 0x10)));//DllBase
			break;
		}
		pNode = pNode->Flink;
	}
#else
	

#endif // _WIN32


	

	// 3. 获取关键模块基址
	DefineFuncPtr(LoadLibraryExA, (HMODULE)hKernel32);
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



	DWORD dwShellRva = 0, dwNowExeSize = 0, dwOldExeSize = 0;
	My_memcpy( &dwShellRva, ShellRva, 4);
	My_memcpy( &dwNowExeSize, NowExeSize, 4);	//压缩后大小
	My_memcpy( &dwOldExeSize, OldExeSize, 4);	//压缩前大小
	

	char* pExeAddr = (char*)My_VirtualAlloc(NULL, dwOldExeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//My_MessageBoxA(NULL, 0, 0, 0);
	char* wer = (char*)(TextEip + dwShellRva);
	int endOnInputSize = 1;
	int noPrefix = 0;
	int full = 0;
	//My_MessageBoxA(NULL, 0, 0, 0);
	//解压
	LZ4_decompress_generic(wer, pExeAddr, dwNowExeSize, dwOldExeSize, endOnInputSize, noPrefix, full, 0);


	//My_MessageBoxA(NULL, 0, 0, 0);
	
	char* RetAdr = NULL;


#ifdef _WIN64
	RetAdr = RetX64RunExeAdr(pExeAddr, hKernel32);
#else
	RetAdr = RetX32RunExeAdr(pExeAddr, hKernel32);
#endif

	
	HANDLE h = My_CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(RetAdr), 0, 0, 0);
	DWORD d = My_WaitForSingleObject(h, INFINITE);
}


int main()
{
	
	MessageBox(NULL, NULL, NULL, NULL);
	EntryPoint();
	MessageBox(NULL, NULL, NULL, NULL);
	return 0;
}
;


