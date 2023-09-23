// ShellCodeBuild.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "ShellLoader.h"
#include "C_ToShell.h"

//压缩的信息返回出去
typedef struct COMPRESSINFO
{
	//预估压缩后的字节数  【压缩后的字节数】
	DWORD Retcompress_size;
	//文件原来的大小
	DWORD SrcFile_size;
	//返回的指针
	char* pRetNewBuffer;

}CompressInfo, * pCompressInfo;


int main()
{
	TO_SHELL("ServerX64.exe", "1.bin");
    
    std::cout << "Hello World!\n";
}
