#include <Windows.h>
class PE_TOOL
{
public:
	static PIMAGE_DOS_HEADER GetPeDOSHeader(char* pvoid);

	static PIMAGE_NT_HEADERS GetPeNtHeader(char* pvoid);

	static PIMAGE_FILE_HEADER GetPeFileHeader(char* pvoid);

	static PIMAGE_OPTIONAL_HEADER GetPeOptionHeader(char* pvoid);

	static BOOL InitDosInfo(char* pvoid);		//初始化Dos头信息
	static BOOL InitNtInfo(char* pvoid);		//初始化NT头信息
	static BOOL InitFileHeader(char* pvoid);	//初始化文件头信息
	static BOOL InitOptionHeader(char* pvoid);	//初始化扩展头信息


	static LPVOID AddSection(char** pvoid, DWORD SectionSize, char* SectionName);						//添加区段 返回地址
	static DWORD SetSectionData(char** pvoid, char* SectionName, char* DataBuffer, DWORD DataSize);		//像某区段覆盖数据
	static DWORD SetOpeAtTheSection(char** pvoid, char* SectionName);
	static DWORD GetPeMemSize(char* pvoid);
	static DWORD SnapToMemAddr(DWORD MemSize, DWORD Alignment_granularity);	//需要对齐的地址，对其的大小
	static PIMAGE_SECTION_HEADER GetSeatchSectionByName(char* pvoid, const char* SectionName);    //PIMAGE_SECTION_HEADER 类型

	static DWORD RvaToFoa(char* lpImage, DWORD dwRva);





};

