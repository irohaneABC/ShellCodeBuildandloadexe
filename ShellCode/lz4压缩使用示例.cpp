//#include <windows.h>
//#include <iostream>
//using namespace std;
//#include "lz4.h"
//
//
//char* get_file_data(const char* path, int * size);
//bool save_file(const char* path, void* data, int size);
//void free_file_data(const char* file_data);
//bool save_file(const char* path, void* data, int size);
//bool save_compress_file(const char* path, void* data, int size, int src_file_size);
//
//// 压缩
//void compress(const char* path)
//{
//	int file_size = 0;
//	char* file_data = get_file_data(path, &file_size);
//	if (file_data == nullptr) {
//		return;
//	}
//
//	//1. 获取预估的压缩后的字节数:
//	int compress_size = LZ4_compressBound(file_size);
//	// 2. 申请内存空间, 用于保存压缩后的数据
//	char* pBuff = new char[compress_size];
//	// 3. 开始压缩文件数据(函数返回压缩后的大小)
//	int dest_size =  LZ4_compress(
//		file_data,/*压缩前的数据*/ 
//		pBuff, /*压缩后的数据*/
//		file_size/*文件原始大小*/);
//
//	printf("压缩前:%d , 压缩后:%d , 压缩比:%.2lf%%\n", file_size, dest_size, dest_size*1.0 / file_size * 100.0);
//
//	
//	char save_path[MAX_PATH];
//	cout << "请输入要保存的位置:";
//	cin.getline(save_path, sizeof(save_path));
//
//	//4. 将压缩后的数据写入到文件中保存:
//	//   保存时, 先保存4个字节的文件原始字节数
//	//   再保存压缩后的数据
//	save_compress_file(save_path, pBuff, dest_size, file_size);
//
//	// 释放文件数据
//	free_file_data(file_data);
//	// 释放保存压缩数据的堆空间
//	delete[] pBuff;
//}
//
//// 解压
//void uncompress(const char* path)
//{
//	int file_size = 0;
//	char* file_data = get_file_data(path, &file_size);
//	if (file_data == nullptr) {
//		return;
//	}
//
//	// 在保存压缩文件时, 先保存了4字节的原始文件大小, 然后再保存压缩后的文件数据
//	//1. 先将前4字节的文件原始大小获取出来
//	int src_file_size = *(int*)file_data;
//	//2. 定位到压缩后的文件数据
//	file_data += 4;
//
//	//3. 申请空间
//	char* pBuff = new char[src_file_size];
//
//	//4. 解压缩
//	LZ4_uncompress_unknownOutputSize(
//		file_data,/*压缩后的数据*/ 
//		pBuff, /*解压出来的数据*/
//		file_size,/*压缩后的大小*/ 
//		src_file_size/*压缩前的大小*/);
//	
//
//	printf("解压前:%d , 解压后:%d\n", file_size,src_file_size);
//
//	save_file(path, pBuff, src_file_size);
//}
//
//
//int main()
//{
//	char path[MAX_PATH];
//	cout << "请输入文件路径:";
//	cin.getline(path, sizeof(path));
//
//	printf("1. 压缩\n");
//	printf("2. 解压\n");
//
//	int menu = 0;
//	cin >> menu;
//	
//	if ( menu == 1 ) {
//		compress(path);
//	}
//	else {
//		uncompress(path);
//	}
//	return 0;
//}
//
//char* get_file_data(const char* path, int * size)
//{
//	FILE* f = NULL;
//	fopen_s(&f, path, "rb");
//	if (f == nullptr) {
//		return nullptr;
//	}
//	fseek(f, 0, SEEK_END);
//	int file_size = ftell(f);
//	char* file_data = new char[file_size];
//	rewind(f);
//
//	fread(file_data, 1, file_size, f);
//	fclose(f);
//	if (size) {
//		*size = file_size;
//	}
//	return file_data;
//}
//
//
//void free_file_data(const char* file_data) {
//	delete[] file_data;
//}
//
//
//bool save_file(const char* path, void* data, int size) {
//	FILE* f = NULL;
//	fopen_s(&f, path, "wb");
//	if (f == nullptr) {
//		return false;
//	}
//	fwrite((char*)data, 1, size, f);
//	fclose(f);
//	return true;
//}
//
//
//bool save_compress_file(const char* path, void* data, int size, int src_file_size) {
//	FILE* f = NULL;
//	fopen_s(&f, path, "wb");
//	if (f == nullptr) {
//		return false;
//	}
//	// 1. 写入文件的原始字节数
//	fwrite(&src_file_size, 1, sizeof(src_file_size), f);
//	// 2. 写入压缩后的文件内容
//	fwrite((char*)data, 1, size, f);
//	fclose(f);
//	return true;
//}
//
