#pragma once
#include <windows.h>
#include <iostream>


class CPeInfo
{
public:
	CPeInfo();
	~CPeInfo();
private:
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtheader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionHeader;
	//PIMAGE_SECTION_HEADER pSectionHeader;
	PIMAGE_DATA_DIRECTORY pDatadir;
public:
	CHAR *filebuff;
	DWORD filesize;

public:
	BOOL CreatePe(char *filename);
	void GetDosHeader();
	void InitPeInfo(char *buff);
	void GetDataDir();
	DWORD RvatoFoa(DWORD rva);
	void PrintSection();
	char* FileBufftoImageBuff(char *buff);
	char *ImagebuffToFileBuff(char *imagebuff);
	BOOL AddShellCodeToSection(char *imagebuff,char *shellcode,DWORD shellsize);
	void SaveFile(char *filebuff,char * filename);
	void PrintExprotTable();//打印导出表
	DWORD GetFuncAddrByName(char *funcname);
	void Printrelocation();//打印重定位表

};

