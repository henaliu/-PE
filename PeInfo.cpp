#define _CRT_SECURE_NO_WARNINGS
#include "PeInfo.h"

#define MESSAGEBOXADDR 0X75b7ed60
CPeInfo::CPeInfo()
{
	pDosHeader=NULL;
	pNtheader = NULL;
	pFileHeader = NULL;
	pOptionHeader = NULL;
	pDatadir = NULL;
	filebuff = NULL;
	filesize = 0;
}

CPeInfo::~CPeInfo()
{
	if (filebuff)
	{
		delete[] filebuff;
	}
}

BOOL CPeInfo::CreatePe(char *filename)
{
	/*HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile=CreateFileA(filename, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	//获取文件大小
	filesize=GetFileSize(hFile, 0);
	filebuff = new CHAR[filesize];
	//读取文件
	DWORD readsize;
	BOOL result;
	result=ReadFile(hFile, filebuff, filesize, &readsize, 0);
	if (result==0)
	{
		return FALSE;
	}
	return TRUE;
	*/
	FILE *file = fopen(filename, "rb");
	if (file==NULL)
	{
		return FALSE;
	}
	fseek(file, 0, SEEK_END);
	filesize = ftell(file);
	filebuff = (CHAR *)malloc(sizeof(char)*filesize);
	ZeroMemory(filebuff, filesize);
	//记得把文件指针移动到文件开头
	fseek(file, 0, SEEK_SET);
	fread(filebuff, 1, filesize, file);
	fclose(file);
	InitPeInfo(filebuff);
	return TRUE;

}

void CPeInfo::GetDosHeader()
{
	pDosHeader = (PIMAGE_DOS_HEADER)filebuff;
	if (pDosHeader == NULL)
	{
		printf("打开PE文件失败,文件或许不存在\n");
		return;
	}
	if (pDosHeader->e_magic==IMAGE_DOS_SIGNATURE)
	{
		printf("此文件为PE文件\n");
	}
}

void CPeInfo::InitPeInfo(char *buff)
{
	pDosHeader = (PIMAGE_DOS_HEADER)buff;
	if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的pe文件\n");
		return;
	}
	pNtheader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + buff);
	if (pNtheader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的pe文件\n");
		return;
	}
	pFileHeader = (&pNtheader->FileHeader);
	pOptionHeader = &pNtheader->OptionalHeader;
}

void CPeInfo::GetDataDir()
{
	pDatadir = &pOptionHeader->DataDirectory[0];
	pDatadir->VirtualAddress;
}


DWORD CPeInfo::RvatoFoa(DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	if (rva==NULL||rva<pSectionHeader->VirtualAddress)
	{
		return 0;
	}
	
	if (rva<pSectionHeader->VirtualAddress)
	{
		//如果此rva小于第一个区段地址,说明内存没有载入被拉长
		return rva;//直接返回就行
	}
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)
	{
		//foa=rva-区段rva+区段的foa
		if (rva>=pSectionHeader->VirtualAddress&&rva<(pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize))
		{
			//如果这个rva大于等于区段的虚拟地址并且小于区段的大小
			//pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize
			return rva - pSectionHeader->VirtualAddress +pSectionHeader->PointerToRawData ;
			//rve-这个区段的地址+区段的文件偏移
		}
		pSectionHeader++;
	}
	return rva;
}

void CPeInfo::PrintSection()
{
	//先获取区段头
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)
	{
		char SectionName[9] = { 0 };
		strcpy(SectionName, (char *)pSectionHeader->Name);
		
		printf("区段名称:%s  区段地址:%0X\n", SectionName,pSectionHeader->VirtualAddress);
		pSectionHeader++;
	}
}

char * CPeInfo::FileBufftoImageBuff(char *buff)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	char *imagebuff = new char[pOptionHeader->SizeOfImage];//根据镜像大小分配内存
	ZeroMemory(imagebuff, pOptionHeader->SizeOfImage);//把内存地址清零
	memcpy(imagebuff, buff, pOptionHeader->SizeOfHeaders);//先把文件头拷贝进去
	PIMAGE_SECTION_HEADER psh = pSectionHeader;
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)//根据区段头数量循环
	{
		//从filebuff的物理地址拷贝到imagebuff的虚拟地址
		memcpy(&imagebuff[psh->VirtualAddress], &buff[psh->PointerToRawData], psh->Misc.VirtualSize);
		psh++;
	}

	return imagebuff;
}

char * CPeInfo::ImagebuffToFileBuff(char *imagebuff)
{
	InitPeInfo(imagebuff);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	//文件中最后一个结的文件偏移+对齐后的大小,就得出Newbuff需要的大小
	DWORD filesize = pSectionHeader[pFileHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pFileHeader->NumberOfSections - 1].SizeOfRawData;
	char *Newbuff = new char[filesize];
	ZeroMemory(Newbuff, filesize);
	memcpy(Newbuff, imagebuff, pOptionHeader->SizeOfHeaders);
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)
	{
		memcpy(&Newbuff[pSectionHeader->PointerToRawData], &imagebuff[pSectionHeader->VirtualAddress], pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	return Newbuff;
}

BOOL CPeInfo::AddShellCodeToSection(char *imagebuff, char *shellcode, DWORD shellsize)
{
	//先初始化pe文件
	InitPeInfo(imagebuff);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	if ((pSectionHeader->SizeOfRawData-pSectionHeader->Misc.VirtualSize)<shellsize)
	{
		printf("区段大小不够\n");
		return FALSE;
	}
	//先获取第一个区段后面的空闲区
	DWORD shellbegin = (DWORD)imagebuff + pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress;
	memcpy((void *)shellbegin, shellcode, shellsize);
	//获取E8要修正的地址
	//目标地址-当前代码地址-指令长度
	DWORD calladdr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((shellbegin + 0xd) - (DWORD)imagebuff)));
	*(DWORD*)(shellbegin + 9) = calladdr;
	//获取E9要修正的地址
	//目标地址-当前代码地址-指令长度
	//基地址+entrypoint=目标地址
	//当前代码地址=基地址+(shellbegin-imagebuff)-E9的下一条指令地址+shellsize

	DWORD jmpaddr = (pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase) -
		/*((shellbegin + shellsize) - (DWORD)imagebuff+pOptionHeader->ImageBase);*/
		(pOptionHeader->ImageBase + (shellbegin - (DWORD)imagebuff) + shellsize);
	*(DWORD *)(shellbegin + 0xe) = jmpaddr;
	//修改entrypoint
	DWORD entrypoint = shellbegin - (DWORD)imagebuff;
	pOptionHeader->AddressOfEntryPoint = entrypoint;
	return TRUE;
}

void CPeInfo::SaveFile(char *filebuff,char *filename)
{
	FILE *newfile = fopen(filename, "wb+");
	fwrite(filebuff, 1, filesize, newfile);
	fclose(newfile);

	printf("保存成功\n");
	
}

void CPeInfo::PrintExprotTable()
{
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[0];
	//导入表
	PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(RvatoFoa(pdd->VirtualAddress)+(DWORD)filebuff);
	//打印导入表信息
	printf("文件名为:%s\n", RvatoFoa(ed->Name)+filebuff);
	printf("base:%d\n", ed->Base);
	printf("NumberOfFunctions:%d\n", ed->NumberOfFunctions);
	printf("NumberOfNames:%d\n",ed->NumberOfNames);
	printf("AddressOfFunctions:%0x\n", ed->AddressOfFunctions);
	printf("AddressOfNames:%0x\n", ed->AddressOfNames);
	printf("AddressOfNameOrdinals:%0x\n", ed->AddressOfNameOrdinals);
	printf("以数量导出函数为:********************************\n");
	DWORD *number = (DWORD*)(RvatoFoa(ed->AddressOfFunctions)+filebuff);
	for (int i = 0; i < ed->NumberOfFunctions; i++)
	{

		printf("第%d个函数RVA为:%0x\n", i, *number);
		number++;
	}

	printf("以名称导出函数为:********************************\n");
	DWORD *name = (DWORD *)(RvatoFoa(ed->AddressOfNames) + filebuff);
	for (int j = 0; j < ed->NumberOfNames;j++)
	{
		printf("第%d个函数名称为:%s\n", j, *name+filebuff);
		name++;
	}

	printf("以序号导出函数为:********************************\n");
	WORD *ord = (WORD *)(RvatoFoa(ed->AddressOfNameOrdinals) + filebuff);
	for (int k = 0; k < ed->NumberOfNames; k++)
	{
		printf("第%d个函数序号为:%d\n", k, *ord+ed->Base);
		ord++;
	}

}

DWORD CPeInfo::GetFuncAddrByName(char *funcname)
{
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[0];
	//获取导出表
	PIMAGE_EXPORT_DIRECTORY pet = (PIMAGE_EXPORT_DIRECTORY)(RvatoFoa(pdd->VirtualAddress) + filebuff);
	//获取函数名表
	DWORD  *funcnametable = (DWORD *)(RvatoFoa(pet->AddressOfNames)+(DWORD)filebuff);
	WORD *ordnametable = (WORD*)(RvatoFoa(pet->AddressOfNameOrdinals) + filebuff);
	DWORD *addrtable = (DWORD*)(RvatoFoa(pet->AddressOfFunctions) + filebuff);
	for (int i = 0; i < pet->NumberOfNames;i++)
	{
		//比较函数名称
		if (strcmp(funcname, (char*)(*funcnametable)+(DWORD)filebuff)==0)
		{
			for (int j = 0; j < pet->NumberOfNames;j++)
			{
				if (ordnametable[j]==i)
				{
					return RvatoFoa(addrtable[j]);
				}
			}
			
			//return *funcnametable;
		}
		funcnametable++;
	}
}

void CPeInfo::Printrelocation()
{
	//获取重定位表
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[5];
	PIMAGE_BASE_RELOCATION prelocation = (PIMAGE_BASE_RELOCATION)(RvatoFoa(pdd->VirtualAddress)+filebuff);
	
	while (1)
	{
		if (prelocation->VirtualAddress == 0)
		{
			break;
		}
		//遍历第一个重定位表
		printf("虚拟地址为:%x\n", prelocation->VirtualAddress);
		DWORD relocation = (prelocation->SizeOfBlock - 8) / 2;
		WORD *readdr = (WORD*)prelocation + 4;
		for (int i = 0; i < relocation; i++)
		{

			if ((*readdr & 0x3000) == 0x3000)
			{
				DWORD *rva = (DWORD *)((*readdr & 0x0fff) + prelocation->VirtualAddress+filebuff);
				printf("偏移为:%x\n", *rva-imagebase+新加载的地址);
			}
			readdr++;
		}
		prelocation = (PIMAGE_BASE_RELOCATION)((DWORD)prelocation + prelocation->SizeOfBlock);
	}
	
}
