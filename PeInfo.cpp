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
	//��ȡ�ļ���С
	filesize=GetFileSize(hFile, 0);
	filebuff = new CHAR[filesize];
	//��ȡ�ļ�
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
	//�ǵð��ļ�ָ���ƶ����ļ���ͷ
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
		printf("��PE�ļ�ʧ��,�ļ���������\n");
		return;
	}
	if (pDosHeader->e_magic==IMAGE_DOS_SIGNATURE)
	{
		printf("���ļ�ΪPE�ļ�\n");
	}
}

void CPeInfo::InitPeInfo(char *buff)
{
	pDosHeader = (PIMAGE_DOS_HEADER)buff;
	if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��pe�ļ�\n");
		return;
	}
	pNtheader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + buff);
	if (pNtheader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��pe�ļ�\n");
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
		//�����rvaС�ڵ�һ�����ε�ַ,˵���ڴ�û�����뱻����
		return rva;//ֱ�ӷ��ؾ���
	}
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)
	{
		//foa=rva-����rva+���ε�foa
		if (rva>=pSectionHeader->VirtualAddress&&rva<(pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize))
		{
			//������rva���ڵ������ε������ַ����С�����εĴ�С
			//pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize
			return rva - pSectionHeader->VirtualAddress +pSectionHeader->PointerToRawData ;
			//rve-������εĵ�ַ+���ε��ļ�ƫ��
		}
		pSectionHeader++;
	}
	return rva;
}

void CPeInfo::PrintSection()
{
	//�Ȼ�ȡ����ͷ
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)
	{
		char SectionName[9] = { 0 };
		strcpy(SectionName, (char *)pSectionHeader->Name);
		
		printf("��������:%s  ���ε�ַ:%0X\n", SectionName,pSectionHeader->VirtualAddress);
		pSectionHeader++;
	}
}

char * CPeInfo::FileBufftoImageBuff(char *buff)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	char *imagebuff = new char[pOptionHeader->SizeOfImage];//���ݾ����С�����ڴ�
	ZeroMemory(imagebuff, pOptionHeader->SizeOfImage);//���ڴ��ַ����
	memcpy(imagebuff, buff, pOptionHeader->SizeOfHeaders);//�Ȱ��ļ�ͷ������ȥ
	PIMAGE_SECTION_HEADER psh = pSectionHeader;
	for (int i = 0; i < pFileHeader->NumberOfSections;i++)//��������ͷ����ѭ��
	{
		//��filebuff�������ַ������imagebuff�������ַ
		memcpy(&imagebuff[psh->VirtualAddress], &buff[psh->PointerToRawData], psh->Misc.VirtualSize);
		psh++;
	}

	return imagebuff;
}

char * CPeInfo::ImagebuffToFileBuff(char *imagebuff)
{
	InitPeInfo(imagebuff);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	//�ļ������һ������ļ�ƫ��+�����Ĵ�С,�͵ó�Newbuff��Ҫ�Ĵ�С
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
	//�ȳ�ʼ��pe�ļ�
	InitPeInfo(imagebuff);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	if ((pSectionHeader->SizeOfRawData-pSectionHeader->Misc.VirtualSize)<shellsize)
	{
		printf("���δ�С����\n");
		return FALSE;
	}
	//�Ȼ�ȡ��һ�����κ���Ŀ�����
	DWORD shellbegin = (DWORD)imagebuff + pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress;
	memcpy((void *)shellbegin, shellcode, shellsize);
	//��ȡE8Ҫ�����ĵ�ַ
	//Ŀ���ַ-��ǰ�����ַ-ָ���
	DWORD calladdr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((shellbegin + 0xd) - (DWORD)imagebuff)));
	*(DWORD*)(shellbegin + 9) = calladdr;
	//��ȡE9Ҫ�����ĵ�ַ
	//Ŀ���ַ-��ǰ�����ַ-ָ���
	//����ַ+entrypoint=Ŀ���ַ
	//��ǰ�����ַ=����ַ+(shellbegin-imagebuff)-E9����һ��ָ���ַ+shellsize

	DWORD jmpaddr = (pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase) -
		/*((shellbegin + shellsize) - (DWORD)imagebuff+pOptionHeader->ImageBase);*/
		(pOptionHeader->ImageBase + (shellbegin - (DWORD)imagebuff) + shellsize);
	*(DWORD *)(shellbegin + 0xe) = jmpaddr;
	//�޸�entrypoint
	DWORD entrypoint = shellbegin - (DWORD)imagebuff;
	pOptionHeader->AddressOfEntryPoint = entrypoint;
	return TRUE;
}

void CPeInfo::SaveFile(char *filebuff,char *filename)
{
	FILE *newfile = fopen(filename, "wb+");
	fwrite(filebuff, 1, filesize, newfile);
	fclose(newfile);

	printf("����ɹ�\n");
	
}

void CPeInfo::PrintExprotTable()
{
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[0];
	//�����
	PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(RvatoFoa(pdd->VirtualAddress)+(DWORD)filebuff);
	//��ӡ�������Ϣ
	printf("�ļ���Ϊ:%s\n", RvatoFoa(ed->Name)+filebuff);
	printf("base:%d\n", ed->Base);
	printf("NumberOfFunctions:%d\n", ed->NumberOfFunctions);
	printf("NumberOfNames:%d\n",ed->NumberOfNames);
	printf("AddressOfFunctions:%0x\n", ed->AddressOfFunctions);
	printf("AddressOfNames:%0x\n", ed->AddressOfNames);
	printf("AddressOfNameOrdinals:%0x\n", ed->AddressOfNameOrdinals);
	printf("��������������Ϊ:********************************\n");
	DWORD *number = (DWORD*)(RvatoFoa(ed->AddressOfFunctions)+filebuff);
	for (int i = 0; i < ed->NumberOfFunctions; i++)
	{

		printf("��%d������RVAΪ:%0x\n", i, *number);
		number++;
	}

	printf("�����Ƶ�������Ϊ:********************************\n");
	DWORD *name = (DWORD *)(RvatoFoa(ed->AddressOfNames) + filebuff);
	for (int j = 0; j < ed->NumberOfNames;j++)
	{
		printf("��%d����������Ϊ:%s\n", j, *name+filebuff);
		name++;
	}

	printf("����ŵ�������Ϊ:********************************\n");
	WORD *ord = (WORD *)(RvatoFoa(ed->AddressOfNameOrdinals) + filebuff);
	for (int k = 0; k < ed->NumberOfNames; k++)
	{
		printf("��%d���������Ϊ:%d\n", k, *ord+ed->Base);
		ord++;
	}

}

DWORD CPeInfo::GetFuncAddrByName(char *funcname)
{
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[0];
	//��ȡ������
	PIMAGE_EXPORT_DIRECTORY pet = (PIMAGE_EXPORT_DIRECTORY)(RvatoFoa(pdd->VirtualAddress) + filebuff);
	//��ȡ��������
	DWORD  *funcnametable = (DWORD *)(RvatoFoa(pet->AddressOfNames)+(DWORD)filebuff);
	WORD *ordnametable = (WORD*)(RvatoFoa(pet->AddressOfNameOrdinals) + filebuff);
	DWORD *addrtable = (DWORD*)(RvatoFoa(pet->AddressOfFunctions) + filebuff);
	for (int i = 0; i < pet->NumberOfNames;i++)
	{
		//�ȽϺ�������
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
	//��ȡ�ض�λ��
	PIMAGE_DATA_DIRECTORY pdd = &pOptionHeader->DataDirectory[5];
	PIMAGE_BASE_RELOCATION prelocation = (PIMAGE_BASE_RELOCATION)(RvatoFoa(pdd->VirtualAddress)+filebuff);
	
	while (1)
	{
		if (prelocation->VirtualAddress == 0)
		{
			break;
		}
		//������һ���ض�λ��
		printf("�����ַΪ:%x\n", prelocation->VirtualAddress);
		DWORD relocation = (prelocation->SizeOfBlock - 8) / 2;
		WORD *readdr = (WORD*)prelocation + 4;
		for (int i = 0; i < relocation; i++)
		{

			if ((*readdr & 0x3000) == 0x3000)
			{
				DWORD *rva = (DWORD *)((*readdr & 0x0fff) + prelocation->VirtualAddress+filebuff);
				printf("ƫ��Ϊ:%x\n", *rva-imagebase+�¼��صĵ�ַ);
			}
			readdr++;
		}
		prelocation = (PIMAGE_BASE_RELOCATION)((DWORD)prelocation + prelocation->SizeOfBlock);
	}
	
}
