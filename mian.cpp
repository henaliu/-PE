#include "PeInfo.h"
char shellcode[] = {
	0x6A, 00, 0x6A, 00, 0X6A, 00, 0X6A, 00,
	0XE8, 00, 00, 00, 00,
	0XE9, 00, 00, 00, 00 };
#define SHELLSIZE 18
#define FILENAME "dlltest.dll"//LoadDll.dll
#define NEWFILENAME "1.exe"
void main()
{
	CPeInfo pe;

	BOOL isLoad = pe.CreatePe(FILENAME);
	if (isLoad)
	{
		pe.Printrelocation();
		system("pause");
		return;
	}
	MessageBox(0,0,0,0);
	system("pause");
}