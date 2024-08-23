/**
* Copyright (C) 2022 Elisha Riedlinger
*
* This software is  provided 'as-is', without any express  or implied  warranty. In no event will the
* authors be held liable for any damages arising from the use of this software.
* Permission  is granted  to anyone  to use  this software  for  any  purpose,  including  commercial
* applications, and to alter it and redistribute it freely, subject to the following restrictions:
*
*   1. The origin of this software must not be misrepresented; you must not claim that you  wrote the
*      original  software. If you use this  software  in a product, an  acknowledgment in the product
*      documentation would be appreciated but is not required.
*   2. Altered source versions must  be plainly  marked as such, and  must not be  misrepresented  as
*      being the original software.
*   3. This notice may not be removed or altered from any source distribution.
*
* Code taken from DDrawCompat for logging
* https://github.com/narzoul/DDrawCompat/
*
* Code in GetOSVersion and GetVersionReg functions taken from source code found in DirectSoundControl
* https://github.com/nRaecheR/DirectSoundControl
*
* Code in GetVersionFile function taken from source code found on stackoverflow.com
* https://stackoverflow.com/questions/940707/how-do-i-programmatically-get-the-version-of-a-dll-or-exe-file
*
* Code in LogComputerManufacturer function taken from source code found on rohitab.com
* http://www.rohitab.com/discuss/topic/35915-win32-api-to-get-system-information/
*
* Code in GetPPID taken from mattn GitHub project
* https://gist.github.com/mattn/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <VersionHelpers.h>
#include <tlhelp32.h>
#include "Logging.h"

// Function pointers for GetProcessImageFileNameA and GetProcessImageFileNameW
typedef DWORD(WINAPI* GetProcessImageFileNameA_t)(HANDLE, LPSTR, DWORD);
typedef DWORD(WINAPI* GetProcessImageFileNameW_t)(HANDLE, LPWSTR, DWORD);

static GetProcessImageFileNameA_t realGetProcessImageFileNameA = nullptr;
static GetProcessImageFileNameW_t realGetProcessImageFileNameW = nullptr;

// Initialization to load the real GetProcessImageFileName functions
void InitializeGetProcessImageFileName()
{
	// Try to load from kernel32.dll first
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32)
	{
		// Check for K32-prefixed functions first in kernel32.dll
		realGetProcessImageFileNameA = (GetProcessImageFileNameA_t)GetProcAddress(hKernel32, "K32GetProcessImageFileNameA");
		realGetProcessImageFileNameW = (GetProcessImageFileNameW_t)GetProcAddress(hKernel32, "K32GetProcessImageFileNameW");

		// If K32-prefixed versions are not found, try the original names
		if (!realGetProcessImageFileNameA)
		{
			realGetProcessImageFileNameA = (GetProcessImageFileNameA_t)GetProcAddress(hKernel32, "GetProcessImageFileNameA");
		}
		if (!realGetProcessImageFileNameW)
		{
			realGetProcessImageFileNameW = (GetProcessImageFileNameW_t)GetProcAddress(hKernel32, "GetProcessImageFileNameW");
		}
	}

	// If the function wasn't found in kernel32.dll, fall back to psapi.dll
	if (!realGetProcessImageFileNameA || !realGetProcessImageFileNameW)
	{
		HMODULE hPsapi = LoadLibraryW(L"psapi.dll");
		if (hPsapi)
		{
			// Check for K32-prefixed functions first in psapi.dll (for completeness, although unlikely)
			if (!realGetProcessImageFileNameA)
			{
				realGetProcessImageFileNameA = (GetProcessImageFileNameA_t)GetProcAddress(hPsapi, "K32GetProcessImageFileNameA");
			}
			if (!realGetProcessImageFileNameW)
			{
				realGetProcessImageFileNameW = (GetProcessImageFileNameW_t)GetProcAddress(hPsapi, "K32GetProcessImageFileNameW");
			}

			// If K32-prefixed versions are not found, try the original names in psapi.dll
			if (!realGetProcessImageFileNameA)
			{
				realGetProcessImageFileNameA = (GetProcessImageFileNameA_t)GetProcAddress(hPsapi, "GetProcessImageFileNameA");
			}
			if (!realGetProcessImageFileNameW)
			{
				realGetProcessImageFileNameW = (GetProcessImageFileNameW_t)GetProcAddress(hPsapi, "GetProcessImageFileNameW");
			}
		}
	}
}

// The replacement functions
DWORD NewGetProcessImageFileName(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize)
{
	if (!realGetProcessImageFileNameA)
	{
		InitializeGetProcessImageFileName();
	}
	if (realGetProcessImageFileNameA)
	{
		return realGetProcessImageFileNameA(hProcess, lpImageFileName, nSize);
	}
	SetLastError(ERROR_PROC_NOT_FOUND);
	return 0;
}

DWORD NewGetProcessImageFileName(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize)
{
	if (!realGetProcessImageFileNameW)
	{
		InitializeGetProcessImageFileName();
	}
	if (realGetProcessImageFileNameW)
	{
		return realGetProcessImageFileNameW(hProcess, lpImageFileName, nSize);
	}
	SetLastError(ERROR_PROC_NOT_FOUND);
	return 0;
}

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

namespace Logging
{
	bool EnableLogging = true;

	void GetOsVersion(OSVERSIONINFOA*);
	void GetVersionReg(OSVERSIONINFO *);
	void GetVersionFile(OSVERSIONINFO *);
	void GetProductName(char *Name, DWORD Size);
	DWORD GetPPID();
	bool CheckProcessNameFromPID(DWORD pid, char *name);
	bool CheckEachParentFolder(char *file, char *path);
	void LogGOGGameType();
	void LogSteamGameType();
}

namespace
{
	template <typename DevMode>
	std::ostream& streamDevMode(std::ostream& os, const DevMode& dm)
	{
		return Logging::LogStruct(os)
			<< dm.dmPelsWidth
			<< dm.dmPelsHeight
			<< dm.dmBitsPerPel
			<< dm.dmDisplayFrequency
			<< dm.dmDisplayFlags;
	}
}

std::ostream& operator<<(std::ostream& os, const char* str)
{
	if (!str)
	{
		return os << "null";
	}

	if (!Logging::Log::isPointerDereferencingAllowed())
	{
		return os << static_cast<const void*>(str);
	}

	return os.write(str, strlen(str));
}

std::ostream& operator<<(std::ostream& os, const unsigned char* data)
{
	return os << static_cast<const void*>(data);
}

std::ostream& operator<<(std::ostream& os, const wchar_t* wstr)
{
	if (!wstr)
	{
		return os << "null";
	}

	if (!Logging::Log::isPointerDereferencingAllowed())
	{
		return os << static_cast<const void*>(wstr);
	}

	return os << static_cast<std::wstring>(std::wstring(wstr));
}

std::ostream& operator<<(std::ostream& os, std::nullptr_t)
{
	return os << "null";
}

std::ostream& operator<<(std::ostream& os, std::string str)
{
	return os << static_cast<const char*>(str.c_str());
}

std::ostream& operator<<(std::ostream& os, std::wstring wstr)
{
	size_t size = wstr.size() + 1;
	std::string str;
	str.resize(size, '\0');
	wcstombs_s(nullptr, &str[0], size, wstr.c_str(), _TRUNCATE);
	return os << str;
}

namespace Logging
{
	DWORD Log::s_outParamDepth = 0;
	bool Log::s_isLeaveLog = false;
}

void Logging::LogFormat(char * fmt, ...)
{
	if (!EnableLogging)
	{
		return;
	}

	// Format arg list
	va_list ap;
	va_start(ap, fmt);
	auto size = vsnprintf(nullptr, 0, fmt, ap);
	std::string output(size + 1, '\0');
	vsprintf_s(&output[0], size + 1, fmt, ap);
	va_end(ap);

	// Log formated text
	Log() << output.c_str();
}

void Logging::LogFormat(wchar_t * fmt, ...)
{
	if (!EnableLogging)
	{
		return;
	}

	// Format arg list
	va_list ap;
	va_start(ap, fmt);
#pragma warning(suppress: 4996)
	auto size = _vsnwprintf(nullptr, 0, fmt, ap);
	std::wstring output(size + 1, '\0');
	vswprintf_s(&output[0], size + 1, fmt, ap);
	va_end(ap);

	// Log formated text
	Log() << output.c_str();
}

// Logs the process name and PID
void Logging::LogProcessNameAndPID()
{
	if (!EnableLogging)
	{
		return;
	}

	// Get process name
	wchar_t exepath[MAX_PATH] = { 0 };
	GetModuleFileNameW(nullptr, exepath, MAX_PATH);

	// Remove path and add process name
	wchar_t *pdest = wcsrchr(exepath, '\\');

	// Log process name and ID
	Log() << (++pdest) << " (PID:" << GetCurrentProcessId() << ")";
}

// Get Windows Operating System version number from RtlGetVersion
void Logging::GetOsVersion(OSVERSIONINFOA* pk_OsVer)
{
	// Initialize variables
	pk_OsVer->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	ZeroMemory(&(pk_OsVer->szCSDVersion), 128 * sizeof(CHAR));
	pk_OsVer->dwMajorVersion = 0;
	pk_OsVer->dwMinorVersion = 0;
	pk_OsVer->dwBuildNumber = 0;

	// Call GetVersionExA API
	typedef BOOL(WINAPI *GetVersionExAProc)(_Inout_ LPOSVERSIONINFOA lpVersionInformation);
	HMODULE Module = LoadLibraryA("Kernel32.dll");
	if (!Module)
	{
		Log() << __FUNCTION__ << " Waring: Failed to load 'Kernel32.dll'!";
		return;
	}

	// Get version data
	GetVersionExAProc pGetVersionExA = (GetVersionExAProc)GetProcAddress(Module, "GetVersionExA");
	if (!pGetVersionExA)
	{
		Log() << __FUNCTION__ << " Waring: Failed to call 'GetVersionExA'!";
		return;
	}

	pGetVersionExA(pk_OsVer);
}

// Get Windows Operating System version number from the registry
void Logging::GetVersionReg(OSVERSIONINFO *oOS_version)
{
	// Initialize variables
	oOS_version->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	oOS_version->dwMajorVersion = 0;
	oOS_version->dwMinorVersion = 0;
	oOS_version->dwBuildNumber = 0;

	// Define registry keys
	HKEY RegKey = nullptr;
	DWORD dwDataMajor = 0;
	DWORD dwDataMinor = 0;
	unsigned long iSize = sizeof(DWORD);
	DWORD dwType = 0;

	// Get version
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &RegKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(RegKey, "CurrentMajorVersionNumber", nullptr, &dwType, (LPBYTE)&dwDataMajor, &iSize) == ERROR_SUCCESS &&
			RegQueryValueExA(RegKey, "CurrentMinorVersionNumber", nullptr, &dwType, (LPBYTE)&dwDataMinor, &iSize) == ERROR_SUCCESS)
		{
			oOS_version->dwMajorVersion = dwDataMajor;
			oOS_version->dwMinorVersion = dwDataMinor;
		}
		RegCloseKey(RegKey);
	}
}

// Get Windows Operating System version number from kernel32.dll
void Logging::GetVersionFile(OSVERSIONINFO *oOS_version)
{
	// Initialize variables
	oOS_version->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	oOS_version->dwMajorVersion = 0;
	oOS_version->dwMinorVersion = 0;
	oOS_version->dwBuildNumber = 0;

	// Load version.dll
	HMODULE Module = LoadLibraryA("version.dll");
	if (!Module)
	{
		Log() << "Failed to load version.dll!";
		return;
	}

	// Declare functions
	typedef DWORD(WINAPI *PFN_GetFileVersionInfoSize)(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
	typedef BOOL(WINAPI *PFN_GetFileVersionInfo)(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
	typedef BOOL(WINAPI *PFN_VerQueryValue)(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);

	// Get functions ProcAddress
	PFN_GetFileVersionInfoSize GetFileVersionInfoSizeA = reinterpret_cast<PFN_GetFileVersionInfoSize>(GetProcAddress(Module, "GetFileVersionInfoSizeA"));
	PFN_GetFileVersionInfo GetFileVersionInfoA = reinterpret_cast<PFN_GetFileVersionInfo>(GetProcAddress(Module, "GetFileVersionInfoA"));
	PFN_VerQueryValue VerQueryValueA = reinterpret_cast<PFN_VerQueryValue>(GetProcAddress(Module, "VerQueryValueA"));
	if (!GetFileVersionInfoSizeA || !GetFileVersionInfoA || !VerQueryValueA)
	{
		if (!GetFileVersionInfoSizeA)
		{
			Log() << "Failed to get 'GetFileVersionInfoSize' ProcAddress of version.dll!";
		}
		if (!GetFileVersionInfoA)
		{
			Log() << "Failed to get 'GetFileVersionInfo' ProcAddress of version.dll!";
		}
		if (!VerQueryValueA)
		{
			Log() << "Failed to get 'VerQueryValue' ProcAddress of version.dll!";
		}
		return;
	}

	// Get kernel32.dll path
	char buffer[MAX_PATH] = { 0 };
	GetSystemDirectoryA(buffer, MAX_PATH);
	strcat_s(buffer, MAX_PATH, "\\kernel32.dll");

	// Define registry keys
	DWORD verHandle = 0;
	UINT size = 0;
	LPBYTE lpBuffer = nullptr;
	LPCSTR szVersionFile = buffer;
	DWORD verSize = GetFileVersionInfoSizeA(szVersionFile, &verHandle);

	// GetVersion from a file
	if (verSize != 0)
	{
		std::string verData(verSize + 1, '\0');

		if (GetFileVersionInfoA(szVersionFile, verHandle, verSize, &verData[0]))
		{
			if (VerQueryValueA(&verData[0], "\\", (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						oOS_version->dwMajorVersion = (verInfo->dwFileVersionMS >> 16) & 0xffff;
						oOS_version->dwMinorVersion = (verInfo->dwFileVersionMS >> 0) & 0xffff;
						oOS_version->dwBuildNumber = (verInfo->dwFileVersionLS >> 16) & 0xffff;
						//(verInfo->dwFileVersionLS >> 0) & 0xffff		//  <-- Other data not used
					}
				}
			}
		}
	}
}

// Get Windows Operating System version number from kernel32.dll
void Logging::GetProductName(char *Name, DWORD Size)
{
	strcpy_s(Name, Size, "");

	// Define registry keys
	HKEY RegKey = nullptr;

	// Get version
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &RegKey) == ERROR_SUCCESS)
	{
		RegQueryValueExA(RegKey, "ProductName", NULL, NULL, (LPBYTE)Name, &Size);
		RegCloseKey(RegKey);
	}
}

// Log hardware manufacturer
void Logging::LogComputerManufacturer()
{
	if (!EnableLogging)
	{
		return;
	}

	std::string Buffer1, Buffer2;
	HKEY hkData;
	LPSTR lpString1 = nullptr, lpString2 = nullptr, lpString3 = nullptr;
	LPBYTE lpData = nullptr;
	DWORD dwType = 0, dwSize = 0;
	UINT uIndex, uStart, uEnd, uString, uState = 0;
	HRESULT hr;

	if ((hr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", 0, KEY_READ, &hkData)) != ERROR_SUCCESS)
	{
		return;
	}

	if ((hr = RegQueryValueExA(hkData, "SMBiosData", nullptr, &dwType, nullptr, &dwSize)) == ERROR_SUCCESS)
	{
		if (dwSize < 8 || dwType != REG_BINARY)
		{
			hr = ERROR_BADKEY;
		}
		else
		{
			lpData = new BYTE[dwSize];
			if (!lpData)
			{
				hr = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				hr = RegQueryValueExA(hkData, "SMBiosData", nullptr, nullptr, lpData, &dwSize);
			}
		}
	}

	RegCloseKey(hkData);

	if (hr == ERROR_SUCCESS)
	{
		uIndex = 8 + *(WORD *)(lpData + 6);
		uEnd = min(dwSize, (DWORD)(8 + *(WORD *)(lpData + 4))) - 1;
		lpData[uEnd] = 0x00;

		while (uIndex + 1 < uEnd && lpData[uIndex] != 0x7F)
		{
			uIndex += lpData[(uStart = uIndex) + 1];
			uString = 1;
			if (uIndex < uEnd && uStart + 6 < uEnd)
			{
				do
				{
					if (lpData[uStart] == 0x01 && uState == 0)
					{
						if (lpData[uStart + 4] == uString ||
							lpData[uStart + 5] == uString ||
							lpData[uStart + 6] == uString)
						{
							lpString1 = (LPSTR)(lpData + uIndex);
							if (!_stricmp(lpString1, "System manufacturer"))
							{
								lpString1 = nullptr;
								uState++;
							}
						}
					}
					else if (lpData[uStart] == 0x02 && uState == 1)
					{
						if (lpData[uStart + 4] == uString ||
							lpData[uStart + 5] == uString ||
							lpData[uStart + 6] == uString)
						{
							lpString1 = (LPSTR)(lpData + uIndex);
						}
					}
					else if (lpData[uStart] == 0x02 && uState == 0)
					{
						if (lpData[uStart + 4] == uString ||
							lpData[uStart + 5] == uString ||
							lpData[uStart + 6] == uString)
						{
							lpString2 = (LPSTR)(lpData + uIndex);
						}
					}
					else if (lpData[uStart] == 0x03 && uString == 1)
					{
						switch (lpData[uStart + 5])
						{
						default:   lpString3 = "(Other)";               break;
						case 0x02: lpString3 = "(Unknown)";             break;
						case 0x03: lpString3 = "(Desktop)";             break;
						case 0x04: lpString3 = "(Low Profile Desktop)"; break;
						case 0x06: lpString3 = "(Mini Tower)";          break;
						case 0x07: lpString3 = "(Tower)";               break;
						case 0x08: lpString3 = "(Portable)";            break;
						case 0x09: lpString3 = "(Laptop)";              break;
						case 0x0A: lpString3 = "(Notebook)";            break;
						case 0x0E: lpString3 = "(Sub Notebook)";        break;
						}
					}
					if (lpString1 != nullptr)
					{
						if (Buffer1.size() != 0)
						{
							Buffer1.append(" ");
						}
						Buffer1.append(lpString1);
						lpString1 = nullptr;
					}
					else if (lpString2 != nullptr)
					{
						if (Buffer2.size() != 0)
						{
							Buffer2.append(" ");
						}
						Buffer2.append(lpString2);
						lpString2 = nullptr;
					}
					else if (lpString3 != nullptr)
					{
						if (Buffer1.size() != 0)
						{
							Buffer1.append(" ");
							Buffer1.append(lpString3);
						}
						if (Buffer2.size() != 0)
						{
							Buffer2.append(" ");
							Buffer2.append(lpString3);
						}
						break;
					}
					uString++;
					while (++uIndex && uIndex < uEnd && lpData[uIndex]);
					uIndex++;
				} while (uIndex < uEnd && lpData[uIndex]);
				if (lpString3 != nullptr)
				{
					break;
				}
			}
			uIndex++;
		}
	}

	if (lpData)
	{
		delete[] lpData;
	}

	if (Buffer1.size() != 0)
	{
		Log() << Buffer1.c_str();
	}
	if (Buffer2.size() != 0)
	{
		Log() << Buffer2.c_str();
	}
}

// Log Windows Operating System type
void Logging::LogOSVersion()
{
	if (!EnableLogging)
	{
		return;
	}

	// Declare vars
	OSVERSIONINFOA oOS_version;
	OSVERSIONINFO fOS_version, rOS_version;

	// GetVersion from RtlGetVersion which is needed for some cases (Need for Speed III)
	GetOsVersion(&oOS_version);
	std::string str(" " + std::string(oOS_version.szCSDVersion));
	char *ServicePack = (str.size() > 1) ? &str[0] : "";

	// GetVersion from registry which is more relayable for Windows 10
	GetVersionReg(&rOS_version);

	// GetVersion from a file which is needed to get the build number
	GetVersionFile(&fOS_version);

	// Choose whichever version is higher
	// Newer OS's report older version numbers for compatibility
	// This allows function to get the proper OS version number
	if (rOS_version.dwMajorVersion > oOS_version.dwMajorVersion)
	{
		oOS_version.dwMajorVersion = rOS_version.dwMajorVersion;
		oOS_version.dwMinorVersion = rOS_version.dwMinorVersion;
		ServicePack = "";
	}
	if (fOS_version.dwMajorVersion > oOS_version.dwMajorVersion)
	{
		oOS_version.dwMajorVersion = fOS_version.dwMajorVersion;
		oOS_version.dwMinorVersion = fOS_version.dwMinorVersion;
		ServicePack = "";
	}
	// The file almost always has the right build number
	if (fOS_version.dwBuildNumber != 0)
	{
		oOS_version.dwBuildNumber = fOS_version.dwBuildNumber;
	}

	// Get OS string name
	char sOSName[MAX_PATH];
	GetProductName(sOSName, MAX_PATH);

	// Get bitness (32bit vs 64bit)
	SYSTEM_INFO SystemInfo;
	GetNativeSystemInfo(&SystemInfo);

	// Log operating system version and type
	Log() << sOSName << ((SystemInfo.wProcessorArchitecture == 9) ? " 64-bit" : "") << " (" << oOS_version.dwMajorVersion << "." << oOS_version.dwMinorVersion << "." << oOS_version.dwBuildNumber << ")" << ServicePack;
}

// Log video card type
void Logging::LogVideoCard()
{
	if (!EnableLogging)
	{
		return;
	}

	DISPLAY_DEVICE DispDev;
	ZeroMemory(&DispDev, sizeof(DispDev));
	DispDev.cb = sizeof(DispDev);
	DispDev.StateFlags = DISPLAY_DEVICE_PRIMARY_DEVICE;
	DWORD nDeviceIndex = 0;
	EnumDisplayDevices(NULL, nDeviceIndex, &DispDev, 0);
	Log() << DispDev.DeviceString;
}

// Get process parent PID
DWORD Logging::GetPPID()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try
	{
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally
	{
		if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hSnapshot);
		}
	}
	return ppid;
}

// Check if process name matches the requested PID
bool Logging::CheckProcessNameFromPID(DWORD pid, char *name)
{
	// Open process handle
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (!hProcess)
	{
		return false;
	}

	// Get process path
	char pidname[MAX_PATH];
	DWORD size = NewGetProcessImageFileName(hProcess, (LPSTR)&pidname, MAX_PATH);
	if (!size)
	{
		return false;
	}

	// Get process name
	char* p_wName = strrchr(pidname, '\\');
	if (!p_wName || !(p_wName > pidname && p_wName < pidname + MAX_PATH))
	{
		return false;
	}
	p_wName++;

	// Check if name matches
	if (!_stricmp(name, p_wName))
	{
		return true;
	}

	return false;
}

// Check each parent path
bool Logging::CheckEachParentFolder(char *file, char *path)
{
	if (!file || !path)
	{
		return false;
	}

	// Predefined variables
	std::string separator("\\");
	char name[MAX_PATH];
	strcpy_s(name, MAX_PATH, path);

	// Check each parent path
	do {
		char* p_wName = strrchr(name, '\\');
		if (!p_wName || !(p_wName > name && p_wName < name + MAX_PATH))
		{
			return false;
		}
		*p_wName = '\0';

		// Check if file exists in the path
		if (PathFileExistsA(std::string(name + separator + file).c_str()))
		{
			return true;
		}
	} while (true);

	return false;
}

// Log if game is a GOG game
void Logging::LogGOGGameType()
{
	// Get process path
	char name[MAX_PATH] = { 0 };
	GetModuleFileNameA(nullptr, name, MAX_PATH);

	// Check if game is a GOG game
	if (GetModuleHandleA("goggame.dll") || CheckEachParentFolder("goggame.dll", name))
	{
		Log() << "Good Old Games (GOG) game detected!";
		return;
	}
}

// Log if game is a Steam game
void Logging::LogSteamGameType()
{
	// Get process path
	char name[MAX_PATH] = { 0 };
	GetModuleFileNameA(nullptr, name, MAX_PATH);

	// Check if game is a Steam game
	if (GetModuleHandleA("steam_api.dll") || CheckEachParentFolder("steam_api.dll", name) || CheckProcessNameFromPID(GetPPID(), "steam.exe"))
	{
		Log() << "Steam game detected!";
		return;
	}
}

// Log if game type if found (GOG or Steam)
void Logging::LogGameType()
{
	LogGOGGameType();
	LogSteamGameType();
}

// Log environment variable
void Logging::LogEnvironmentVariable(const char* var)
{
	const DWORD size = GetEnvironmentVariableA(var, nullptr, 0);
	std::string value(size, 0);
	if (!value.empty())
	{
		GetEnvironmentVariableA(var, &value.front(), size);
		value.pop_back();
	}
	Log() << "Environment variable " << var << " = \"" << value.c_str() << '"';
}

// Log compatibility layer
void Logging::LogCompatLayer()
{
	LogEnvironmentVariable("__COMPAT_LAYER");
}
