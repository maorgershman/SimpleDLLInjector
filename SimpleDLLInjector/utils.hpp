#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <utility>
#include <string>
#include <sstream>
#include <optional>

struct Utils
{
	static inline void show_error(std::string&& message)
	{
		MessageBox(NULL, message.c_str(), "Error", MB_ICONERROR);
	}

	static inline bool is_command_line_usage_valid()
	{
		return __argc == 3;
	}

	static inline std::pair<std::string, std::string> get_files_from_command_line(const std::string& cmdLine)
	{
		std::istringstream ssCmdLine(cmdLine);

		std::string dllFile, exeFile;
		std::getline(ssCmdLine, dllFile, ' ');
		std::getline(ssCmdLine, exeFile, ' ');

		return std::pair { dllFile, exeFile };
	}

	static inline bool does_file_exist(const std::string& fileName)
	{
		DWORD dwAttrib = GetFileAttributes(fileName.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	static inline std::optional<DWORD> get_PID(const std::string& processName)
	{
		auto check_process = [&](LPDWORD pDwPID, HANDLE hSnapshot, PPROCESSENTRY32 pProcessEntry)
		{
			if (!strcmp(pProcessEntry->szExeFile, processName.c_str()))
			{
				CloseHandle(hSnapshot);
				*pDwPID = pProcessEntry->th32ProcessID;
			}
		};

		DWORD dwPID = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
		PROCESSENTRY32 processEntry{};
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		// Load the first process in the system.
		if (Process32First(hSnapshot, &processEntry))
		{
			// Is it this one?
			check_process(&dwPID, hSnapshot, &processEntry);

			// Iterate over all of the other processes in the system.
			while (Process32Next(hSnapshot, &processEntry) && !dwPID)
			{
				// Is it this one?
				check_process(&dwPID, hSnapshot, &processEntry);
			}
		}

		return dwPID ? std::optional{ dwPID } : std::nullopt;
	}
};