#include "utils.hpp"
#include "injector.hpp"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int)
{
	if (!Utils::is_command_line_usage_valid())
	{
		Utils::show_error("Usage: SimpleDLLInjector.exe <dll> <exe>");
		return 1;
	}

	auto[dllPath, processName] = Utils::get_files_from_command_line(lpCmdLine);

	if (!Utils::does_file_exist(dllPath))
	{
		Utils::show_error("Unable to find the file named \"" + dllPath + "\"!");
		return 1;
	}

	auto optPID = Utils::get_PID(processName);
	if (!optPID.has_value())
	{
		Utils::show_error("Unable to find the process named \"" + processName + "\"!");
		return 1;
	}

	inject(optPID.value(), dllPath.c_str());

	return 0;
}