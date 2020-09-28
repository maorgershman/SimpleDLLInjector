# SimpleDLLInjector
A simple manual-mapping DLL injector library, written in C using Win32 API.

# Usage
Link to `SimpleDLLInjector.dll` and call `inject(unsigned long dwPID, const char *cstrDLLFilePath)`.    
The function assumes valid PID and file path.
