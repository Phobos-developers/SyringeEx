#include <vector>
#include <string>
#include <Windows.h>

const std::string& ExecutableDirectoryPath()
{
	static std::string ss;
	if (!ss.empty())return ss;
	std::vector<char> full_path_exe(MAX_PATH);

	for (;;)
	{
		const DWORD result = GetModuleFileNameA(NULL,
			&full_path_exe[0],
			full_path_exe.size());

		if (result == 0)
		{
			// Report failure to caller. 
		}
		else if (full_path_exe.size() == result)
		{
			// Buffer too small: increase size. 
			full_path_exe.resize(full_path_exe.size() * 2);
		}
		else
		{
			// Success. 
			break;
		}
	}

	// Remove executable name. 
	std::string result(full_path_exe.begin(), full_path_exe.end());
	std::string::size_type i = result.find_last_of("\\/");
	if (std::string::npos != i) result.erase(i);

	ss = result;
	return ss;
}

const std::wstring& ExecutableDirectoryPathW()
{
	static std::wstring ss;
	if (!ss.empty())return ss;
	std::vector<wchar_t> full_path_exe(MAX_PATH);

	for (;;)
	{
		const DWORD result = GetModuleFileNameW(NULL,
			&full_path_exe[0],
			full_path_exe.size());

		if (result == 0)
		{
			// Report failure to caller. 
		}
		else if (full_path_exe.size() == result)
		{
			// Buffer too small: increase size. 
			full_path_exe.resize(full_path_exe.size() * 2);
		}
		else
		{
			// Success. 
			break;
		}
	}

	// Remove executable name. 
	std::wstring result(full_path_exe.begin(), full_path_exe.end());
	std::wstring::size_type i = result.find_last_of(L"\\/");
	if (std::string::npos != i) result.erase(i);

	ss = result;
	return ss;
}
