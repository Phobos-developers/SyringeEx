#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"
#include "resource.h"

#include <string>

#include <commctrl.h>
#include <shellapi.h>

struct Arguments
{
    std::vector<std::string> syringe_args;
    std::string game_args;
};

// Find position of the separator token "--" (token-aware).
// Returns the index of the whitespace BEFORE "--", or npos if not found.
//
// This implementation:
// - Tracks quotes using correct Windows rules (backslash counting)
// - Ensures "--" is a standalone token
// - Avoids false matches inside quotes
size_t FindSeparator(const std::wstring& cmdLine)
{
    bool inQuotes = false;
    const size_t len = cmdLine.length();

    for (size_t i = 0; i < len; ++i)
    {
        // ------------------------------------------------------------
        // Handle quote with Windows backslash rules
        // ------------------------------------------------------------
        if (cmdLine[i] == L'"')
        {
            // Count consecutive backslashes before the quote
            size_t backslashCount = 0;
            for (size_t j = i; j > 0 && cmdLine[j - 1] == L'\\'; --j)
            {
                backslashCount++;
            }

            // Even => delimiter, Odd => escaped
            if ((backslashCount % 2) == 0)
            {
                inQuotes = !inQuotes;
            }

            continue;
        }

        // ------------------------------------------------------------
        // Only check for separator outside quotes
        // ------------------------------------------------------------
        if (!inQuotes && iswspace(cmdLine[i]))
        {
            // Skip whitespace to find next token start
            size_t j = i;
            while (j < len && iswspace(cmdLine[j]))
            {
                j++;
            }

            // Check for "--"
            if (j + 1 < len &&
                cmdLine[j] == L'-' &&
                cmdLine[j + 1] == L'-')
            {
                size_t k = j + 2;

                // Ensure it's a standalone token:
                // must end or be followed by whitespace
                if (k == len || iswspace(cmdLine[k]))
                {
                    return i; // position before separator
                }
            }
        }
    }

    return std::wstring::npos;
}

Arguments GetArguments()
{
    std::wstring wszSyringeArgs;
    std::wstring wszGameArgs;
    std::wstring lpCmdLine = GetCommandLineW();
    auto separator = FindSeparator(lpCmdLine);
    if (separator != std::wstring::npos)
    {
        wszSyringeArgs = lpCmdLine.substr(0, separator);
        wszGameArgs = lpCmdLine.substr(separator + 4);
    }
    else
    {
        wszSyringeArgs = lpCmdLine;
        wszGameArgs = L"";
    }

    // Get argc, argv in wide chars
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(wszSyringeArgs.c_str(), &argc);

    // Convert to UTF-8. Skip the first argument as it contains the path to Syringe itself
    std::vector<std::string> argv(argc - 1);
    for (int i = 1; i < argc; ++i)
    {
        int len = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        argv[i - 1].resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, argv[i - 1].data(), len, nullptr, nullptr);
    }

    LocalFree(argvW);

    int len = WideCharToMultiByte(CP_UTF8, 0, wszGameArgs.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string gameArgs = std::string(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wszGameArgs.c_str(), -1, gameArgs.data(), len, nullptr, nullptr);

    return {
        argv,
        gameArgs,
    };
}

int Run(const Arguments& arguments)
{
    constexpr auto const VersionString = "SyringeEx " SYRINGEEX_VER_TEXT ", based on Syringe 0.7.2.0";

    InitCommonControls();

    Log::Open("syringe.log");

    Log::WriteLine(VersionString);
    Log::WriteLine("===============");
    Log::WriteLine();
    Log::WriteLine("WinMain: arguments = \"%.*s\"", printable(arguments.syringe_args));

    auto failure = "Could not load executable.";
    auto exit_code = ERROR_ERRORS_ENCOUNTERED;

    try
    {
        auto const command = parse_command_line(arguments.syringe_args);

        Log::WriteLine(
            "WinMain: Trying to load executable file \"%.*s\"...",
            printable(command.executable_name));
        Log::WriteLine();

        SyringeDebugger Debugger{ command.executable_name, command.syringe_arguments };
        failure = "Could not run executable.";

        Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
        Log::WriteLine();
        Debugger.FindDLLs();

        Log::WriteLine(
            "WinMain: SyringeDebugger::Run(\"%.*s\");",
            printable(arguments.game_args));
        Log::WriteLine();

        Debugger.Run(arguments.game_args);
        Log::WriteLine("WinMain: SyringeDebugger::Run finished.");
        Log::WriteLine("WinMain: Exiting on success.");
        return ERROR_SUCCESS;
    }
    catch (lasterror const& e)
    {
        auto const message = replace(e.message, "%1", e.insert);
        Log::WriteLine("WinMain: %s (%d)", message.c_str(), e.error);

        auto const msg = std::string(failure) + "\n\n" + message;
        MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

        exit_code = static_cast<long>(e.error);
    }
    catch (invalid_command_arguments const&)
    {
        MessageBoxA(
            nullptr, "Syringe cannot be run like that.\n\n"
                     "Usage:\nSyringe.exe <exe name> [-i=<injectedfile.dll> ...] [-- <arguments>]",
            VersionString, MB_OK | MB_ICONINFORMATION);

        Log::WriteLine(
            "WinMain: Invalid command line arguments given, exiting...");

        exit_code = ERROR_INVALID_PARAMETER;
    }

    Log::WriteLine("WinMain: Exiting on failure.");
    return static_cast<int>(exit_code);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    return Run(GetArguments());
}
