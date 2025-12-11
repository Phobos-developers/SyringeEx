#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"
#include "resource.h"

#include <string>

#include <commctrl.h>
#include <shellapi.h>

std::vector<std::string> GetArguments()
{
    // Get argc, argv in wide chars
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);

    // Convert to UTF-8. Skip the first argument as it contains the path to Syringe itself
    std::vector<std::string> argv(argc - 1);
    for (int i = 1; i < argc; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        argv[i - 1].resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, argv[i - 1].data(), len, nullptr, nullptr);
    }

    LocalFree(argvW);

    return argv;
}

int Run(const std::vector<std::string>& arguments)
{
    constexpr auto const VersionString = "SyringeEx " SYRINGEEX_VER_TEXT ", based on Syringe 0.7.2.0";

    InitCommonControls();

    Log::Open("syringe.log");

    Log::WriteLine(VersionString);
    Log::WriteLine("===============");
    Log::WriteLine();
    Log::WriteLine("WinMain: arguments = \"%.*s\"", printable(arguments));

    auto failure = "Could not load executable.";
    auto exit_code = ERROR_ERRORS_ENCOUNTERED;

    try
    {
        auto const command = parse_command_line(arguments);

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
            printable(command.game_arguments));
        Log::WriteLine();

        Debugger.Run(command.game_arguments);
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
            "Usage:\nSyringe.exe [-i=<injectedfile.dll> ...] \"<exe name>\" <arguments>",
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
