#pragma once

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Windows.h>

struct invalid_command_arguments : std::exception
{
};

inline auto trim(std::string_view string) noexcept
{
    auto const first = string.find_first_not_of(' ');
    if (first != std::string_view::npos)
    {
        auto const last = string.find_last_not_of(' ');
        string = string.substr(first, last - first + 1);
    }
    return string;
}

inline auto parse_command_line(const std::vector<std::string>& arguments)
{
    static constexpr std::string_view ARGS_FLAG = "--args=";

    struct argument_set
    {
        std::vector<std::string> syringe_arguments;
        std::string executable_name;
        std::string game_arguments;
    };

    if (arguments.empty())
        throw invalid_command_arguments{};

    argument_set ret;

    // First non-flag argument becomes executable name
    bool exe_found = false;

    for (const auto& arg : arguments)
    {
        // executable name: first argument not starting with '-'
        if (!exe_found && !arg.starts_with("-"))
        {
            exe_found = true;
            ret.executable_name = arg;
            continue;
        }

        // game arguments: --args="blob"
        if (arg.starts_with(ARGS_FLAG))
        {
            // extract after --args=
            std::string blob = arg.substr(ARGS_FLAG.size());
            ret.game_arguments = blob;
            continue;
        }

        // Syringe arguments
        ret.syringe_arguments.push_back(arg);
    }

    if (!exe_found || ret.executable_name.empty())
        throw invalid_command_arguments{};

    return ret;
}

inline std::string replace(
    std::string_view string, std::string_view const pattern,
    std::string_view const substitute)
{
    std::string ret;

    auto pos = 0u;
    while ((pos = string.find(pattern)) != std::string::npos)
    {
        ret += string.substr(0, pos);
        string.remove_prefix(pos);

        if (string.size() > 1)
        {
            ret += substitute;
            string.remove_prefix(pattern.size());
        }
    }

    ret += string;
    return ret;
}

// returns something %.*s can format
inline auto printable(std::string_view const string) noexcept
{
    return std::make_pair(string.size(), string.data());
}

inline auto printable(const std::vector<std::string>& arguments) noexcept
{
    static thread_local std::string buffer;
    buffer.clear();

    // Join arguments with spaces
    for (size_t i = 0; i < arguments.size(); ++i) {
        buffer += arguments[i];
        if (i + 1 < arguments.size())
            buffer += ' ';
    }

    return std::make_pair(buffer.size(), buffer.data());
}

inline auto GetFormatMessage(DWORD const error)
{
    LocalAllocHandle handle;

    auto count = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPTSTR>(handle.set()), 0u, nullptr);

    auto const message = static_cast<LPCTSTR>(handle.get());
    while (count && isspace(static_cast<unsigned char>(message[count - 1])))
    {
        --count;
    }

    return std::string(message, count);
}

struct lasterror : std::exception
{
    lasterror(DWORD const error)
        : error(error)
    {
    }

    lasterror(DWORD const error, std::string insert)
        : error(error), insert(std::move(insert))
    {
    }

    DWORD error{ 0 };
    std::string message{ GetFormatMessage(error) };
    std::string insert;
};

[[noreturn]] inline void throw_lasterror(DWORD error_code, std::string insert)
{
    throw lasterror(error_code, std::move(insert));
}

[[noreturn]] inline void throw_lasterror_or(
    DWORD alterative, std::string insert)
{
    auto const error_code = GetLastError();
    throw_lasterror(
        error_code ? error_code : alterative, std::move(insert));
}
