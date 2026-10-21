#include "Log.h"

#include <chrono>
#include <share.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

FileHandle Log::File;

void Log::Open(char const* const pFilename) noexcept
{
    if (pFilename && *pFilename)
    {
        File = FileHandle(_fsopen(pFilename, "w", _SH_DENYWR));
    }
}

void Log::Flush() noexcept
{
    if (File)
    {
        fflush(File);
    }
}

void Log::WriteTimestamp() noexcept
{
    if (File)
    {
        auto const now = std::chrono::system_clock::now();
        auto const seconds = std::chrono::floor<std::chrono::seconds>(now);
        auto const millis = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count());
        auto const raw = std::chrono::system_clock::to_time_t(seconds);

        tm t;
        localtime_s(&t, &raw);

        fprintf(File, "[%02d:%02d:%02d:%03d] ", t.tm_hour, t.tm_min, t.tm_sec, millis);
    }
}

void Log::WriteLine() noexcept
{
    if (File)
    {
        fputs("\n", File);
    }
}

void Log::WriteLine(char const* const pFormat, ...) noexcept
{
    if (File)
    {
        va_list args;
        va_start(args, pFormat);

        WriteTimestamp();
        vfprintf(File, pFormat, args);
        WriteLine();
        fflush(File);

        va_end(args);
    }
}
