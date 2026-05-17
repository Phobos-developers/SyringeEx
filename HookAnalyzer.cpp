#include "HookAnalyzer.h"
#include "Handle.h"
//#include "Setting.h"
#include <filesystem>
#include "Log.h"
#include "resource.h"

const std::string& ExecutableDirectoryPath();

void HookAnalyzer::Add(HookAnalyzeData&& Data, bool Show)
{
	if (Show)
	{
		ByLibName[Data.Lib].push_back(Data);
		HookMap[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
		ByAddress[Data.Addr].push_back(Data);
	}

	HookMapEx[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
	ByLibNameEx[Data.Lib].push_back(Data);
	ByAddressEx[Data.RelLib][Data.Addr].push_back(std::move(Data));
}

bool HookAnalyzer::ReportLOG(bool ByAddr, bool ByLib)
{
	Log::WriteLine(__FUNCTION__ ": Hook Analysis ");
	if (ByAddr)
	{
		Log::WriteLine("========================");
		Log::WriteLine("By Hook Position: （Execution order for each address）");
		for (auto& p : ByAddress)
		{
			Log::WriteLine("At %08X : ", p.first);
			for (auto v : p.second)
			{
				//Log::WriteLine("Hook\"%s, Relative to\"%s\", From\"%s\", %d Bytes Overridden ,Priority %d, Sub Priority \"%s\"", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
				Log::WriteLine("Hook\"%s, From\"%s\", %d Bytes Overridden", v.Proc.c_str(), v.Lib.c_str(), v.Len);
			}
		}
	}

	if (ByLib)
	{
		Log::WriteLine("========================");
		Log::WriteLine("By Hook Source: ");
		for (auto& p : ByLibName)
		{
			Log::WriteLine("Analyzing DLL : \"%s\" ……", p.first.c_str());
			for (auto v : p.second)
			{
				//Log::WriteLine("Hook\"%s, Relative to\"%s\", At 0x%08X, From\"%s\", %d Bytes Overridden ,Priority %d, Sub Priority \"%s\"", v.Proc.c_str(), v.RelLib.c_str(), v.Addr, v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
				Log::WriteLine("Hook\"%s, At 0x%08X, From\"%s\", %d Bytes Overridden", v.Proc.c_str(), v.Addr, v.Lib.c_str(), v.Len);
			}
		}
	}

	Log::WriteLine("========================");
	Log::WriteLine(__FUNCTION__ ": Complete. ");
	return true;
}

bool HookAnalyzer::ReportNDJSON()
{
	//TODO
	//Until a JSON library is chosen and imported
	//A format may work : 
	//every line :
	//Hook Address / Name / Source / Bytes Overridden
	return true;
}

bool HookAnalyzer::HasHookConflict(bool ShowHookConflictPopup)
{
	//check if there are conflicting hooks
	bool Conflict = false;
	for (auto& [lib, byaddr] : ByAddressEx)
	{
		std::vector<std::vector<HookAnalyzeData>*> SortedHooks;
		for (auto& p : byaddr)
			SortedHooks.push_back(&p.second);
		std::sort(SortedHooks.begin(), SortedHooks.end(), [](const auto& lhs, const auto& rhs) -> bool
			{
				return lhs->front().Addr < rhs->front().Addr;
			});
		for (size_t i = 0; i < SortedHooks.size() - 1; i++)
		{
			auto Addr1 = SortedHooks[i]->front().Addr;
			auto Addr2 = SortedHooks[i + 1]->front().Addr;
			auto Len1 = std::max_element(SortedHooks[i]->begin(), SortedHooks[i]->end(), [](const auto& lhs, const auto& rhs) -> bool
				{
					return lhs.Len < rhs.Len;
				})->Len;
			Len1 = std::max(Len1, 5);//a JMP is 5 bytes
			if (Addr1 + Len1 > Addr2)
			{
				Log::WriteLine("Hook Conflict Detected:");
				for (auto& v : *SortedHooks[i])
					//Log::WriteLine("Hook\"%s, Relative to\"%s\", From\"%s\", %d Bytes Overridden ,Priority %d, Sub Priority \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
					Log::WriteLine("Hook\"%s\", At 0x%08X, From\"%s\", %d Bytes Overridden\n", v.Proc.c_str(), v.Addr, v.Lib.c_str(), v.Len);
				for (auto& v : *SortedHooks[i + 1])
					//Log::WriteLine("Hook\"%s, Relative to\"%s\", From\"%s\", %d Bytes Overridden ,Priority %d, Sub Priority \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
					Log::WriteLine("Hook\"%s\", At 0x%08X, From\"%s\", %d Bytes Overridden\n", v.Proc.c_str(), v.Addr, v.Lib.c_str(), v.Len);
				if (!Conflict && ShowHookConflictPopup)
				{
					wchar_t ErrorStr[1000];
					swprintf_s(ErrorStr, 1000, L"Hook Conflict detected at 0x%08X and 0x%08X , see details in Syringe.log.", Addr1, Addr2);
					MessageBoxW(NULL, ErrorStr, L"SyringeEx", MB_OK | MB_ICONERROR);
				}
				Conflict = true;
			}
		}
	}
	return Conflict;
}

bool HookAnalyzer::GenerateINJ()
{
	//Log::WriteLine(ExecutableDirectoryPath().c_str());
	auto path = ExecutableDirectoryPath() + "\\INJ";
	auto pp = CreateDirectoryA(path.c_str(), NULL);
	if (pp || GetLastError() == ERROR_ALREADY_EXISTS)
	{
		//Log::WriteLine((path + "\\").c_str());
		for (auto& p : ByLibNameEx)
		{
			//Log::WriteLine((path + "\\" + p.first).c_str());
			FileHandle File = FileHandle(fopen((path + "\\" + p.first + ".inj").c_str(), "w"));
			if (!File)return false;
			for (auto& h : p.second)
			{
				if (!h.RelLib.empty())
					fputs(";Relative Hook Found ,failed to Generate", File);
				else if (!h.SubPriority.empty())
					fprintf(File, "%X=%s,%X,%d,%s\n", h.Addr, h.Proc.c_str(), h.Len, h.Priority, h.SubPriority.c_str());
				else if (h.Priority == DefaultPriority)
					fprintf(File, "%X=%s,%X\n", h.Addr, h.Proc.c_str(), h.Len);
				else
					fprintf(File, "%X=%s,%X,%d\n", h.Addr, h.Proc.c_str(), h.Len, h.Priority);
			}
		}
		return true;
	}
	return false;
}