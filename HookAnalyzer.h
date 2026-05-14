#pragma once

#include<vector>
#include<unordered_map>
#include<string>

const std::string AnalyzerDelim = "\\*^*\\";
const int DefaultPriority = 100000;

struct HookAnalyzeData
{
	std::string Lib;
	std::string Proc;
	int Addr;
	int Len;

	int Priority{ DefaultPriority };
	std::string SubPriority{ "" };
	std::string RelLib{ "" };
};

class HookAnalyzer
{
private:
	std::unordered_map<std::string, std::vector<HookAnalyzeData>> ByLibName;
	std::unordered_map<std::string, std::vector<HookAnalyzeData>> ByLibNameEx;
public:
	std::unordered_map<std::string, HookAnalyzeData> HookMap;
	std::unordered_map<int, std::vector<HookAnalyzeData>> ByAddress;
	std::unordered_map<std::string, HookAnalyzeData> HookMapEx;
	std::unordered_map<std::string, std::unordered_map<int, std::vector<HookAnalyzeData>>> ByAddressEx;

	void Add(HookAnalyzeData&& , bool Show);
	bool ReportLOG(bool ByAddr, bool ByLib);
	bool ReportNDJSON();//TODO
	bool GenerateINJ();
	bool HasHookConflict(bool ShowHookConflictPopup);
};

//static constexpr size_t MaxNameLength = 0x100u;
//
//struct Hook
//{
//	char lib[MaxNameLength];
//	char proc[MaxNameLength];
//	void* proc_address;
//
//	size_t num_overridden;
//	int Priority;
//	char SubPriority[MaxNameLength];
//	char RelativeLib[MaxNameLength];
//};