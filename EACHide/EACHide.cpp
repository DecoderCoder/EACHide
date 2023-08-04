// GetModuleHandleRemover.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <vector>
#include <map>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <charconv>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "ntdll.lib")
#include "ntdll.h"

#include "color.hpp"

#include "XEDParse/XEDParse.h"

#include "RawPDB/PDB.h"
#include "RawPDB/PDB_RawFile.h"
#include "RawPDB/PDB_InfoStream.h"
#include "RawPDB/PDB_DBIStream.h"
#include "RawPDB/PDB_TPIStream.h"
#include "RawPDB/PDB_NamesStream.h"
#include "RawPDB/PDB_ModuleInfoStream.h"

#include "Zydis/Zydis.h"

#undef GetModuleHandle

using namespace std;
namespace fs = filesystem;
PDB_NO_DISCARD static bool IsError(PDB::ErrorCode errorCode)
{
	switch (errorCode)
	{
	case PDB::ErrorCode::Success:
		return false;

	case PDB::ErrorCode::InvalidSuperBlock:
		printf("Invalid Superblock\n");
		return true;

	case PDB::ErrorCode::InvalidFreeBlockMap:
		printf("Invalid free block map\n");
		return true;

	case PDB::ErrorCode::InvalidStream:
		printf("Invalid stream\n");
		return true;

	case PDB::ErrorCode::InvalidSignature:
		printf("Invalid stream signature\n");
		return true;

	case PDB::ErrorCode::InvalidStreamIndex:
		printf("Invalid stream index\n");
		return true;

	case PDB::ErrorCode::UnknownVersion:
		printf("Unknown version\n");
		return true;
	}

	// only ErrorCode::Success means there wasn't an error, so all other paths have to assume there was an error
	return true;
}

static char* ReadAllBytes(string filename, int* read)
{
	ifstream ifs(filename, ios::binary | ios::ate);
	ifstream::pos_type pos = ifs.tellg();
	int length = pos;
	char* pChars = new char[length];
	ifs.seekg(0, ios::beg);
	ifs.read(pChars, length);
	ifs.close();
	*read = length;
	return pChars;
}

class Function {
public:
	string Name;
	uint32_t RVA;
	uint32_t Size;
	std::vector<ZydisDisassembledInstruction> instructions;

	bool operator <(const Function& func) const {
		return func.instructions.size() < this->instructions.size();
	}

	bool operator ==(const Function& func) const {
		if (func.RVA == 0xb00d9 && this->RVA == 0xb00d9)
			printf(0);
		return func.RVA == this->RVA;
	}
};

enum class ReplaceInstructionType {
	GetModuleHandle,
	GetAsyncKeyState,
};

HANDLE m_hChildStd_OUT_Rd = NULL;
HANDLE m_hChildStd_OUT_Wr = NULL;
HANDLE m_hreadDataFromExtProgram = NULL;

DWORD __stdcall readDataFromExtProgram(void* argh)
{
#define BUFSIZE 256
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];
	BOOL bSuccess = FALSE;

	for (;;)
	{
		bSuccess = ReadFile(m_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) continue;

		cout << string(chBuf, dwRead);

		if (!bSuccess) break;
	}
	return 0;
#undef BUFSIZE
}

wstring lowercase(const wstring& s)
{
	std::wstring str(s);
	std::transform(str.begin(), str.end(), str.begin(),
		[](wchar_t c) { return std::tolower(c); });
	return str;
}

wchar_t* appendToEnvironmentBlock(wchar_t* pEnvBlock, const wstring& varname, const wstring& varvalue)
{
	//UNICODE_STRING name;
	//name.Buffer = (PWSTR)varname.data();
	//name.Length = varname.size();
	//name.MaximumLength = varname.size();

	//UNICODE_STRING value;
	//value.Buffer = (PWSTR)varvalue.data();
	//value.Length = varvalue.size();
	//value.MaximumLength = varvalue.size();

	//NTSTATUS status = RtlSetEnvironmentVariable((void**)pEnvBlock, &name, &value);

	map<wstring, wstring> env;
	const wchar_t* currentEnv = (const wchar_t*)pEnvBlock;
	wstring result;

	// parse the current block into a map of key/value pairs
	while (*currentEnv)
	{
		wstring keyvalue = currentEnv;
		wstring key;
		wstring value;

		size_t pos = keyvalue.find_last_of(L'=');
		if (pos != wstring::npos)
		{
			key = keyvalue.substr(0, pos);
			value = keyvalue; // entire string
		}
		else
		{
			// ??? no '=' sign, just save it off
			key = keyvalue;
			value = keyvalue;
		}
		value += L'\0'; // reappend the null char

		env[lowercase(key)] = value;
		currentEnv += keyvalue.size() + 1;
	}

	// add the new key and value to the map
	if (varvalue.empty())
	{
		env.erase(lowercase(varname)); // if varvalue is empty, just assume this means, "delete this environment variable"
	}
	else
	{
		env[lowercase(varname)] = varname + L'=' + varvalue + L'\0';
	}

	// serialize the map into the buffer we just allocated
	for (auto& item : env)
	{
		result += item.second;
	}
	result += L'\0';
	auto ptr = result.c_str();

	wchar_t* newArr = (wchar_t*)malloc(result.size() * sizeof(wchar_t));
	memcpy(newArr, result.data(), result.size() * sizeof(wchar_t));
	return newArr;

	//	return L"";
}

class FunctionToReplace {
public:
	string Name;
	uint32_t RVA;
	Function Function;
	ReplaceInstructionType Type;
};

class GetAsyncKeyStateType {
public:
	bool isApiset = false;
	string moduleName = "";
};

class ReplaceInstruction {
public:
	uint64_t instructionPlace;
	ZydisDisassembledInstruction i;
	ZyanUSize offset;
	ReplaceInstructionType type;
	Function* function;

	GetAsyncKeyStateType getAsyncKeyState;



};

std::vector<Function> Functions;
PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* Sections;

template< typename T >
std::string to_hex(T i, int count = 0)
{
	std::stringstream stream;
	uint64_t bytes = 0xFFFFFFFFFFFFFFFF;
	if (count == 0)
		count = sizeof(T);
	count *= 8;
	bytes = bytes >> sizeof(bytes) * 8 - count;
	stream << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex << (bytes & i);
	return stream.str();
}

PDB::IMAGE_SECTION_HEADER* GetSectionByName(std::string name) {
	for (auto section : *Sections) {
		if (string((char*)section.Name) == name) {
			return &section;
		}
	}
	return nullptr;
}

PDB::IMAGE_SECTION_HEADER* GetSectionByRVA(uint32_t rva) {
	for (auto section : *Sections) {
		if (rva > section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData) {
			return &section;
		}
	}
	return nullptr;
}

uintptr_t RVA2Offset(uint32_t rva) {
	auto section = GetSectionByRVA(rva);
	if (!section)
		return 0;
	return rva - section->VirtualAddress + section->PointerToRawData;
}

//Function* GetFunctionByInstruction(const ZydisDisassembledInstruction& inst) {
//	for (auto& func : Functions) {
//		if (inst.runtime_address >= func.RVA && inst.runtime_address <= func.RVA + func.Size)
//			return &func;
//	}
//	return nullptr;
//}

Function* GetFunctionByName(string name, bool strict = false, bool first = false) {
	Function* found = nullptr;
	for (auto& func : Functions) {
		if (strict && func.Name == name)
		{
			if (first)
				return &func;
			found = &func;
		}
		else if (!strict && func.Name.find(name) != string::npos)
		{
			if (first)
				return &func;
			found = &func;
		}
	}
	return found;
}

string hashString(string str) {
	string temp = string(str, 0, 2);
	string result = "";

	for (int i = 0; i < str.size(); i++) {
		temp[i % 2] += str[i];
	}

	for (int i = 0; i < temp.size(); i++) {
		result += to_hex((char)temp[i]);
	}


	return result;
}

void WriteToFile(std::string FileName, std::string text) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::app);
	myfile << text << "\n";
	myfile.close();
}

void WriteToFile(std::wstring FileName, std::string text) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::app);
	myfile << text << "\n";
	myfile.close();
}

void WriteToFile(std::string FileName, char* file, size_t size) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::out | std::ios::binary);
	myfile.write(file, size);
	myfile.close();
}

// --basemodule "modulename.exe" // GetModuleHandle(NULL)

std::string ReplaceAll(std::string str, const std::string& from = "", const std::string& to = "") {
	if (from == "" && to == "") {
		string resultStr = "";
		for (int i = 0; i < str.size(); i++) {
			if (std::isdigit((unsigned char)str[i]) || std::ispunct((unsigned char)str[i]) || std::isalpha((unsigned char)str[i]))
				resultStr += str[i];
			else {
				resultStr += hashString(string("_") + str[i] + "_");
			}
		}
		return resultStr;
	}

	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}

Function GetFunctionByRecord(const PDB::CodeView::DBI::Record* record, const PDB::ImageSectionStream& imageSectionStream) {

	const char* name = nullptr;
	uint32_t rva = 0u;
	uint32_t address = 0;
	uint32_t size = record->header.size;

	if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32)
	{
		name = record->data.S_GDATA32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GDATA32.section, record->data.S_GDATA32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GTHREAD32)
	{
		name = record->data.S_GTHREAD32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GTHREAD32.section, record->data.S_GTHREAD32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
	{
		name = record->data.S_LDATA32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32)
	{
		name = record->data.S_LTHREAD32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT)
	{
		name = record->data.S_UDT.name;
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT_ST)
	{
		name = record->data.S_UDT_ST.name;
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32)
	{
		if (record->data.S_THUNK32.thunk == PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental)
		{
			// we have never seen incremental linking thunks stored inside a S_THUNK32 symbol, but better be safe than sorry
			name = "ILT";
			rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_THUNK32.section, record->data.S_THUNK32.offset);
		}
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE)
	{
		// incremental linking thunks are stored in the linker module
		name = "ILT";
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_TRAMPOLINE.thunkSection, record->data.S_TRAMPOLINE.thunkOffset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_BLOCK32)
	{
		// blocks never store a name and are only stored for indicating whether other symbols are children of this block
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LABEL32)
	{
		// labels don't have a name
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32)
	{
		name = record->data.S_LPROC32.name;
		size = record->data.S_LPROC32.codeSize;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32.section, record->data.S_LPROC32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32)
	{
		name = record->data.S_GPROC32.name;
		size = record->data.S_GPROC32.codeSize;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32.section, record->data.S_GPROC32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID)
	{
		name = record->data.S_LPROC32_ID.name;
		size = record->data.S_LPROC32_ID.codeSize;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32_ID.section, record->data.S_LPROC32_ID.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID)
	{
		name = record->data.S_GPROC32_ID.name;
		size = record->data.S_GPROC32_ID.codeSize;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32_ID.section, record->data.S_GPROC32_ID.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_REGREL32)
	{
		name = record->data.S_REGREL32.name;
		// You can only get the address while running the program by checking the register value and adding the offset
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
	{
		name = record->data.S_LDATA32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
	}
	else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32)
	{
		name = record->data.S_LTHREAD32.name;
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
	}
	else {
		rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
		name = record->data.S_PUB32.name;
	}
	string name2 = "";
	if (name)
		name2 = ReplaceAll(string(name));
	else
		rva = 0;

	if (name2 == "__scrt_is_managed_app")
		printf("");
	return Function{ name2, rva, size };
}

int main(int argc, char* argv[])
{
	if (argc == 1)
		return 0;

	wstring vsPath;
	wstring clPath;
	wstring winSdk;
	wstring msvc;
	wstring windowsKitPath;

	wstring currentPath = fs::path(argv[0]).parent_path().wstring();
	{
		wchar_t buff[MAX_PATH];
		wstring winDrive;
		if (GetWindowsDirectoryW(buff, sizeof(buff) / sizeof(wchar_t)))
		{
			winDrive += buff[0]; // X:\\		
			winDrive += buff[1];
			winDrive += buff[2];
		}
		else
			return 0;
		wstring visualStudioPathes[] = { // from newest to oldest
			L"Program Files\\Microsoft Visual Studio\\2022",
			L"Program Files (x86)\\Microsoft Visual Studio\\2019"
		};

		for (auto path : visualStudioPathes) { // Find VS Path
			for (auto& p : fs::directory_iterator(winDrive + path))
			{
				if (p.is_directory())
				{
					vsPath = p.path().wstring();
					break;
				}
			}
			if (!vsPath.empty())
				break;
		}

		for (auto& p : fs::directory_iterator(vsPath + L"\\VC\\Tools\\MSVC"))
		{
			if (p.is_directory())
			{
				msvc = p.path().filename().wstring();
			}
		}

		clPath = vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\bin\\Hostx64\\x64\\cl.exe";

		windowsKitPath = winDrive + L"Program Files (x86)\\Windows Kits\\10";
		for (auto& p : fs::directory_iterator(windowsKitPath + L"\\Include"))
		{
			if (p.is_directory())
			{
				wstring path = p.path().wstring();
				if (path.find(L"10.0.") != wstring::npos)
					winSdk = p.path().filename();
			}
		}
	}

	if (clPath.empty()) {
		cout << "msvc compiler not found" << endl;
		return 0;
	}

	//string GMHBaseModule = "";
	bool apiStrict = false;
	for (int i = 1; i < argc; i++) { // Parse args
		if (string(argv[i]) == "--api-strict") {
			//GMHBaseModule = string(argv[i + 1]);
			i++;
		}
	}


	string exeFileName = string(argv[1]);
	string fileExtension = exeFileName.substr(exeFileName.size() - 3);
	string newExeFileName = string(argv[1]);
	newExeFileName = newExeFileName.substr(0, newExeFileName.size() - 4) + "_new." + fileExtension;
	string pdbFileName = string(argv[1]);
	pdbFileName.replace(pdbFileName.end() - 3, pdbFileName.end(), "pdb");

	if (!fs::exists(exeFileName) || !fs::exists(pdbFileName))
		return -1;

	int pdbFileSize = 0;
	char* pdbFile = ReadAllBytes(pdbFileName, &pdbFileSize);

	if (IsError(PDB::ValidateFile(pdbFile)))
		return -1;

	int exeFileSize = 0;
	char* exeFile = ReadAllBytes(exeFileName, &exeFileSize);

	const PDB::RawFile rawPdbFile = PDB::CreateRawFile(pdbFile);
	const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawPdbFile);
	const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);
	const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(rawPdbFile);
	const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawPdbFile);
	const PDB::PublicSymbolStream publicSymbolStream = dbiStream.CreatePublicSymbolStream(rawPdbFile);
	auto sections = imageSectionStream.GetImageSections();
	Sections = &sections;
	// Imports
	{
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)exeFile;
		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(exeFile + dos_header->e_lfanew);
		PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(exeFile + dos_header->e_lfanew + sizeof(nt_header->Signature));
		PIMAGE_OPTIONAL_HEADER optional_header = (PIMAGE_OPTIONAL_HEADER)(exeFile + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));
		if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) // Only X64
			return -1;

		//IMAGE_DATA_DIRECTORY image_import = optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		//auto offset = RVA2Offset((uint32_t)image_import.VirtualAddress);
		//PIMAGE_IMPORT_DESCRIPTOR kernel32 = nullptr;
		//PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(exeFile + offset);
		//do {
		//	if (import_desc->Name == 0)
		//		break;
		//	auto name = string((char*)(exeFile + RVA2Offset(import_desc->Name)));
		//	if (name == "KERNEL32.dll") {
		//		kernel32 = import_desc;
		//	}
		//	else {
		//		import_desc++;
		//	}
		//} while (kernel32 == nullptr);

		//if (!kernel32)
		//	return -1;

		//PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)(exeFile + RVA2Offset(import_desc->OriginalFirstThunk == 0 ? import_desc->FirstThunk : import_desc->OriginalFirstThunk));

		//for (; thunk_data->u1.AddressOfData != 0; thunk_data++) {

		//	auto name = exeFile + RVA2Offset(thunk_data->u1.AddressOfData) + 2;
		//	if (string(name).find("GetModuleHandle") != string::npos) {
		//		printf("[Import] Found %s at %x\n", name, thunk_data->u1.AddressOfData);

		//	}
		//}

		//printf("\n\n");

	}

	{

		const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();
		const size_t count = hashRecords.GetLength();

		for (const PDB::HashRecord& hashRecord : hashRecords)
		{
			const PDB::CodeView::DBI::Record* record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
			if (Function f = GetFunctionByRecord(record, imageSectionStream); f.RVA != 0)
				Functions.push_back(f);
		}
	}
	const PDB::GlobalSymbolStream globalSymbolStream = dbiStream.CreateGlobalSymbolStream(rawPdbFile);
	{
		const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();
		const size_t count = hashRecords.GetLength();

		for (const PDB::HashRecord& hashRecord : hashRecords)
		{
			const PDB::CodeView::DBI::Record* record = globalSymbolStream.GetRecord(symbolRecordStream, hashRecord);

			if (Function f = GetFunctionByRecord(record, imageSectionStream); f.RVA != 0)
				Functions.push_back(f);
		}
	}
	{
		const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();

		for (const PDB::ModuleInfoStream::Module& module : modules)
		{
			if (!module.HasSymbolStream())
			{
				continue;
			}

			const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawPdbFile);
			moduleSymbolStream.ForEachSymbol([&imageSectionStream](const PDB::CodeView::DBI::Record* record)
				{
					if (Function f = GetFunctionByRecord(record, imageSectionStream); f.RVA != 0)
						Functions.push_back(f);
				});
		}
	}

	std::map<uint32_t, FunctionToReplace> FunctionsToReplace;
	for (auto func : Functions) {
		if (func.Name.find("__imp_GetModuleHandleW") != string::npos) {
			FunctionsToReplace[func.RVA] = FunctionToReplace{ "__imp_GetModuleHandleW", func.RVA, func, ReplaceInstructionType::GetModuleHandle };
			cout << "[Import] Found " << dye::light_red(func.Name) << " at " << hex << func.RVA << endl;
		}
		else if (func.Name.find("__imp_GetAsyncKeyState") != string::npos) {
			FunctionsToReplace[func.RVA] = FunctionToReplace{ "__imp_GetAsyncKeyState", func.RVA, func, ReplaceInstructionType::GetAsyncKeyState };
			cout << "[Import] Found " << dye::light_red(func.Name) << " at " << hex << func.RVA << endl;
		}
	}

	for (auto& func : Functions) {
		uintptr_t FuncAddress = RVA2Offset(func.RVA);
		if (FuncAddress == 0)
			continue;

		ZyanUSize offset = 0;
		ZydisDisassembledInstruction instruction;

		ZyanStatus zyanStatus;
		while (ZYAN_SUCCESS(zyanStatus = ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (uintptr_t)func.RVA + offset, (char*)(exeFile + FuncAddress + offset), func.Size - offset, &instruction)))
		{
			offset += instruction.info.length;
			func.instructions.push_back(instruction);
		}
	}

	//std::sort(Functions.begin(), Functions.end());
	//Functions.erase(std::unique(Functions.begin(), Functions.end()), Functions.end());


	int haveToReplace = 0;
	int replaced = 0;
	std::map<uint32_t, std::vector<ReplaceInstruction>> instructionsToReplace;
	for (int b = 0; b < Functions.size(); b++) {
		ZyanUSize offset = 0;
		for (unsigned long long i = 0; i < Functions[b].instructions.size(); i++) {
			auto instruction = Functions[b].instructions[i];

			if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
				if (instruction.info.opcode == 0xFF && instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
					uintptr_t calledFunction = Functions[b].RVA + offset + instruction.operands[0].mem.disp.value + instruction.info.length;
					for (auto [fRVA, rFunc] : FunctionsToReplace) {
						if (fRVA == calledFunction) {
							ReplaceInstruction rep;
							rep.function = &Functions[b];
							rep.instructionPlace = i;
							rep.i = instruction;
							rep.offset = offset;
							rep.type = rFunc.Type;
							instructionsToReplace[fRVA].push_back(rep);
							haveToReplace++;
							break;
						}
					}
				}
			offset += instruction.info.length;
		}
	}
	for (auto& [iRVA, instructions] : instructionsToReplace) {
		for (auto& inst : instructions) {
			Function* func = inst.function;
			switch (inst.type) {
			case ReplaceInstructionType::GetModuleHandle:
				bool apiSet = false;
				string moduleName = "NULL";
				{
					int leaInstructionPlace = 0;
					ZydisDisassembledInstruction* leaInstruction = nullptr;
					for (int i = inst.instructionPlace - 1; i >= 0; i--) {
						auto instr = func->instructions[i];
						if (instr.info.mnemonic == ZYDIS_MNEMONIC_XOR && (instr.operands[0].reg.value == ZYDIS_REGISTER_RCX || instr.operands[1].reg.value == ZYDIS_REGISTER_ECX))
							break;
						if (instr.info.mnemonic == ZYDIS_MNEMONIC_LEA) {
							if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instr.operands[0].reg.value == ZYDIS_REGISTER_RCX && instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
								wchar_t* str = (wchar_t*)(exeFile + RVA2Offset(instr.runtime_address + instr.operands[1].mem.disp.value + instr.info.length));
								int strLen = wcslen(str);
								if (strLen > 4) {
									apiSet = wcsstr(str, L"api") == str || wcsstr(str, L"ext") == str;
									leaInstructionPlace = i;
									leaInstruction = &func->instructions[i];

									//
									memset(exeFile + RVA2Offset(leaInstruction->runtime_address), 0x90, leaInstruction->info.length);
									//

									int offset = 0;
									for (int i = 0; i < leaInstructionPlace; i++) {
										offset += func->instructions[i].info.length;
									}

									char* pModuleName = (char*)malloc(128);
									memset(pModuleName, 0, 128);
									wchar_t* wModuleName = (wchar_t*)(exeFile + RVA2Offset(func->RVA + offset + leaInstruction->info.length + leaInstruction->operands[1].mem.disp.value));
									size_t moduleNameLength;
									wcstombs_s(&moduleNameLength, pModuleName, 128, wModuleName, 128 - 1);
									moduleName = string(pModuleName);
									if (apiSet && !apiStrict) {
										moduleName = moduleName.substr(0, moduleName.size() - 6); // remove
									}
									break;
								}
							}
						}
						if (inst.instructionPlace - i > 5)
							break;
					}
				}
				inst.getAsyncKeyState = GetAsyncKeyStateType{ apiSet, moduleName };
				break;
			}
		}
	}

	for (auto [iRVA, instructions] : instructionsToReplace) {
		printf("\n%s\n", FunctionsToReplace[iRVA].Name.c_str());
		for (auto inst : instructions)
			cout << "  " << setfill('0') << setw(8) << hex << inst.i.runtime_address << dec << ": " << dye::light_aqua(inst.function->Name) << endl;
	}

	cout << endl << "Genereting functions" << endl;

	string GetAsyncKeyStateFuncName = "_" + hashString("EACGetAsyncKeyState") + "_" + hashString(fs::path(exeFileName).filename().string());
	{ // Generating
		wstring resultFileName = currentPath + L"\\EACHide\\EACHide.cpp";
		fs::create_directories(fs::path(resultFileName).parent_path());
		if (fs::exists(resultFileName))
			fs::remove(resultFileName);
		//	WriteToFile(resultFileName, "#pragma once");	
		WriteToFile(resultFileName, "#include <Windows.h>");
		WriteToFile(resultFileName, "#include \"LazyImporter.hpp\"");
		WriteToFile(resultFileName, "");

		WriteToFile(resultFileName, "#ifndef _DEBUG");
		WriteToFile(resultFileName, "#pragma comment(linker, \"/include:" + GetAsyncKeyStateFuncName + "\")");
		WriteToFile(resultFileName, "EXTERN_C __declspec(noinline) short " + GetAsyncKeyStateFuncName + "(int vKey) {");
		WriteToFile(resultFileName, "	auto kernel32 = LI_MODULE(\"kernel32.dll\").safe<char*>();");
		WriteToFile(resultFileName, "	if (!kernel32)");
		WriteToFile(resultFileName, "		return 0;");
		WriteToFile(resultFileName, "	auto poorVGetAsyncKeyState = kernel32 + 0x81600;");
		WriteToFile(resultFileName, "	if (*poorVGetAsyncKeyState == 0) {");
		WriteToFile(resultFileName, "		auto pReturnAddress = poorVGetAsyncKeyState - sizeof(uintptr_t) * 1;");
		WriteToFile(resultFileName, "		unsigned char shellCode[] = {");
		WriteToFile(resultFileName, "			0x4D, 0x89, 0xFA, //");
		WriteToFile(resultFileName, "			0xB8, 0x3F, 0x10, 0x00, 0x00, //getasynckeystate");
		WriteToFile(resultFileName, "			0x0F, 0x05,  //syscall");
		WriteToFile(resultFileName, "			0xFF, 0x25, 0xE8, 0xFF, 0xFF, 0xFF // jmp far [rip-24]");
		WriteToFile(resultFileName, "		};");
		WriteToFile(resultFileName, "		DWORD old;");
		WriteToFile(resultFileName, "		VirtualProtect(pReturnAddress, sizeof(shellCode) + sizeof(uintptr_t) * 1, 0x40, &old);");
		WriteToFile(resultFileName, "		VirtualProtect(&" + GetAsyncKeyStateFuncName + ", 0x9999999, 0x40, &old);");
		WriteToFile(resultFileName, "		memcpy(poorVGetAsyncKeyState, &shellCode, sizeof(shellCode));");
		WriteToFile(resultFileName, "		*(uintptr_t*)pReturnAddress = (uintptr_t)((uintptr_t)&" + GetAsyncKeyStateFuncName + " + 0x11111111);");
		WriteToFile(resultFileName, "		*(uintptr_t*)((uintptr_t)&" + GetAsyncKeyStateFuncName + " + 0x22222222) = (uintptr_t)poorVGetAsyncKeyState;");
		WriteToFile(resultFileName, "	}");
		WriteToFile(resultFileName, "	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); // jmp rbx");
		WriteToFile(resultFileName, "	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); // shellcodeptr");
		WriteToFile(resultFileName, "	__nop(); // <- ret here");
		WriteToFile(resultFileName, "	return 0;");
		WriteToFile(resultFileName, "}");
		WriteToFile(resultFileName, "#endif");
		WriteToFile(resultFileName, "");
		cout << " - [" << dye::aqua("GetAsyncKeyState") << "] - Created function: " << dye::light_green(GetAsyncKeyStateFuncName) << endl;

		vector<string> addedFuncs;
		for (auto [iRVA, instructions] : instructionsToReplace) {
			for (auto inst : instructions) {
				Function* func = inst.function;
				if (inst.type == ReplaceInstructionType::GetModuleHandle) { // GetModuleHandle					
					{
						string moduleName = inst.getAsyncKeyState.moduleName;
						string newFuncName = "_" + hashString(inst.getAsyncKeyState.moduleName);

						if (std::find(addedFuncs.begin(), addedFuncs.end(), moduleName) != addedFuncs.end())
							continue;
						if (moduleName != "NULL") {
							WriteToFile(resultFileName, "#pragma comment(linker, \"/include:" + newFuncName + "\")");
							WriteToFile(resultFileName, "EXTERN_C __declspec(noinline) HMODULE __stdcall " + newFuncName + "() { // " + to_hex(func->RVA + inst.offset) + " _ " + func->Name);
							if (inst.getAsyncKeyState.isApiset)
								WriteToFile(resultFileName, "\treturn LI_MODULE(\"" + moduleName + "\").api<HMODULE>();");
							else
								WriteToFile(resultFileName, "\treturn LI_MODULE(\"" + moduleName + "\").safe<HMODULE>();");
							WriteToFile(resultFileName, "}");
							WriteToFile(resultFileName, "");

							cout << " - [" << dye::aqua("GetModuleHandle") << "]  - Created function: " << dye::light_green(newFuncName) << "(" << dye::yellow(moduleName) << ")" << endl;
						}
						else {
							WriteToFile(resultFileName, "#pragma comment(linker, \"/include:" + newFuncName + "\")");
							WriteToFile(resultFileName, "EXTERN_C __declspec(noinline) HMODULE __stdcall " + newFuncName + "() { // " + to_hex(func->RVA + inst.offset) + "  [NULL]" + func->Name); //LPCWSTR lpModuleName
							WriteToFile(resultFileName, "\treturn LI_BASE().get<HMODULE>();");
							WriteToFile(resultFileName, "}");
							WriteToFile(resultFileName, "");

							cout << " - [" << dye::aqua("GetModuleHandle") << "]  - Created function: " << dye::light_green(newFuncName) << "(" << dye::light_purple("NULL") << ") in " << dye::light_aqua(inst.function->Name) << endl;
						}
						addedFuncs.push_back(moduleName);
					}
				}
			}
		}

		WriteToFile(resultFileName, "int main() {}");
	}


	// Compiling code
	//{
	//	wchar_t* pEnv = (wchar_t*)L"";
	//	pEnv = GetEnvironmentStringsW();
	//	HANDLE hToken = NULL;
	//	BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);
	//	CreateEnvironmentBlock((void**)&pEnv, hToken, TRUE);

	//	wstring include = L"";
	//	include += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\include" + L";";
	//	include += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\ATLMFC\\include" + L";";
	//	include += vsPath + L"\\VC\\Auxiliary\\VS\\include" + L";";
	//	include += windowsKitPath + L"\\include\\" + winSdk + L"\\ucrt" + L";";
	//	include += windowsKitPath + L"\\include\\" + winSdk + L"\\um" + L";";
	//	include += windowsKitPath + L"\\include\\" + winSdk + L"\\shared" + L";";
	//	include += windowsKitPath + L"\\include\\" + winSdk + L"\\winrt" + L";";
	//	include += windowsKitPath + L"\\include\\" + winSdk + L"\\cppwinrt" + L"";
	//	pEnv = appendToEnvironmentBlock(pEnv, L"INCLUDE", include.c_str());

	//	wstring lib = L"";
	//	lib += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\ATLMFC\\lib\\x64" + L";";
	//	lib += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\lib\\x64" + L";";
	//	//lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\shared" + L";";
	//	lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\ucrt\\x64" + L";";
	//	lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\um\\x64" + L";";
	//	pEnv = appendToEnvironmentBlock(pEnv, L"LIB", lib.c_str());

	//	cout << endl << "Compiling code" << endl;

	//	STARTUPINFO si;
	//	PROCESS_INFORMATION clProc;
	//	SECURITY_ATTRIBUTES saAttr;

	//	memset(&saAttr, 0, sizeof(saAttr));
	//	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	//	saAttr.bInheritHandle = TRUE;
	//	saAttr.lpSecurityDescriptor = NULL;

	//	if (!CreatePipe(&m_hChildStd_OUT_Rd, &m_hChildStd_OUT_Wr, &saAttr, 0))
	//	{
	//		// log error
	//		return HRESULT_FROM_WIN32(GetLastError());
	//	}

	//	if (!SetHandleInformation(m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
	//	{
	//		// log error
	//		return HRESULT_FROM_WIN32(GetLastError());
	//	}

	//	memset(&si, 0, sizeof(si));
	//	si.cb = sizeof(si);
	//	si.hStdError = m_hChildStd_OUT_Wr;
	//	si.hStdOutput = m_hChildStd_OUT_Wr;
	//	si.dwFlags |= STARTF_USESTDHANDLES;

	//	memset(&clProc, 0, sizeof(clProc));

	//	if (CreateProcessW((LPWSTR)clPath.c_str(), (LPWSTR)L" EACHide.cpp /permissive- /GS /GL /Gy /Zc:wchar_t /Zi /Gm- /O2 /sdl /Zc:inline /fp:precise /Zc:forScope /Gd /Oi /MT /FC ", NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, pEnv, (currentPath + L"\\EACHide\\").c_str(), &si, &clProc))
	//	{
	//		m_hreadDataFromExtProgram = CreateThread(0, 0, readDataFromExtProgram, NULL, 0, NULL);
	//		WaitForSingleObject(clProc.hProcess, INFINITE);
	//	}
	//	else {
	//		cout << "msvc failed: " << GetLastError() << endl;
	//	}
	//	DWORD exit_code = 0;
	//	if (GetExitCodeProcess(clProc.hProcess, &exit_code)) {
	//		cout << "Exit: " << hex << exit_code << dec << endl;
	//	}
	//	else {
	//		cout << "Exit error: " << hex << GetLastError() << dec << endl;
	//	}

	//}

	cout << endl;
	{

		Function* GetAsyncKeyStateFunc = GetFunctionByName(GetAsyncKeyStateFuncName);
		if (GetAsyncKeyStateFunc) {
			char* funcPtr = exeFile + RVA2Offset(GetAsyncKeyStateFunc->RVA);
			{ // save rcx
				char code[] = { 0x49, 0x89, 0xCF, 0x53, 0xEB, 0x02, 0xEB, 0xF8 };
				memcpy(funcPtr - sizeof(code) + 2, &code, sizeof(code));
			}

			int firstNop = 0;
			uint64_t firstNopOffset = 0;
			int lastNop = 0;
			uint64_t lastNopOffset;
			uint64_t offset = 0;
			for (int i = 0; i < GetAsyncKeyStateFunc->instructions.size() - 1; i++) {
				auto inst = GetAsyncKeyStateFunc->instructions[i];
				auto nextInst = GetAsyncKeyStateFunc->instructions[i + 1];
				if (inst.info.opcode == 0x90) {
					if (firstNop == 0) {
						firstNop = i;
						firstNopOffset = offset;
					}

					if (nextInst.info.opcode != 0x90) {
						lastNop = i;
						lastNopOffset = offset + inst.info.length;
						break;
					}
				}
				offset += inst.info.length;
			}

			*(short*)(funcPtr + firstNopOffset) = 0x25FF;
			*(int*)(funcPtr + firstNopOffset + 2) = 0;

			offset = 0;
			for (int i = 0; i < GetAsyncKeyStateFunc->instructions.size(); i++) {
				auto inst = GetAsyncKeyStateFunc->instructions[i];
				XEDPARSE xed;
				memset(&xed, 0, sizeof(xed));
				xed.x64 = true;
				if (string(inst.text).find("0x11111111") != string::npos) {
					strcpy(xed.instr, ReplaceAll(inst.text, "0x11111111", "0x" + to_hex(lastNopOffset)).c_str());
					if (XEDParseAssemble(&xed)) {
						memset(funcPtr + offset, 0x90, inst.info.length);
						memcpy(funcPtr + offset, &xed.dest, xed.dest_size);
					}
					else {
						// cancel getasynckeystate
					}
				}
				else if (string(inst.text).find("0x22222222") != string::npos) {
					strcpy(xed.instr, ReplaceAll(inst.text, "0x22222222", "0x" + to_hex(firstNopOffset + 6)).c_str());
					if (XEDParseAssemble(&xed)) {
						memset(funcPtr + offset, 0x90, inst.info.length);
						memcpy(funcPtr + offset, &xed.dest, xed.dest_size);
					}
					else {
						// cancel getasynckeystate
					}
				}
				else if (string(inst.text).find("0x9999999") != string::npos) {
					auto str = to_hex(GetAsyncKeyStateFunc->Size);
					strcpy(xed.instr, ReplaceAll(inst.text, "0x9999999", "0x" + str).c_str());
					if (XEDParseAssemble(&xed)) {
						memset(funcPtr + offset, 0x90, inst.info.length);
						memcpy(funcPtr + offset, &xed.dest, xed.dest_size);
					}
					else {
						// cancel getasynckeystate
					}
				}
				else if (inst.info.mnemonic == ZYDIS_MNEMONIC_XOR && inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && inst.operands[0].reg.value == ZYDIS_REGISTER_EAX && inst.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && inst.operands[1].reg.value == ZYDIS_REGISTER_EAX) { // remove xor eax, eax
					memset(funcPtr + offset, 0x90, inst.info.length);
				}
				offset += inst.info.length;
			}
		}

		for (auto [iRVA, instructions] : instructionsToReplace) {
			for (auto inst : instructions) {
				Function* func = inst.function;
				if (GetAsyncKeyStateFunc && inst.type == ReplaceInstructionType::GetAsyncKeyState) {
					ZydisEncoderRequest req;
					memset(&req, 0, sizeof(req));

					req.mnemonic = ZYDIS_MNEMONIC_CALL;
					req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
					req.operand_count = 1;
					req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

					uint32_t currentRVA = func->RVA + inst.offset;
					int callFunction = GetAsyncKeyStateFunc->RVA - currentRVA - 5;

					req.operands[0].imm.u = callFunction;

					ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
					ZyanUSize encoded_length = sizeof(encoded_instruction);

					if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
					{
						cout << dye::light_red("Failed") << " to replace " << dye::yellow("GetAsyncKeyState") << " function" << endl;
						continue;
					}

					char* dest = exeFile + RVA2Offset(func->RVA + inst.offset);
					memset(dest, 0x90, inst.i.info.length);
					memcpy(dest, &encoded_instruction, encoded_length);

					cout << " - [" << dye::aqua("GetAsyncKeyState") << "] - Success replaced call in " << dye::light_aqua(func->Name) << "!" << endl;
					replaced++;
				}
				else if (inst.type == ReplaceInstructionType::GetModuleHandle) { // GetModuleHandle					
					{
						string newFuncName = "_" + hashString(inst.getAsyncKeyState.moduleName);
						if (Function* newFunction = GetFunctionByName(newFuncName)) { // Replacing

							ZydisEncoderRequest req;
							memset(&req, 0, sizeof(req));

							req.mnemonic = ZYDIS_MNEMONIC_CALL;
							req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
							req.operand_count = 1;
							req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

							uint32_t currentRVA = func->RVA + inst.offset;
							int callFunction = newFunction->RVA - currentRVA - 5;

							req.operands[0].imm.u = callFunction;

							ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
							ZyanUSize encoded_length = sizeof(encoded_instruction);

							if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
							{
								cout << dye::light_red("Failed") << " to generate " << dye::yellow(newFuncName) << " function" << endl;
								continue;
							}

							char* dest = exeFile + RVA2Offset(func->RVA + inst.offset);
							memset(dest, 0x90, inst.i.info.length);
							memcpy(dest, &encoded_instruction, encoded_length);

							cout << " - [" << dye::aqua("GetModuleHandle") << "]  - Success replaced call " << dye::light_green(newFuncName) << " function in " << dye::light_aqua(func->Name) << "!" << endl;
							replaced++;
						}
					}
				}
			}
		}

		if (replaced == haveToReplace) {
			cout << endl << hue::black_on_green;
		}
		else {
			cout << endl << hue::black_on_red;
		}

		cout << "Complete (" << replaced << "/" << haveToReplace << ")" << hue::reset << endl;

	}
	if (fs::exists(newExeFileName))
		fs::remove(newExeFileName);
	WriteToFile(newExeFileName, exeFile, exeFileSize);
	return 0;
}