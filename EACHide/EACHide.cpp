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

static char* ReadAllBytes(wstring filename, int* read)
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

class AddedFunction {
public:
	string Name;
	uint32_t RVA;
	uint32_t Size;
};

class Function {
public:
	enum class Type {
		Public,
		Global,
		Module
	};

	string Name;
	uint32_t RVA;
	uint32_t Size;
	Type FuncType;
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

string hashString(string str, int size = 4) {
	size /= 2;
	string temp;
	if (str.size() < size) {
		temp = str;
		for (int i = str.size(); i < size; i++) {
			temp += "\0";
		}
	}
	else {
		temp = string(str, 0, size);
	}
	string result = "";

	for (int i = 0; i < str.size() || i < size; i++) {
		temp[i % temp.size()] += str[i % str.size()];
	}

	for (int i = 0; i < temp.size(); i++) {
		result += to_hex((char)temp[i]);
	}


	return result;
}

std::string ReplaceAll(std::string str, const std::string& from = "", const std::string& to = "") {
	if (from == "" && to == "") {
		string resultStr = "";
		for (int i = 0; i < str.size(); i++) {
			if (std::isdigit((unsigned char)str[i]) || std::ispunct((unsigned char)str[i]) || std::isalpha((unsigned char)str[i]))
			{
				resultStr += str[i];
			}
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
		if (!bSuccess || dwRead == 0)
			continue;

		cout << ReplaceAll(string(chBuf, dwRead), "\n", "\n - ");

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
	int leaInstructionPlace = 0;
	ZydisDisassembledInstruction* leaInstruction = nullptr;
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

std::vector<Function> o_Functions;
std::vector<Function> c_Functions;
PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* o_Sections;
PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* c_Sections;
PIMAGE_SECTION_HEADER newSectionHeader;

PDB::IMAGE_SECTION_HEADER* GetSectionByName(std::string name) {
	for (auto section : *o_Sections) {
		if (string((char*)section.Name) == name) {
			return &section;
		}
	}
	return nullptr;
}

PDB::IMAGE_SECTION_HEADER* GetSectionByRVA(uint32_t rva, PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* sections = nullptr) {
	for (auto section : sections ? *sections : *o_Sections) {
		if (rva > section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
			return &section;
		}
	}
	return nullptr;
}

PDB::IMAGE_SECTION_HEADER* GetSectionByOffset(uint32_t offset, PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* sections = nullptr) {
	for (auto section : sections ? *sections : *o_Sections) {
		if (offset > section.PointerToRawData && offset < section.PointerToRawData + section.SizeOfRawData) {
			return &section;
		}
	}
	return nullptr;
}


uint32_t RVA2Offset(uint32_t rva, PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* sections = nullptr) {
	if (newSectionHeader && !sections) // newSectionHeader not supposed to be null, but who knows
		if (rva > newSectionHeader->VirtualAddress && rva < newSectionHeader->VirtualAddress + newSectionHeader->Misc.VirtualSize) {
			return rva - newSectionHeader->VirtualAddress + newSectionHeader->PointerToRawData;
		}
	auto section = GetSectionByRVA(rva, sections);
	if (!section)
		return 0;
	return rva - section->VirtualAddress + section->PointerToRawData;
}

uintptr_t Offset2RVA(uint32_t offset, PDB::ArrayView<PDB::IMAGE_SECTION_HEADER>* sections = nullptr) {
	if (newSectionHeader && !sections) // newSectionHeader not supposed to be null, but who knows
		if (offset > newSectionHeader->PointerToRawData && offset < newSectionHeader->PointerToRawData + newSectionHeader->SizeOfRawData) {
			return offset + newSectionHeader->VirtualAddress - newSectionHeader->PointerToRawData;
		}
	auto section = GetSectionByOffset(offset, sections);
	if (!section)
		return 0;
	return offset + section->VirtualAddress - section->PointerToRawData;
}

//Function* GetFunctionByInstruction(const ZydisDisassembledInstruction& inst) {
//	for (auto& func : Functions) {
//		if (inst.runtime_address >= func.RVA && inst.runtime_address <= func.RVA + func.Size)
//			return &func;
//	}
//	return nullptr;
//}

Function* GetFunctionByName(string name, std::vector<Function>& functions, bool strict = false, bool first = false) {
	Function* found = nullptr;
	for (auto& func : functions) {
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

Function* GetFunctionByName(string name, bool strict = false, bool first = false) {
	return GetFunctionByName(name, o_Functions, strict, first);
}

Function* GetFunctionByRVA(uint32_t RVA, std::vector<Function>& functions, bool first = false) {
	Function* found = nullptr;
	for (auto& func : functions) {
		if (func.RVA == RVA)
		{
			found = &func;
			if (first)
				return found;
		}
	}
	return found;
}

Function* GetFunctionByRVA(uint32_t RVA, bool first = false) {
	return GetFunctionByRVA(RVA, o_Functions, first);
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

Function GetFunctionByRecord(const PDB::CodeView::DBI::Record* record, const PDB::ImageSectionStream& imageSectionStream, Function::Type funcType) {
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
	return Function{ name2, rva, size, funcType };
}

void dissasemble_function(char* exeFile, Function& func)
{
	uintptr_t FuncAddress = RVA2Offset(func.RVA);
	if (FuncAddress == 0)
		return;

	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;

	ZyanStatus zyanStatus;
	while (ZYAN_SUCCESS(zyanStatus = ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (uintptr_t)func.RVA + offset, (char*)(exeFile + FuncAddress + offset), func.Size - offset, &instruction)))
	{
		offset += instruction.info.length;
		func.instructions.push_back(instruction);
	}
}

void fix_function_calls(char* o_exeFile, Function& func, uint32_t oRVA) {
	for (auto& inst : func.instructions) {
		if (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
			int offset;
			if (inst.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
				offset = inst.operands[0].mem.disp.value;
			else if (inst.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				offset = inst.operands[0].imm.value.s;
			else
				continue;
			uint32_t oldRVA = oRVA + offset + inst.info.length + (inst.runtime_address - func.RVA);
			Function* oldFunc = GetFunctionByRVA(oldRVA, c_Functions);
			if (!oldFunc)
				continue;

			//if (oldFunc->Name == "__security_check_cookie") // fix this // fixed with /GS- and removing /sdl
			//{
			//	memset(o_exeFile + RVA2Offset(inst.runtime_address), 0x90, inst.info.length);
			//	continue;
			//}

			Function* newFunc = GetFunctionByName(oldFunc->Name, true, true);
			if (!newFunc)
				continue;

			int newOffset = newFunc->RVA - inst.runtime_address - inst.info.length;
			auto instAddr = o_exeFile + RVA2Offset(inst.runtime_address);
			*(int*)(instAddr + inst.info.length - sizeof(int)) = newOffset;

			//inst.operands[0].mem.disp.value = newFunc->RVA - inst.runtime_address - inst.info.length;

			//ZydisEncoderRequest req;
			//memset(&req, 0, sizeof(req));
			//if (ZYAN_STATUS_CODE(ZydisEncoderDecodedInstructionToEncoderRequest(&inst.info, inst.operands, inst.info.operand_count, &req))) { // ZYAN_STATUS_INVALID_ARGUMENT
			//	
			//	continue;
			//}
			//ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
			//ZyanUSize encoded_length = sizeof(encoded_instruction);

			//if (ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length))) {
			//	memcpy(o_exeFile + RVA2Offset(inst.runtime_address), encoded_instruction, encoded_length); // if wrong length, you will see in debugger wrong instructs after
			//}
			continue;
		}
	}
}

void CopyFunction(char* o_exeFile, char* c_exeFile, Function* oldFunc, uint32_t& offset, uint32_t& backwardOffset, std::map<uint32_t, Function>& addedFunctions) {
	memcpy(o_exeFile + newSectionHeader->PointerToRawData + offset, c_exeFile + RVA2Offset(oldFunc->RVA, c_Sections), oldFunc->Size);
	auto RVA = Offset2RVA(newSectionHeader->PointerToRawData + offset);

	cout << " - " << dye::light_green(oldFunc->Name) << " inserted at " << dye::white("0x") << dye::white(RVA) << endl;

	Function newGetAsyncKeyState;
	newGetAsyncKeyState.FuncType = oldFunc->FuncType;
	newGetAsyncKeyState.Name = oldFunc->Name;
	newGetAsyncKeyState.RVA = RVA;
	newGetAsyncKeyState.Size = oldFunc->Size;
	dissasemble_function(o_exeFile, newGetAsyncKeyState);

	o_Functions.push_back(newGetAsyncKeyState);
	addedFunctions[oldFunc->RVA] = newGetAsyncKeyState;
	offset += oldFunc->Size + 8 + oldFunc->Size % 16;
}

void InsertByteFunction(char* o_exeFile, string funcName, unsigned char* code, uint32_t codeSize, uint32_t& offset) {
	memcpy(o_exeFile + newSectionHeader->PointerToRawData + offset, code, codeSize);

	auto RVA = Offset2RVA(newSectionHeader->PointerToRawData + offset);
	Function func;
	func.FuncType = Function::Type::Global;
	func.Name = funcName;
	func.RVA = RVA;
	func.Size = codeSize;
	o_Functions.push_back(func);

	offset += codeSize + 8 + codeSize % 16;
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
	string exeName = fs::path(exeFileName).filename().string();
	string fileExtension = exeFileName.substr(exeFileName.size() - 3);
	string newExeFileName = string(argv[1]);
	newExeFileName = newExeFileName.substr(0, newExeFileName.size() - 4) + "_new." + fileExtension;
	string pdbFileName = string(argv[1]);
	pdbFileName.replace(pdbFileName.end() - 3, pdbFileName.end(), "pdb");

	cout.setf(ios::left);
	int width = 15;

	string trashStr = ReplaceAll("sdfsdaas");

	cout << hue::light_blue << endl;
	cout << " _____ " << hue::white << " ___ " << hue::light_blue << " _____  _   _ _     _      " << endl;
	cout << "|  ___|" << hue::white << "/ _ \\" << hue::light_blue << "/  __ \\| | | (_)   | |     " << endl;
	cout << "| |__ " << hue::white << "/ /_\\ \\" << hue::light_blue << " /  \\/| |_| |_  __| | ___ " << endl;
	cout << "|  __|" << hue::white << "|  _  |" << hue::light_blue << " |    |  _  | |/ _` |/ _ \\" << endl;
	cout << "| |___" << hue::white << "| | | | " << hue::light_blue << "\\__/\\| | | | | (_| |  __/" << endl;
	cout << "\\____/" << hue::white << "\\_| |_/" << hue::light_blue << "\\____/\\_| |_/_|\\__,_|\\___|" << endl;
	cout << endl;
	cout << endl;
	cout << hue::reset;


	cout << setw(width) << "Input file" << ": " << exeFileName << endl;
	cout << setw(width) << "Pdb file" << ": " << pdbFileName << endl;
	cout << setw(width) << "Output file" << ": " << newExeFileName << endl;
	cout << endl;

	if (!fs::exists(exeFileName) || !fs::exists(pdbFileName))
		return -1;

	int o_pdbFileSize = 0;
	char* o_pdbFile = ReadAllBytes(pdbFileName, &o_pdbFileSize);

	if (IsError(PDB::ValidateFile(o_pdbFile)))
		return -1;

	int o_exeFileSize = 0;
	char* o_exeFile = ReadAllBytes(exeFileName, &o_exeFileSize);

	const PDB::RawFile o_rawPdbFile = PDB::CreateRawFile(o_pdbFile);
	const PDB::DBIStream o_dbiStream = PDB::CreateDBIStream(o_rawPdbFile);

	const PDB::ModuleInfoStream o_moduleInfoStream = o_dbiStream.CreateModuleInfoStream(o_rawPdbFile);
	const PDB::CoalescedMSFStream o_symbolRecordStream = o_dbiStream.CreateSymbolRecordStream(o_rawPdbFile);
	const PDB::PublicSymbolStream o_publicSymbolStream = o_dbiStream.CreatePublicSymbolStream(o_rawPdbFile);
	const PDB::ImageSectionStream o_imageSectionStream = o_dbiStream.CreateImageSectionStream(o_rawPdbFile);
	auto sections = o_imageSectionStream.GetImageSections();
	o_Sections = &sections;

	{
		cout << "[PE Header]" << endl;

		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)o_exeFile;
		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(o_exeFile + dos_header->e_lfanew);
		PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(o_exeFile + dos_header->e_lfanew + sizeof(nt_header->Signature));
		PIMAGE_OPTIONAL_HEADER optional_header = (PIMAGE_OPTIONAL_HEADER)(o_exeFile + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));
		if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) // Only X64
			return -1;
		//file_header->NumberOfSections

		newSectionHeader = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(nt_header)) + file_header->NumberOfSections;
		memset(newSectionHeader, 0, sizeof(PIMAGE_SECTION_HEADER));
		PIMAGE_SECTION_HEADER lastSection = newSectionHeader - 1;

		char newSectionName[6];
		hashString(exeName, 6).copy(&newSectionName[0], 6);
		newSectionHeader->Name[0] = '.';
		memcpy(&newSectionHeader->Name[1], newSectionName, 6);
		auto secAlign = optional_header->SectionAlignment;
		newSectionHeader->PointerToRawData = o_exeFileSize;
		newSectionHeader->Characteristics = 0x60000020;
		newSectionHeader->SizeOfRawData = 0x1000;
		newSectionHeader->Misc.VirtualSize = newSectionHeader->SizeOfRawData;
		newSectionHeader->VirtualAddress = (uint32_t)(ceil((lastSection->VirtualAddress + lastSection->Misc.VirtualSize) / (double)optional_header->SectionAlignment) * optional_header->SectionAlignment);
		file_header->NumberOfSections++;

		auto additionalSize = (uint32_t)(ceil(newSectionHeader->SizeOfRawData / (double)optional_header->SectionAlignment) * optional_header->SectionAlignment);
		optional_header->SizeOfImage = optional_header->SizeOfImage + additionalSize;

		newSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)newSectionHeader - (uintptr_t)o_exeFile);
		o_exeFile = (char*)realloc(o_exeFile, o_exeFileSize + additionalSize);
		newSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)newSectionHeader + (uintptr_t)o_exeFile);
		memset(o_exeFile + o_exeFileSize, 0x00, additionalSize);
		o_exeFileSize = o_exeFileSize + additionalSize;
		cout << endl;
	}

	cout << "[Analyzing pdb file]" << endl;
	{
		const PDB::ArrayView<PDB::HashRecord> hashRecords = o_publicSymbolStream.GetRecords();
		const size_t count = hashRecords.GetLength();

		for (const PDB::HashRecord& hashRecord : hashRecords)
		{
			const PDB::CodeView::DBI::Record* record = o_publicSymbolStream.GetRecord(o_symbolRecordStream, hashRecord);
			if (Function f = GetFunctionByRecord(record, o_imageSectionStream, Function::Type::Global); f.RVA != 0)
				o_Functions.push_back(f);
		}
	}
	const PDB::GlobalSymbolStream globalSymbolStream = o_dbiStream.CreateGlobalSymbolStream(o_rawPdbFile);
	{
		const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();
		const size_t count = hashRecords.GetLength();

		for (const PDB::HashRecord& hashRecord : hashRecords)
		{
			const PDB::CodeView::DBI::Record* record = globalSymbolStream.GetRecord(o_symbolRecordStream, hashRecord);

			if (Function f = GetFunctionByRecord(record, o_imageSectionStream, Function::Type::Public); f.RVA != 0)
				o_Functions.push_back(f);
		}
	}
	{
		const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = o_moduleInfoStream.GetModules();

		for (const PDB::ModuleInfoStream::Module& module : modules)
		{
			if (!module.HasSymbolStream())
			{
				continue;
			}

			const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(o_rawPdbFile);
			moduleSymbolStream.ForEachSymbol([&o_imageSectionStream](const PDB::CodeView::DBI::Record* record)
				{
					if (Function f = GetFunctionByRecord(record, o_imageSectionStream, Function::Type::Module); f.RVA != 0)
						o_Functions.push_back(f);
				});
		}
	}

	std::map<uint32_t, FunctionToReplace> FunctionsToReplace;
	for (auto func : o_Functions) {
		if (func.FuncType != Function::Type::Global)
			continue;
		if (func.Name.find("__imp_GetModuleHandleW") != string::npos) {
			FunctionsToReplace[func.RVA] = FunctionToReplace{ "__imp_GetModuleHandleW", func.RVA, func, ReplaceInstructionType::GetModuleHandle };
			cout << " - Found " << dye::light_red(func.Name) << " at 0x" << hex << func.RVA << endl;
		}
		else if (func.Name.find("__imp_GetAsyncKeyState") != string::npos) {
			FunctionsToReplace[func.RVA] = FunctionToReplace{ "__imp_GetAsyncKeyState", func.RVA, func, ReplaceInstructionType::GetAsyncKeyState };
			cout << " - Found " << dye::light_red(func.Name) << " at 0x" << hex << func.RVA << endl;
		}
	}

	/////
	for (auto& func : o_Functions) {
		dissasemble_function(o_exeFile, func);
	}

	int haveToReplace = 0;
	int replaced = 0;
	std::map<uint32_t, std::vector<ReplaceInstruction>> instructionsToReplace;
	for (int b = 0; b < o_Functions.size(); b++) {
		//if (o_Functions[b].FuncType == Function::Type::Global)
		//	continue;
		ZyanUSize offset = 0;
		for (unsigned long long i = 0; i < o_Functions[b].instructions.size(); i++) {
			auto instruction = o_Functions[b].instructions[i];

			if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
				if (instruction.info.opcode == 0xFF && instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
					uintptr_t calledFunction = o_Functions[b].RVA + offset + instruction.operands[0].mem.disp.value + instruction.info.length;
					for (auto [fRVA, rFunc] : FunctionsToReplace) {
						if (fRVA == calledFunction) {
							ReplaceInstruction rep;
							rep.function = &o_Functions[b];
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
				int leaInstructionPlace = 0;
				ZydisDisassembledInstruction* leaInstruction = nullptr;
				{
					for (int i = inst.instructionPlace - 1; i >= 0; i--) {
						auto instr = func->instructions[i];
						if (instr.info.mnemonic == ZYDIS_MNEMONIC_XOR && (instr.operands[0].reg.value == ZYDIS_REGISTER_RCX || instr.operands[1].reg.value == ZYDIS_REGISTER_ECX))
							break;
						if (instr.info.mnemonic == ZYDIS_MNEMONIC_LEA) {
							if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instr.operands[0].reg.value == ZYDIS_REGISTER_RCX && instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
								wchar_t* str = (wchar_t*)(o_exeFile + RVA2Offset(instr.runtime_address + instr.operands[1].mem.disp.value + instr.info.length));
								int strLen = wcslen(str);
								if (strLen > 4) {
									apiSet = wcsstr(str, L"api") == str || wcsstr(str, L"ext") == str;
									leaInstructionPlace = i;
									leaInstruction = &func->instructions[i];

									//
									//memset(o_exeFile + RVA2Offset(leaInstruction->runtime_address), 0x90, leaInstruction->info.length);
									//

									int offset = 0;
									for (int i = 0; i < leaInstructionPlace; i++) {
										offset += func->instructions[i].info.length;
									}

									char* pModuleName = (char*)malloc(128);
									memset(pModuleName, 0, 128);
									wchar_t* wModuleName = (wchar_t*)(o_exeFile + RVA2Offset(func->RVA + offset + leaInstruction->info.length + leaInstruction->operands[1].mem.disp.value));
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
				inst.getAsyncKeyState = GetAsyncKeyStateType{ apiSet, moduleName, leaInstructionPlace, leaInstruction };
				break;
			}
		}
	}

	//for (auto [iRVA, instructions] : instructionsToReplace) {
	//	printf("\n%s\n", FunctionsToReplace[iRVA].Name.c_str());
	//	for (auto inst : instructions)
	//		cout << "  " << setfill('0') << setw(8) << hex << inst.i.runtime_address << dec << ": " << dye::light_aqua(inst.function->Name) << endl;
	//}

	cout << endl << "[Genereting functions]" << endl;

	string GetAsyncKeyStateFuncName = "_" + hashString("EACGetAsyncKeyState") + "_" + hashString(exeName);
	{ // Generating
		wstring resultFileName = currentPath + L"\\EACHide\\EACHide.cpp";
		fs::create_directories(fs::path(resultFileName).parent_path());
		if (fs::exists(resultFileName))
			fs::remove(resultFileName);
		//	WriteToFile(resultFileName, "#pragma once");	
		WriteToFile(resultFileName, "#include <Windows.h>");
		WriteToFile(resultFileName, "#include \"LazyImporter.hpp\"");
		WriteToFile(resultFileName, "");

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
		cout << endl;
	}

	// Compiling code
	{
		cout << "[Compiling code]" << endl;
		wchar_t* pEnv = (wchar_t*)L"";
		pEnv = GetEnvironmentStringsW();
		HANDLE hToken = NULL;
		BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);
		CreateEnvironmentBlock((void**)&pEnv, hToken, TRUE);

		wstring include = L"";
		include += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\include" + L";";
		include += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\ATLMFC\\include" + L";";
		include += vsPath + L"\\VC\\Auxiliary\\VS\\include" + L";";
		include += windowsKitPath + L"\\include\\" + winSdk + L"\\ucrt" + L";";
		include += windowsKitPath + L"\\include\\" + winSdk + L"\\um" + L";";
		include += windowsKitPath + L"\\include\\" + winSdk + L"\\shared" + L";";
		include += windowsKitPath + L"\\include\\" + winSdk + L"\\winrt" + L";";
		include += windowsKitPath + L"\\include\\" + winSdk + L"\\cppwinrt" + L"";
		pEnv = appendToEnvironmentBlock(pEnv, L"INCLUDE", include.c_str());

		wstring lib = L"";
		lib += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\ATLMFC\\lib\\x64" + L";";
		lib += vsPath + L"\\VC\\Tools\\MSVC\\" + msvc + L"\\lib\\x64" + L";";
		//lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\shared" + L";";
		lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\ucrt\\x64" + L";";
		lib += windowsKitPath + L"\\lib\\" + winSdk + L"\\um\\x64" + L";";
		pEnv = appendToEnvironmentBlock(pEnv, L"LIB", lib.c_str());

		//cout << endl << "Compiling code" << endl;

		STARTUPINFO si;
		PROCESS_INFORMATION clProc;
		SECURITY_ATTRIBUTES saAttr;

		memset(&saAttr, 0, sizeof(saAttr));
		saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		saAttr.bInheritHandle = TRUE;
		saAttr.lpSecurityDescriptor = NULL;

		if (!CreatePipe(&m_hChildStd_OUT_Rd, &m_hChildStd_OUT_Wr, &saAttr, 0))
		{
			// log error
			return HRESULT_FROM_WIN32(GetLastError());
		}

		if (!SetHandleInformation(m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		{
			// log error
			return HRESULT_FROM_WIN32(GetLastError());
		}

		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.hStdError = m_hChildStd_OUT_Wr;
		si.hStdOutput = m_hChildStd_OUT_Wr;
		si.dwFlags |= STARTF_USESTDHANDLES;

		memset(&clProc, 0, sizeof(clProc));

		if (CreateProcessW((LPWSTR)clPath.c_str(), (LPWSTR)L" EACHide.cpp /nologo /permissive- /GS- /GL /Gy /Zc:wchar_t /Z7 /Gm- /Ot /O2 /Zc:inline /fp:precise /Zc:forScope /Gd /Oi /MT /FC ", NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, pEnv, (currentPath + L"\\EACHide\\").c_str(), &si, &clProc))
		{
			cout << " - "; // lifehack
			m_hreadDataFromExtProgram = CreateThread(0, 0, readDataFromExtProgram, NULL, 0, NULL);
			WaitForSingleObject(clProc.hProcess, INFINITE);
		}
		else {
			cout << "msvc failed: " << GetLastError() << endl;
		}
		DWORD exit_code = 0;
		if (GetExitCodeProcess(clProc.hProcess, &exit_code)) {
			if (exit_code == 0) {
				cout << dye::black_on_green(" Compilation success ") << endl;
			}
			else {
				cout << hue::black_on_red << " Compilation failed: " << exit_code << " " << hue::reset << endl;
#ifdef _DEBUG // continue when file is open
				if (exit_code != 2)
					return exit_code;
#else
				return exit_code;
#endif
			}

		}
		else {
			cout << hue::black_on_red << " Failed to run MSVC: " << GetLastError() << " " << hue::reset << endl;
			return GetLastError();
		}

		cout << endl;
	}

	{
		cout << "[Analyzing compiled code]" << endl;

		int c_pdbFileSize = 0;
		char* c_pdbFile = ReadAllBytes(currentPath + L"\\EACHide\\EACHide.pdb", &c_pdbFileSize);

		if (IsError(PDB::ValidateFile(c_pdbFile)))
			return -1;

		int c_exeFileSize = 0;
		char* c_exeFile = ReadAllBytes(currentPath + L"\\EACHide\\EACHide.exe", &c_exeFileSize);

		const PDB::RawFile c_rawPdbFile = PDB::CreateRawFile(c_pdbFile);
		const PDB::DBIStream c_dbiStream = PDB::CreateDBIStream(c_rawPdbFile);

		const PDB::ModuleInfoStream c_moduleInfoStream = c_dbiStream.CreateModuleInfoStream(c_rawPdbFile);
		const PDB::CoalescedMSFStream c_symbolRecordStream = c_dbiStream.CreateSymbolRecordStream(c_rawPdbFile);
		const PDB::PublicSymbolStream c_publicSymbolStream = c_dbiStream.CreatePublicSymbolStream(c_rawPdbFile);
		const PDB::ImageSectionStream c_imageSectionStream = c_dbiStream.CreateImageSectionStream(c_rawPdbFile);
		auto sections = c_imageSectionStream.GetImageSections();
		c_Sections = &sections;

		{
			const PDB::ArrayView<PDB::HashRecord> hashRecords = c_publicSymbolStream.GetRecords();
			const size_t count = hashRecords.GetLength();

			for (const PDB::HashRecord& hashRecord : hashRecords)
			{
				const PDB::CodeView::DBI::Record* record = c_publicSymbolStream.GetRecord(c_symbolRecordStream, hashRecord);
				if (Function f = GetFunctionByRecord(record, c_imageSectionStream, Function::Type::Global); f.RVA != 0)
					c_Functions.push_back(f);
			}
		}
		const PDB::GlobalSymbolStream globalSymbolStream = c_dbiStream.CreateGlobalSymbolStream(c_rawPdbFile);
		{
			const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();
			const size_t count = hashRecords.GetLength();

			for (const PDB::HashRecord& hashRecord : hashRecords)
			{
				const PDB::CodeView::DBI::Record* record = globalSymbolStream.GetRecord(c_symbolRecordStream, hashRecord);

				if (Function f = GetFunctionByRecord(record, c_imageSectionStream, Function::Type::Public); f.RVA != 0)
					c_Functions.push_back(f);
			}
		}
		{
			const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = c_moduleInfoStream.GetModules();

			for (const PDB::ModuleInfoStream::Module& module : modules)
			{
				if (!module.HasSymbolStream())
				{
					continue;
				}

				const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(c_rawPdbFile);
				moduleSymbolStream.ForEachSymbol([&c_imageSectionStream](const PDB::CodeView::DBI::Record* record)
					{
						if (Function f = GetFunctionByRecord(record, c_imageSectionStream, Function::Type::Module); f.RVA != 0)
							c_Functions.push_back(f);
					});
			}
		}

		cout << "[Inserting compiled code]" << endl;

		uint32_t offset = 32;
		uint32_t backwardOffset = 32;
		std::map<uint32_t, Function> addedFunctions;
		{
			unsigned char getAsyncKeyStateFunc[] = {
				0x49, 0x89, 0xCA,
				0xB8, 0x3F, 0x10, 0x00, 0x00, //getasynckeystate
				0x0F, 0x05,  //syscall
				0xc3 // ret
			};
			InsertByteFunction(o_exeFile, GetAsyncKeyStateFuncName, getAsyncKeyStateFunc, sizeof(getAsyncKeyStateFunc), offset);			
		}
		{
			for (auto [iRVA, instructions] : instructionsToReplace) {
				for (auto inst : instructions) {
					Function* func = inst.function;
					if (inst.type == ReplaceInstructionType::GetModuleHandle) {
						string newFuncName = "_" + hashString(inst.getAsyncKeyState.moduleName);
						if (!GetFunctionByName(newFuncName))
							if (Function* newFunction = GetFunctionByName(newFuncName, c_Functions)) { // Replacing

								CopyFunction(o_exeFile, c_exeFile, newFunction, offset, backwardOffset, addedFunctions);

							}
					}
				}
			}
		}

		for (auto& func : c_Functions) {
			if (func.Name.find("VirtualProtect") != string::npos)
				printf("");
		}

		for (auto& [oRVA, func] : addedFunctions) {
			fix_function_calls(o_exeFile, func, oRVA);
		}
		printf("");
	}

	cout << endl;
	{
		Function* GetAsyncKeyStateFunc = GetFunctionByName(GetAsyncKeyStateFuncName);
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

					char* dest = o_exeFile + RVA2Offset(func->RVA + inst.offset);
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

							char* dest = o_exeFile + RVA2Offset(func->RVA + inst.offset);
							memset(dest, 0x90, inst.i.info.length);
							memcpy(dest, &encoded_instruction, encoded_length);

							cout << " - [" << dye::aqua("GetModuleHandle") << "]  - Success replaced call " << dye::light_green(newFuncName) << " function in " << dye::light_aqua(func->Name) << "!" << endl;
							replaced++;
						}
					}
				}
			}
		}
	}
	if (fs::exists(newExeFileName))
		fs::remove(newExeFileName);
	WriteToFile(newExeFileName, o_exeFile, o_exeFileSize);

	if (replaced == haveToReplace) {
		cout << endl << hue::black_on_green << endl << endl;
	}
	else {
		cout << endl << hue::black_on_red << endl << endl;
	}

	cout << dec << "	Complete (" << replaced << "/" << haveToReplace << ")" << endl << hue::reset << endl;


#ifndef _DEBUG
	system("pause");
#endif
	return 0;
}
