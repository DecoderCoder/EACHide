#pragma once
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
};

enum class ReplaceInstructionType {
	GetModuleHandle,
	GetAsyncKeyState,
	VirtualProtect,
};

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
	uint32_t RVA;
	ReplaceInstructionType type;
	Function* function;

	GetAsyncKeyStateType getAsyncKeyState;
};

PDB_NO_DISCARD static bool IsError(PDB::ErrorCode errorCode);

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

static string hashString(string str, int size = 4) {
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

static std::string ReplaceAll(std::string str, const std::string& from = "", const std::string& to = "") {
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

wstring lowercase(const wstring& s)
{
	std::wstring str(s);
	std::transform(str.begin(), str.end(), str.begin(),
		[](wchar_t c) { return std::tolower(c); });
	return str;
}

static void WriteToFile(std::string FileName, std::string text) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::app);
	myfile << text << "\n";
	myfile.close();
}

static void WriteToFile(std::wstring FileName, std::string text) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::app);
	myfile << text << "\n";
	myfile.close();
}

static void WriteToFile(std::string FileName, char* file, size_t size) {
	std::ofstream myfile;
	myfile.open(FileName, std::ios_base::out | std::ios::binary);
	myfile.write(file, size);
	myfile.close();
}


static wchar_t* appendToEnvironmentBlock(wchar_t* pEnvBlock, const wstring& varname, const wstring& varvalue)
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
}