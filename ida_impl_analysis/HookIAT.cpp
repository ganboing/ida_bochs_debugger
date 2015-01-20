#include <Windows.h>
#include <DbgHelp.h>
#include <map>
#include <set>
#include <string>
#include "DbgPrintf.h"
#include "HookIAT.h"

PULONG_PTR GetIatSlotAddr(HMODULE Module, LPCSTR ExternModuleName, LPCSTR ExportName)
{
	ULONG ImportDirSize;
	PIMAGE_IMPORT_DESCRIPTOR ImportDir = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(Module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportDirSize, NULL);
	if (ImportDir == NULL)
	{
		return NULL;
	}	
	for (SIZE_T i = 0; sizeof(IMAGE_IMPORT_DESCRIPTOR) * (i + 1) < ImportDirSize; ++i)
	{
		LPCSTR DllName = (LPCSTR)((char*)Module + ImportDir[i].Name);
		if (!stricmp(DllName, ExternModuleName))
		{
			PIMAGE_THUNK_DATA LookupTable = (PIMAGE_THUNK_DATA)((char*)Module + ImportDir[i].OriginalFirstThunk);
			PIMAGE_THUNK_DATA ImportTable = (PIMAGE_THUNK_DATA)((char*)Module + ImportDir[i].FirstThunk);
			for (SIZE_T j = 0; LookupTable[j].u1.AddressOfData != NULL; ++j)
			{
				if (!IMAGE_SNAP_BY_ORDINAL(LookupTable[j].u1.Ordinal))
				{
					PIMAGE_IMPORT_BY_NAME FuncHintName = (PIMAGE_IMPORT_BY_NAME)((char*)Module + LookupTable[j].u1.AddressOfData);
					if (!strcmp(ExportName, (LPCSTR)FuncHintName->Name))
					{
						return &ImportTable[j].u1.Function;
					}
				}
			}
			break;
		}
	}
	return NULL;
}

void HookImpCalls(HMODULE Module, LPCSTR ExternModuleName, const FuncDesc_t* NewFuncs, SlotDesc_t* OrigFuncs, BOOL Debug, const LPCSTR* FuncExcluded)
{
	typedef ::std::map< ::std::string, LPVOID> FuncMap_t;
	typedef ::std::set< ::std::string> FuncSet_t;
	FuncMap_t FuncsToHook;
	FuncSet_t FuncsNotToHook;
	for (const FuncDesc_t* i = NewFuncs; i->Name != NULL; ++i)
	{
		FuncsToHook.insert(FuncMap_t::value_type(::std::string(i->Name), i->Func));
	}
	if (Debug && FuncExcluded)
	{
		for (const LPCSTR* i = FuncExcluded; *i; ++i)
		{
			FuncsNotToHook.insert(*i);
			if (FuncsToHook.find(*i) != FuncsToHook.end())
			{
				DbgPrint("FUNCTION EXCLUDED is IN the Hook list!!! ");
			}
			DbgPrint("Function Excluded: %s\n", *i);
		}
	}
	for (FuncMap_t::iterator i = FuncsToHook.begin(), j = FuncsToHook.end(); i != j; ++i)
	{
		DbgPrint("Function To Hook: %s, NewAddr=%p from IAT of %p DLL is %s\n", (LPVCSTR)i->first.c_str(), i->second, Module, ExternModuleName);
	}
	ULONG ImportDirSize;
	PIMAGE_IMPORT_DESCRIPTOR ImportDir = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(Module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportDirSize, NULL);
	if (ImportDir == NULL)
	{
		DbgPrint("Import Directory Not found!\n");
		abort();
	}
	for (SIZE_T i = 0; sizeof(IMAGE_IMPORT_DESCRIPTOR) * (i + 1) < ImportDirSize; ++i)
	{
		LPCSTR DllName = (LPCSTR)((char*)Module + ImportDir[i].Name);
		if (!stricmp(DllName, ExternModuleName))
		{
			PIMAGE_THUNK_DATA LookupTable = (PIMAGE_THUNK_DATA)((char*)Module + ImportDir[i].OriginalFirstThunk);
			PIMAGE_THUNK_DATA ImportTable = (PIMAGE_THUNK_DATA)((char*)Module + ImportDir[i].FirstThunk);
			for (SIZE_T j = 0; LookupTable[j].u1.AddressOfData != NULL; ++j)
			{
				if (!IMAGE_SNAP_BY_ORDINAL(LookupTable[j].u1.Ordinal))
				{
					PIMAGE_IMPORT_BY_NAME FuncHintName = (PIMAGE_IMPORT_BY_NAME)((char*)Module + LookupTable[j].u1.AddressOfData);
					FuncMap_t::iterator p = FuncsToHook.find(::std::string((LPCSTR)FuncHintName->Name));
					if (p != FuncsToHook.end())
					{
						DbgPrint("hooking %s", (LPVCSTR)FuncHintName->Name);
						DWORD OldProt;
						OrigFuncs->Func = ImportTable[j].u1.Function;
						OrigFuncs->Slot = &ImportTable[j].u1.Function;
						DbgPrint(" IAT Slot=%p, Original Addr=%p\n", OrigFuncs->Slot, OrigFuncs->Func);
						++OrigFuncs;
						VirtualProtect(&ImportTable[j].u1.Function, sizeof(ULONG_PTR), PAGE_WRITECOPY, &OldProt);
						ImportTable[j].u1.Function = (ULONG_PTR)p->second;
						VirtualProtect(&ImportTable[j].u1.Function, sizeof(ULONG_PTR), PAGE_READONLY, &OldProt);
						FuncsToHook.erase(p);
					}
					else
					{
						if (Debug && FuncsNotToHook.find((LPCSTR)FuncHintName->Name) == FuncsNotToHook.end())
						{
							DbgPrint("%%%%%%%% Func \"%s\" not Hooked\n", (LPVCSTR)FuncHintName->Name);
						}
					}
				}
			}
			OrigFuncs->Slot = NULL;
			for (FuncMap_t::iterator j = FuncsToHook.begin(), k = FuncsToHook.end(); j != k; ++j)
			{
				DbgPrint("%s not hooked (export entry not found)\n", (LPVCSTR)j->first.c_str());
			}
			return;
		}
	}
	DbgPrint("Import Module not Found!\n");
	abort();
}

void RestoreImpCalls(const SlotDesc_t* OrigFuncs)
{
	for (; OrigFuncs->Slot; ++OrigFuncs)
	{
		DWORD OldProt;
		VirtualProtect(OrigFuncs->Slot, sizeof(ULONG_PTR), PAGE_WRITECOPY, &OldProt);
		*OrigFuncs->Slot = OrigFuncs->Func;
		VirtualProtect(OrigFuncs->Slot, sizeof(ULONG_PTR), PAGE_READONLY, &OldProt);
	}
}