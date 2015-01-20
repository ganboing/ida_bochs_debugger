#include <Windows.h>
#include <DbgHelp.h>
#include <map>
#include <string>
#include "DbgPrintf.h"
#include "HookIAT.h"

#include "global_win.h"
#include "BochsUserImplHook.h"
#include "IdaWllHook.h"
#include "exception_clause.h"

#pragma warning(push,3)
#include <ida.hpp>
#include <idd.hpp>
#include <loader.hpp>
#pragma warning(pop)
#include "global.h"

/*typedef ::std::pair<size_t, ::std::string> DllInfo_t;
typedef ::std::map<ULONG_PTR, DllInfo_t> DllDB_t;
static DllDB_t DllDB;
*/
static const char BochsUserStr[] = "bochs_user.plw";

namespace Kernel32_Hook{
	BOOL WINAPI FreeLibrary(HMODULE hModule)
	{
		DbgPrint("FreeLibrary: %p\n", hModule);
		BOOL ret = ::FreeLibrary(hModule);
		if (hModule == hBochsUserImpl)
		{
			DbgPrint("!!!! BochsUser Module Might Be unloaded\n");
			if (GetModuleHandle(BochsUserStr) == NULL)
			{
				DbgPrint("!!!! BochsUser Module IS unloaded, prepare to restore\n");
				//RestoreHallsFromIda();
				memset(&BochsDbgShadow, 0, sizeof(BochsDbgShadow));
				memset(&BochsPlgShadow, 0, sizeof(BochsPlgShadow));
				hBochsUserImpl = NULL;
				pBochsPlugin = NULL;
				pBochsDbg = NULL;
			}
		}
		return ret;
	}

	HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName)
	{
		static const ptrdiff_t BochsDbgRVA = 0x15bfd3d0 - 0x15bc0000;

		DbgPrint("LoadlibraryA: %s\n", (LPVCSTR)lpLibFileName);
		HMODULE ret = ::LoadLibraryA(lpLibFileName);
		if (ret)
		{
			DbgPrint(" @ %p\n", ret);
			HMODULE hBochsUserNew = GetModuleHandle("bochs_user.plw");
			if (hBochsUserNew == ret)
			{
				if (!hBochsUserImpl)
				{
					DbgPrint("@@@@ bohcs_user.plw detected, prepare to hook@@@@\n");
					hBochsUserImpl = ret;
					pBochsDbg = (debugger_t*)((char*)hBochsUserImpl + BochsDbgRVA);
					pBochsPlugin = (plugin_t*)::GetProcAddress(ret, "PLUGIN");
					if (!strcmp(pBochsDbg->name, "bochs"))
					{
						DbgPrint("@@@@ DBG STRUCTURE in bochs_user.plw has successfully been identified@@@@\n");
						DbgPrint("\tPLUGIN @%p, DBG@%p\n", pBochsPlugin, pBochsDbg);
						BochsUserImageSize = ImageNtHeader(hBochsUserImpl)->OptionalHeader.SizeOfImage;
						HookCallsToIdaWll();
						//HookCallsFromIda();
					}
					else
					{
						DbgPrint("@@@@ DBG STRUCTURE not found@@@@\n");
						abort();
					}
				}
				else if (hBochsUserNew == hBochsUserImpl)
				{
					DbgPrint("@@@@ bochs_user.plw referenced\n");
				}
				else
				{
					abort();
				}
			}
		}
		return ret;
	}

	HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName)
	{
		return ::LoadLibraryW(lpLibFileName);
	}

	HMODULE WINAPI LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		return ::LoadLibraryExA(lpLibFileName, hFile, dwFlags);
	}
	
	HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		return ::LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	}
}

static FuncDesc_t Hookers[] =
{
	{ "LoadLibraryA", &Kernel32_Hook::LoadLibraryA },
	{ "LoadLibraryW", &Kernel32_Hook::LoadLibraryW },
	{ "LoadLibraryExA", &Kernel32_Hook::LoadLibraryExA },
	{ "LoadLibraryExW", &Kernel32_Hook::LoadLibraryExW },
	{ "FreeLibrary", &Kernel32_Hook::FreeLibrary },
	{ NULL, NULL },
};

static SlotDesc_t Restorers_wll[_countof(Hookers)];
static SlotDesc_t Restorers_exe[_countof(Hookers)];

void HookKernel32Funcs()
{
	HookImpCalls(hIDA_EXE, "KERNEL32.DLL", Hookers, Restorers_exe);
	HookImpCalls(hIDA_wll, "KERNEL32.DLL", Hookers, Restorers_wll);
}

void RestoreKernel32Funcs()
{
	RestoreImpCalls(Restorers_exe);
	RestoreImpCalls(Restorers_wll);
}