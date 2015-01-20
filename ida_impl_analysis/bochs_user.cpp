#include <Windows.h>
#include <DbgHelp.h>
#include "global_win.h"
#include "DbgPrintf.h"
#include "HookIAT.h"

#include "IdaWllHook.h"
#include "krnl32_hook.h"
#include "BochsUserImplHook.h"
#include "exception_clause.h"

#pragma warning(push,3)
#include <ida.hpp>
#include <idd.hpp>
#include <idp.hpp>
#include <loader.hpp>
#pragma warning(pop)

extern "C"
{
	_declspec(dllexport) int BochsUserHook;
}

debugger_t* pBochsDbg;
plugin_t* pBochsPlugin;
debugger_t BochsDbgShadow;
plugin_t BochsPlgShadow;
PVOID pKiUserExceptionDispatcher;

HMODULE hBochsUserImpl;
HMODULE hIDA_wll;
HMODULE hIDA_EXE;
HMODULE hKrnl32;
HMODULE hSelf;

DWORD BochsUserImageSize;
DWORD SelfDllImageSize;

/*void PrintEnumMap()
{
	for (EnumStrMap::iterator i = enumui_notification_t_str.begin(), j = enumui_notification_t_str.end(); i != j; ++i)
	{
		DbgPrintfA("%s = %d\n", i->second.c_str(), i->first);
	}
}*/

BOOL WINAPI DllMain(
	_In_  HINSTANCE hinstDLL,
	_In_  DWORD fdwReason,
	_In_  LPVOID /*lpvReserved*/
	)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		InitDbgPrint();
		hSelf = hinstDLL;
		SelfDllImageSize = ImageNtHeader(hSelf)->OptionalHeader.SizeOfImage;

		DbgPrint("BOCHS_USER_HOOK ATTACHED\n");
		//DisableThreadLibraryCalls(hinstDLL);
		pKiUserExceptionDispatcher = GetProcAddress(GetModuleHandle("NTDLL.DLL"), "KiUserExceptionDispatcher");

		DbgPrint("KiUserExceptionDispatcher @ %p\n", pKiUserExceptionDispatcher);
		hIDA_wll = GetModuleHandle("ida_wll_impl.dll");
		hIDA_EXE = GetModuleHandle(NULL);
		DbgPrint("IDA.WLL at %p\n", hIDA_wll);
		DbgPrint("IDA.EXE at %p\n", hIDA_EXE);
		

		LocalStorTlsIdx = TlsAlloc();
		ThreadFlagTlsIdx = TlsAlloc();
		LastDataAccessTlsIdx = TlsAlloc();
		PointerToCatcherArea = TlsAlloc();
		LastEipTlsIdx = TlsAlloc();
		DbgPrint("LocalStorTlsIdx at slot %d\n", LocalStorTlsIdx);
		DbgPrint("ThreadFlagTlsIdx at slot %d\n", ThreadFlagTlsIdx);
		DbgPrint("LastDataAccessTlsIdx at slot %d\n", LastDataAccessTlsIdx);
		DbgPrint("PointerToCatcherArea at slot %d\n", PointerToCatcherArea);
		DbgPrint("LastEipTlsIdx at slot %d\n", LastEipTlsIdx);

		HookKernel32Funcs();
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		FreeCatcherArea();
		if (fdwReason == DLL_THREAD_DETACH){ break; }
		TlsFree(LastEipTlsIdx);
		TlsFree(PointerToCatcherArea);
		TlsFree(LastDataAccessTlsIdx);
		TlsFree(ThreadFlagTlsIdx);
		TlsFree(LocalStorTlsIdx);
		RestoreKernel32Funcs();
		DbgPrint("BOCHS_USER_HOOK DETACHED\n");
		DeInitDbgPrint();
		break;
	}

	return TRUE;
}