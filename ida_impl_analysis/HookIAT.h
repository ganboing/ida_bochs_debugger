#include <Windows.h>

typedef struct{
	LPCSTR Name;
	LPVOID Func;
}FuncDesc_t;

typedef struct{
	PULONG_PTR Slot;
	ULONG_PTR Func;
}SlotDesc_t;

void HookImpCalls(HMODULE Module, LPCSTR ExternModuleName, const FuncDesc_t* NewFuncs, SlotDesc_t* OrigFuncs, BOOL Debug = FALSE, const LPCSTR* FuncExcluded = NULL);
PULONG_PTR GetIatSlotAddr(HMODULE Module, LPCSTR ExternModuleName, LPCSTR ExportName);
void RestoreImpCalls(const SlotDesc_t* OrigFuncs);
