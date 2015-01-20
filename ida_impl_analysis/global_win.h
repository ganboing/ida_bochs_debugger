#include <Windows.h>

//typedef BOOL(WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/);
//extern DllMain_t BochsUserImplEntryPoint;
extern HMODULE hBochsUserImpl;
extern HMODULE hIDA_wll;
extern HMODULE hIDA_EXE;
extern HMODULE hKrnl32;
extern HMODULE hSelf;
extern DWORD BochsUserImageSize;
extern PVOID pKiUserExceptionDispatcher;

extern DWORD BochsUserImageSize;
extern DWORD SelfDllImageSize;