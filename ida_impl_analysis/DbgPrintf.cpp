#include <Windows.h>
#include <cstdio>
#include <intrin.h>
#include <atomic>
#include "DbgPrintf.h"
#include "global_win.h"

static HANDLE hDbgPrintThread;
static volatile BOOL bContinue;

#define container_of(ptr, type, member)           \
((type *)( (char *)ptr - offsetof(type,member)))

#define CHECK_POW2(value) \
	(!( (value) & ((value) - 1) ))


namespace DbgPrintfInternal{

	static const size_t DbgBuffLines = 0x1000UL;
	//static const size_t DbgBuffLinesTotal = DbgBuffLinesPerLevel * DbgBuffPriLevels;
	static_assert(CHECK_POW2(DbgBuffLinesPerLevel), "check pow2 DbgBuffLinesPerLevel");
	static_assert(CHECK_POW2(DbgBuffObjSize), "check pow2 DbgBuffObjSize");

#pragma warning(push)
#pragma warning( disable : 4201)
	struct SlotPtrs
	{
		union{
			long long value;
			struct{
				ULONG_PTR Cnt;
				SlotBuff* Next;
			};
		};
	};
#pragma warning(pop)

	static SlotBuff DbgPrintSlots[DbgBuffPriLevels][DbgBuffLinesPerLevel];
	static volatile SlotPtrs AvailSlots[DbgBuffPriLevels];
	static_assert(_countof(DbgPrintSlots[0]) == DbgBuffLinesPerLevel, "check _countof(DbgPrintSlots[0])");
	static_assert(sizeof(DbgPrintSlots) == DbgBuffObjSize * DbgBuffPriLevels * DbgBuffLinesPerLevel, "check buff size");
	
	static PrintSlot* volatile DbgPrintSlotPtrs[DbgBuffLinesTotal];
	static_assert(_countof(DbgPrintSlotPtrs) == DbgBuffLinesTotal, "check DbgPrintSlotPtrs count");
	union longulong{
		unsigned long nth;
		long value;
	};
	static volatile longulong SlotPtrFirst;
	static volatile longulong SlotPtrLast;
	static volatile longulong SlotPtrFinal;

	static void CheckPtrAtLevel(SlotBuff* pSlotBuff, size_t level)
	{
		char* p = (char*)pSlotBuff;
		char* base = (char*)DbgPrintSlots;
		if ((p - base) % DbgBuffObjSize)
		{
			abort();
		}
		if ((p - base) < 0 || (p - base) >= (ptrdiff_t)(DbgBuffObjSize*DbgBuffLinesPerLevel*(level+1)))
		{
			abort();
		}
	}

	static PrintSlot* AllocSlotAt(size_t Level)
	{
		SlotPtrs OldPtr;
		SlotPtrs NewPtr;
		do
		{
			OldPtr.value = AvailSlots[Level].value;
			if (!OldPtr.Next)
			{
				return NULL;
			}
			NewPtr.Cnt = OldPtr.Cnt + 1;
			NewPtr.Next = OldPtr.Next->next;
		} while (_InterlockedCompareExchange64(&AvailSlots[Level].value, NewPtr.value, OldPtr.value) != OldPtr.value);
		CheckPtrAtLevel(OldPtr.Next, Level);
		return (PrintSlot*)OldPtr.Next->PrintSlot;
	}

	static PrintSlot* AllocSlotLess(size_t Level)
	{
		for (size_t l = Level; l < DbgBuffPriLevels; ++l)
		{
			PrintSlot* ret = AllocSlotAt(l);
			if (ret)
			{
				return ret;
			}
		}
		return NULL;
	}

	static void FreeSlot(PrintSlot* pPrintSlot)
	{
		SlotPtrs OldPtr;
		SlotPtrs NewPtr;
		SlotBuff* pSlotBuff = container_of(pPrintSlot, SlotBuff, PrintSlot);
		size_t Level = (pSlotBuff - DbgPrintSlots[0]) / _countof(DbgPrintSlots[0]);
		CheckPtrAtLevel(pSlotBuff, Level);
		do{
			OldPtr.value = AvailSlots[Level].value;
			pSlotBuff->next = OldPtr.Next;
			NewPtr.Cnt = OldPtr.Cnt + 1;
			NewPtr.Next = pSlotBuff;
		} while (_InterlockedCompareExchange64(&AvailSlots[Level].value, NewPtr.value, OldPtr.value) != OldPtr.value);
	}

	void CheckIfStaticStr(const char* Str)
	{
		if (Str)
		{
			if (
				((ULONG_PTR)Str >= (ULONG_PTR)hSelf + SelfDllImageSize)
				||
				((ULONG_PTR)Str < (ULONG_PTR)hSelf)
				)
			{
				__DbgPrintfA("Str %s @ %p is not Static\n", Str, Str);
				__debugbreak();
				abort();
			}
		}
	}

	void CheckIfDynamicStr(volatile const char* Str)
	{
		if (Str)
		{
			if (
				((ULONG_PTR)Str < (ULONG_PTR)hSelf + SelfDllImageSize)
				&&
				((ULONG_PTR)Str >= (ULONG_PTR)hSelf)
				)
			{
				__DbgPrintfA("Str %s @ %p is not Dynamic\n", Str, Str);
				__debugbreak();
				abort();
			}
		}
	}

	size_t MyStrNCpy(char* Dest, const volatile char* Src, size_t n)
	{
		if (n)
		{
			size_t i;
			for (i = 0; i < n - 1 && Src[i]; ++i)
			{
				Dest[i] = Src[i];
			}
			Dest[i] = 0;
			return i + 1;
		}
		return 0;
	}

	static void PrintAndfreeSlot(PrintSlot* pPrintSlot)
	{
		pPrintSlot->Print();
		pPrintSlot->~PrintSlot();
		FreeSlot(pPrintSlot);
	}

	static DWORD WINAPI DbgPrintThread(LPVOID)
	{
		while (bContinue)
		{
			longulong OldFirst;
			longulong NewFirst;
			OldFirst.value = SlotPtrFirst.value;
			if (OldFirst.nth != SlotPtrLast.nth)
			{
				NewFirst.nth = (OldFirst.nth + 1) & (DbgBuffLinesTotal - 1);
				PrintSlot* pSlotToPrint = DbgPrintSlotPtrs[OldFirst.nth];
				if (_InterlockedCompareExchange(&SlotPtrFirst.value, NewFirst.value, OldFirst.value) == OldFirst.value)
				{
					PrintAndfreeSlot(pSlotToPrint);
				}
			}
			else
			{
				_mm_pause();
				Sleep(50);
			}
		}
		return (SlotPtrFirst.nth != SlotPtrLast.nth);
	}
	
	PrintSlot* ReQuestSlotAt(size_t Level)
	{
		PrintSlot* pPrintSlot;
		while (!(pPrintSlot = AllocSlotAt(Level)))
		{
			_mm_pause();
		}
		return pPrintSlot;
	}
	
	PrintSlot* ReQuestSlotLess(size_t Level)
	{
		PrintSlot* pPrintSlot;
		while (!(pPrintSlot = AllocSlotLess(Level)))
		{
			_mm_pause();
		}
		return pPrintSlot;
	}

	void CommitSlot(PrintSlot* pSlot)
	{
		longulong OldFinal;
		longulong NewFinal;
		do{
			OldFinal.value = SlotPtrFinal.value;
			NewFinal.nth = (OldFinal.nth + 1) & (DbgBuffLinesTotal - 1);
		} while (_InterlockedCompareExchange(&SlotPtrFinal.value, NewFinal.value, OldFinal.value) != OldFinal.value);
		DbgPrintSlotPtrs[OldFinal.nth] = pSlot;
		while (SlotPtrLast.nth != OldFinal.nth)
		{
			_mm_pause();
		}
		SlotPtrLast.nth = NewFinal.nth;
	}
}

#define DbgBuffLineSize (0x8000UL)

void __vDbgPrintfA(const char* format, va_list args)
{
	char buff[DbgBuffLineSize];
	_vsnprintf(buff, DbgBuffLineSize - 1, format, args);
	buff[DbgBuffLineSize - 1] = 0;
	OutputDebugStringA(buff);
}

void __DbgPrintfA(const char* format...)
{
	va_list args;
	va_start(args, format);
	__vDbgPrintfA(format, args);
	va_end(args);
}

void __vDbgPrintfW(const wchar_t* format, va_list args)
{
	wchar_t buff[DbgBuffLineSize];
	_vsnwprintf(buff, DbgBuffLineSize - 1, format, args);
	buff[DbgBuffLineSize - 1] = 0;
	OutputDebugStringW(buff);
}

void __DbgPrintfW(const wchar_t* format...)
{
	va_list args;
	va_start(args, format);
	__vDbgPrintfW(format, args);
	va_end(args);
}

#undef DbgBuffLineSize

using namespace DbgPrintfInternal;

void InitDbgPrint()
{
	size_t i;
	for (size_t l = 0; l < DbgBuffPriLevels; ++l)
	{
		AvailSlots[l].Next = DbgPrintSlots[l] ;
		for (i = 0; i < DbgBuffLinesPerLevel - 1; ++i)
		{
			DbgPrintSlots[l][i].next = DbgPrintSlots[l] + i + 1;
		}
		DbgPrintSlots[l][i].next = NULL;
	}
	AvailSlots[DbgBuffPriLevels - 1].Next = AvailSlots[DbgBuffPriLevels - 1].Next->next; 
	// Make sure we do not overflow the Ptr array
	bContinue = TRUE;
	hDbgPrintThread = CreateThread(NULL, 0, DbgPrintThread, NULL, 0, NULL);
}

void DeInitDbgPrint()
{
	bContinue = FALSE;
	WaitForSingleObject(hDbgPrintThread, INFINITE);
	CloseHandle(hDbgPrintThread);
}