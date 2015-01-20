#include <Windows.h>
#include <set>
#include <map>
#include <algorithm>
#include "DbgPrintf.h"
#include "HookIAT.h"
#include "global_win.h"
#include "asm_stub.h"

#pragma warning(push,3)
#include <ida.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <expr.hpp>
#pragma warning(pop)
#include "global.h"
#include "EnumToString.h"

DWORD ThreadFlagTlsIdx;
DWORD LastDataAccessTlsIdx;
DWORD LastEipTlsIdx;
DWORD PointerToCatcherArea;

typedef union{
	struct{
		BYTE DataSelector;
		BYTE ReEnter;
		WORD InsCnt;
	};
	LPVOID TlsValue;
}ThreadFlags_t;

#pragma warning(push)
#pragma warning( disable : 4201 )
typedef union{
	struct{
		DWORD B0 : 1;
		DWORD B1 : 1;
		DWORD B2 : 1;
		DWORD B3 : 1;
	DWORD: 9;
		DWORD BD : 1;
		DWORD BS : 1;
		DWORD BT : 1;
	DWORD: 16;
	};
	DWORD DR6;
}Dr6_t;

typedef union{
	struct{
		DWORD L0 : 1;
		DWORD G0 : 1;
		DWORD L1 : 1;
		DWORD G1 : 1;
		DWORD L2 : 1;
		DWORD G2 : 1;
		DWORD L3 : 1;
		DWORD G3 : 1;
		DWORD LE : 1;
		DWORD GE : 1;
		DWORD RESERVE1_CONST1 : 3;
		DWORD GD : 1;
		DWORD RESERVE2_CONST0 : 2;
		DWORD RW0 : 2;
		DWORD LEN0 : 2;
		DWORD RW1 : 2;
		DWORD LEN1 : 2;
		DWORD RW2 : 2;
		DWORD LEN2 : 2;
		DWORD RW3 : 2;
		DWORD LEN3 : 2;
	};
	DWORD DR7;
}Dr7_t;
#pragma warning(pop)

#pragma pack(push, 1)
typedef struct {
	BYTE opcode;
	union{
		struct {
			BYTE sib;
			PULONG_PTR addr;
		}GvEv;
		struct {
			PULONG_PTR addr;
		}rAxOv;
	};
}MovRM32, *PMovRM32;
#pragma pack(pop)

typedef struct{
	processor_t local_ph;
	idainfo local_inf;
	auto_display_t local_auto_display;
	extlang_t* local_extlang;
}DataCatcherArea_t;

typedef void(*DataHandler_t)(PVOID pObj, ULONG_PTR offset, bool timing, bool action);
typedef struct{
	LPCSTR Name;
	ULONG_PTR NewOffset;
	ULONG_PTR OrigBase;
	SIZE_T Size;
	DataHandler_t Handler;
}DataRange_t;

#define DATA_RANGES (4U)

#define STR(v) #v
#define TOSTR(v) STR(v)

static const char* DataAccessTiming[] = { "(before)", "(after)" };
static const char* DataAccessAction[] = { "read from", "writen to" };

#define HANDLER_GEN_CASE_START(type) \
	typedef type GLOBAL_STRUCTURE_TYPE;\
	const char* GLOBAL_STRUCTURE_NAME = TOSTR(type);\
	if(0){

#define HANDLER_GEN_CASE(x) \
		}\
		else if(\
		((uintptr_t)&(((GLOBAL_STRUCTURE_TYPE*)0)->x)) <= offset\
		&&\
		((uintptr_t)((&(((GLOBAL_STRUCTURE_TYPE*)0)->x))+1)) > offset\
	)\
	{\
		DbgPrint("#### Member \""TOSTR(x)"\" of %s at offset %p is %s via ptr +%p %s\n",GLOBAL_STRUCTURE_NAME, ((uintptr_t)&(((GLOBAL_STRUCTURE_TYPE*)0)->x)),DataAccessAction[action], offset, DataAccessTiming[timing]);

#define HANDLER_GEN_CASE_END() \
	}\
	else{\
		DbgPrint("####The access of %s at offset %p is unexcepted\n",GLOBAL_STRUCTURE_NAME, offset);\
	}

#pragma warning( push )
#pragma warning( disable : 4127 )

static void Handler_ph(PVOID , ULONG_PTR offset, bool timing, bool action)
{
	HANDLER_GEN_CASE_START(processor_t)
	HANDLER_GEN_CASE(version)
	HANDLER_GEN_CASE(id)
	{
		DbgPrint("\tprocessor id is \"%s\"\n", processor_id_get_str(ph.id));
	}
	HANDLER_GEN_CASE(flag)
	HANDLER_GEN_CASE(cnbits)
	HANDLER_GEN_CASE(dnbits)
	HANDLER_GEN_CASE(psnames)
	HANDLER_GEN_CASE(plnames)
	HANDLER_GEN_CASE(assemblers)
	HANDLER_GEN_CASE(notify)
	HANDLER_GEN_CASE(header)
	HANDLER_GEN_CASE(footer)
	HANDLER_GEN_CASE(segstart)
	HANDLER_GEN_CASE(segend)
	HANDLER_GEN_CASE(assumes)
	HANDLER_GEN_CASE(u_ana)
	HANDLER_GEN_CASE(u_emu)
	HANDLER_GEN_CASE(u_out)
	HANDLER_GEN_CASE(u_outop)
	HANDLER_GEN_CASE(d_out)
	HANDLER_GEN_CASE(cmp_opnd)
	HANDLER_GEN_CASE(can_have_type)
	HANDLER_GEN_CASE(regsNum)
	HANDLER_GEN_CASE(regNames)
	HANDLER_GEN_CASE(getreg)
	HANDLER_GEN_CASE(rFiles)
	HANDLER_GEN_CASE(rFnames)
	HANDLER_GEN_CASE(rFdescs)
	HANDLER_GEN_CASE(CPUregs)
	HANDLER_GEN_CASE(regFirstSreg)
	HANDLER_GEN_CASE(regLastSreg)
	HANDLER_GEN_CASE(segreg_size)
	HANDLER_GEN_CASE(regCodeSreg)
	HANDLER_GEN_CASE(regDataSreg)
	HANDLER_GEN_CASE(codestart)
	HANDLER_GEN_CASE(retcodes)
	HANDLER_GEN_CASE(instruc_start)
	HANDLER_GEN_CASE(instruc_end)
	HANDLER_GEN_CASE(instruc)
	HANDLER_GEN_CASE(is_far_jump)
	HANDLER_GEN_CASE(translate)
	HANDLER_GEN_CASE(tbyte_size)
	HANDLER_GEN_CASE(realcvt)
	HANDLER_GEN_CASE(real_width)
	HANDLER_GEN_CASE(is_switch)
	HANDLER_GEN_CASE(gen_map_file)
	HANDLER_GEN_CASE(extract_address)
	HANDLER_GEN_CASE(is_sp_based)
	HANDLER_GEN_CASE(create_func_frame)
	HANDLER_GEN_CASE(get_frame_retsize)
	HANDLER_GEN_CASE(gen_stkvar_def)
	HANDLER_GEN_CASE(u_outspec)
	HANDLER_GEN_CASE(icode_return)
	HANDLER_GEN_CASE(set_idp_options)
	HANDLER_GEN_CASE(is_align_insn)
	HANDLER_GEN_CASE(mvm)
	HANDLER_GEN_CASE(high_fixup_bits)
	HANDLER_GEN_CASE_END()
}
static void Handler_inf(PVOID , ULONG_PTR offset, bool timing, bool action)
{
	HANDLER_GEN_CASE_START(idainfo)
	HANDLER_GEN_CASE(tag)
	HANDLER_GEN_CASE(version)
	HANDLER_GEN_CASE(procName)
	HANDLER_GEN_CASE(lflags)
	HANDLER_GEN_CASE(demnames)
	HANDLER_GEN_CASE(filetype)
	HANDLER_GEN_CASE(fcoresiz)
	HANDLER_GEN_CASE(corestart)
	HANDLER_GEN_CASE(ostype)
	HANDLER_GEN_CASE(apptype)
	HANDLER_GEN_CASE(startSP)
	HANDLER_GEN_CASE(af)
	HANDLER_GEN_CASE(startIP)
	HANDLER_GEN_CASE(beginEA)
	HANDLER_GEN_CASE(minEA)
	HANDLER_GEN_CASE(maxEA)
	HANDLER_GEN_CASE(ominEA)
	HANDLER_GEN_CASE(omaxEA)
	HANDLER_GEN_CASE(lowoff)
	HANDLER_GEN_CASE(highoff)
	HANDLER_GEN_CASE(maxref)
	HANDLER_GEN_CASE(ASCIIbreak)
	HANDLER_GEN_CASE(wide_high_byte_first)
	HANDLER_GEN_CASE(indent)
	HANDLER_GEN_CASE(comment)
	HANDLER_GEN_CASE(xrefnum)
	HANDLER_GEN_CASE(s_entab)
	HANDLER_GEN_CASE(specsegs)
	HANDLER_GEN_CASE(s_void)
	HANDLER_GEN_CASE(s_reserved2)
	HANDLER_GEN_CASE(s_showauto)
	HANDLER_GEN_CASE(s_auto)
	HANDLER_GEN_CASE(s_limiter)
	HANDLER_GEN_CASE(s_null)
	HANDLER_GEN_CASE(s_genflags)
	HANDLER_GEN_CASE(s_showpref)
	HANDLER_GEN_CASE(s_prefseg)
	HANDLER_GEN_CASE(asmtype)
	HANDLER_GEN_CASE(baseaddr)
	HANDLER_GEN_CASE(s_xrefflag)
	HANDLER_GEN_CASE(binSize)
	HANDLER_GEN_CASE(s_cmtflg)
	HANDLER_GEN_CASE(nametype)
	HANDLER_GEN_CASE(s_showbads)
	HANDLER_GEN_CASE(s_prefflag)
	HANDLER_GEN_CASE(s_packbase)
	HANDLER_GEN_CASE(asciiflags)
	HANDLER_GEN_CASE(listnames)
	HANDLER_GEN_CASE(ASCIIpref)
	HANDLER_GEN_CASE(ASCIIsernum)
	HANDLER_GEN_CASE(ASCIIzeroes)
	HANDLER_GEN_CASE(graph_view)
	HANDLER_GEN_CASE(s_reserved5)
	HANDLER_GEN_CASE(tribyte_order)
	HANDLER_GEN_CASE(mf)
	HANDLER_GEN_CASE(s_org)
	HANDLER_GEN_CASE(s_assume)
	HANDLER_GEN_CASE(s_checkarg)
	HANDLER_GEN_CASE(start_ss)
	HANDLER_GEN_CASE(start_cs)
	HANDLER_GEN_CASE(main)
	HANDLER_GEN_CASE(short_demnames)
	HANDLER_GEN_CASE(long_demnames)
	HANDLER_GEN_CASE(datatypes)
	HANDLER_GEN_CASE(strtype)
	HANDLER_GEN_CASE(af2)
	HANDLER_GEN_CASE(namelen)
	HANDLER_GEN_CASE(margin)
	HANDLER_GEN_CASE(lenxref)
	HANDLER_GEN_CASE(lprefix)
	HANDLER_GEN_CASE(lprefixlen)
	HANDLER_GEN_CASE(cc)
	{
		HANDLER_GEN_CASE_START(compiler_info_t)
		HANDLER_GEN_CASE(id)
		HANDLER_GEN_CASE(cm)
		HANDLER_GEN_CASE(size_i)
		HANDLER_GEN_CASE(size_b)
		HANDLER_GEN_CASE(size_e)
		HANDLER_GEN_CASE(defalign)
		HANDLER_GEN_CASE(size_s)
		HANDLER_GEN_CASE(size_l)
		HANDLER_GEN_CASE(size_ll)
		HANDLER_GEN_CASE_END()
	}
	HANDLER_GEN_CASE(database_change_count)
	HANDLER_GEN_CASE(size_ldbl)
	HANDLER_GEN_CASE(appcall_options)
	HANDLER_GEN_CASE(reserved)
	HANDLER_GEN_CASE_END()
}
/*static void Handler_dbg(DataCatcherArea_t* pArea, ULONG_PTR , bool timing, bool action)
{
	if (timing && action)
	{
		DbgPrintfA("Setting DBG to %p, Previous was %p\n", local_dbg, dbg);
	}
}
static void Handler_debug(DataCatcherArea_t* pArea, ULONG_PTR , bool , bool )
{
	DbgPrintfA("\tGlobal Debug Flag=%X\n", debug);
}*/

static void Handler_extlang(PVOID plocal_extlang, ULONG_PTR, bool timing, bool action)
{
	if (timing)
	{
		if (action)
		{
			DbgPrint("Setting extlang to %p, previous was %p\n", *(extlang_t**)plocal_extlang, extlang);
		}
		else
		{
			DbgPrint("Reading extlang = %p\n", extlang);
		}
	}
}

static void Handler_auto_display(PVOID, ULONG_PTR offset, bool timing, bool action)
{
	HANDLER_GEN_CASE_START(auto_display_t)
	HANDLER_GEN_CASE(type);
	HANDLER_GEN_CASE(ea);
	HANDLER_GEN_CASE(state);
	HANDLER_GEN_CASE_END()
}
/*void InitCatcherAreas()
{
	DEF_INIT_DATA_RANGE(ph);
	//DEF_INIT_DATA_RANGE(dbg);
	DEF_INIT_DATA_RANGE(inf);
	//DEF_INIT_DATA_RANGE(debug);
	DEF_INIT_DATA_RANGE(auto_display);
	DEF_INIT_DATA_RANGE(extlang);
}*/
#pragma warning( pop )

#define DEF_DATA_RANGE(x) {#x, offsetof(DataCatcherArea_t, local_##x), (ULONG_PTR)&x, sizeof(x), Handler_##x}
static const DataRange_t DataRanges[] =
{
	DEF_DATA_RANGE(ph),
	DEF_DATA_RANGE(inf),
	DEF_DATA_RANGE(extlang),
	DEF_DATA_RANGE(auto_display)
};
static_assert(_countof(DataRanges) <= 4, "Too Many Data to Watch");

void AllocCatcherArea()
{
	LPVOID pArea = TlsGetValue(PointerToCatcherArea);
	if (!pArea)
	{
		pArea = VirtualAlloc(NULL, sizeof(DataCatcherArea_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pArea)
		{
			DbgPrint("allocate Catcher Area Failed!\n");
			abort();
		}
		DWORD tmp;
		VirtualProtect(pArea, sizeof(DataCatcherArea_t), PAGE_NOACCESS, &tmp);
		TlsSetValue(PointerToCatcherArea, pArea);
	}
}

void FreeCatcherArea()
{
	LPVOID pArea = TlsGetValue(PointerToCatcherArea);
	if (pArea)
	{
		VirtualFree(pArea, 0, MEM_RELEASE);
		TlsSetValue(PointerToCatcherArea, 0);
	}
}

static PULONG_PTR GetBochsUserImplIatSolt(LPCSTR Func)
{
	PULONG_PTR ret = GetIatSlotAddr(hBochsUserImpl, "IDA.WLL", Func);
	if (!ret)
	{
		abort();
	}
	return ret;
}

static void UnsetBreakPoint(CONTEXT& Context, SIZE_T Dr7Slot)
{
	Dr7_t dr7;
	dr7.DR7 = Context.Dr7;
	switch (Dr7Slot)
	{
	case 0:
		dr7.L0 = 0;
		break;
	case 1:
		dr7.L1 = 0;
		break;
	case 2:
		dr7.L2 = 0;
		break;
	case 3:
		dr7.L3 = 0;
		break;
	default:
		abort();
		break;
	}
	Context.Dr7 = dr7.DR7;
}

static void SetReadBreakPoint(CONTEXT& Context, ULONG_PTR Addr, SIZE_T Dr7Slot)
{
	Dr7_t dr7;
	dr7.DR7 = Context.Dr7;
	dr7.RESERVE1_CONST1 = 1;
	dr7.RESERVE2_CONST0 = 0;
	switch (Dr7Slot)
	{
	case 0:
		dr7.L0 = 1;
		dr7.RW0 = 3;
		dr7.LEN0 = 3;
		Context.Dr0 = Addr;
		break;
	case 1:
		dr7.L1 = 1;
		dr7.RW1 = 3;
		dr7.LEN1 = 3;
		Context.Dr1 = Addr;
		break;
	case 2:
		dr7.L2 = 1;
		dr7.RW2 = 3;
		dr7.LEN2 = 3;
		Context.Dr2 = Addr;
		break;
	case 3:
		dr7.L3 = 1;
		dr7.RW3 = 3;
		dr7.LEN3 = 3;
		Context.Dr3 = Addr;
		break;
	default:
		abort();
		break;
	}
	Context.Dr7 = dr7.DR7;
}

static void SetIatBreakPoints(CONTEXT& Context)
{
	for (size_t i = 0; i < _countof(DataRanges); ++i)
	{
		SetReadBreakPoint(Context, (ULONG_PTR)GetBochsUserImplIatSolt(DataRanges[i].Name), i);
	}
}

static void UnsetBreakPoints(CONTEXT& Context)
{
	for (size_t i = 0; i < _countof(DataRanges); ++i)
	{
		UnsetBreakPoint(Context, i);
	}
}

static void SetCurrentThreadBreakPoint()
{
	HANDLE hCurrentThread = GetCurrentThread();
	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(hCurrentThread, &ThreadContext))
	{
		abort();
	}
	ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	SetIatBreakPoints(ThreadContext);
	if (!SetThreadContext(hCurrentThread, &ThreadContext))
	{
		abort();
	}
}

static void UnsetCurrentThreadBreakPoint()
{
	HANDLE hCurrentThread = GetCurrentThread();
	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(hCurrentThread, &ThreadContext))
	{
		abort();
	}
	ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	UnsetBreakPoints(ThreadContext);
	if (!SetThreadContext(hCurrentThread, &ThreadContext))
	{
		abort();
	}
}

static inline void __singlestep()
{
	__asm{
		__asm __emit 0xF1;
	}
}

static void DetectReEnter(LPCSTR Str)
{
	ThreadFlags_t ThreadFlag;
	ThreadFlag.TlsValue = TlsGetValue(ThreadFlagTlsIdx);
	if (ThreadFlag.ReEnter)
	{
		DbgPrint("%s ReEntered\n", Str);
		abort();
	}
	ThreadFlag.ReEnter = 1;
	TlsSetValue(ThreadFlagTlsIdx, ThreadFlag.TlsValue);
	DbgPrint("#### Establish Catcher For %s\n", Str);
}

static void LeaveHookedFunc(LPCSTR Str)
{
	DbgPrint("#### Leaving Catcher for %s\n", Str);
	ThreadFlags_t ThreadFlag;
	ThreadFlag.TlsValue = TlsGetValue(ThreadFlagTlsIdx);
	if (!ThreadFlag.ReEnter)
	{
		DbgPrint("%s Impossible \n", Str);
		abort();
	}
	ThreadFlag.ReEnter = 0;
	TlsSetValue(ThreadFlagTlsIdx, ThreadFlag.TlsValue);
}

#define CATCHER_NORET(x)\
	do{\
		DetectReEnter(#x);\
		AllocCatcherArea();\
		SetCurrentThreadBreakPoint(); \
		__try{\
			SetTF();\
			BochsDbgShadow.x;\
			EndCatching();\
		}\
		__except (catcher(GetExceptionInformation()))\
		{\
			exit(-1); \
		}\
		UnsetCurrentThreadBreakPoint();\
		LeaveHookedFunc(#x);\
	}while(0)

#define CATCHER_RET(x) \
	do { \
		DetectReEnter(#x);\
		AllocCatcherArea();\
		SetCurrentThreadBreakPoint(); \
		decltype(BochsDbgShadow.x) ret; \
		__try{\
			SetTF();\
			ret = BochsDbgShadow.x; \
			EndCatching();\
		} \
		__except (catcher(GetExceptionInformation()))\
		{\
			exit(-1); \
		} \
		UnsetCurrentThreadBreakPoint();\
		LeaveHookedFunc(#x);\
		return ret; \
	}while (0)

#define CATCHER_PLG_RET(x) \
	do {\
		DetectReEnter(#x);\
		AllocCatcherArea();\
		SetCurrentThreadBreakPoint(); \
		decltype(BochsPlgShadow.x) ret; \
		__try{\
			SetTF();\
			ret = BochsPlgShadow.x; \
			EndCatching();\
		} \
		__except (catcher(GetExceptionInformation()))\
		{\
			exit(-1); \
		} \
		UnsetCurrentThreadBreakPoint();\
		LeaveHookedFunc(#x);\
		return ret; \
	} while (0)

#define CATCHER_PLG_NORET(x) \
	do {\
		DetectReEnter(#x);\
		AllocCatcherArea();\
		SetCurrentThreadBreakPoint(); \
		__try{\
			SetTF();\
			BochsPlgShadow.x; \
			EndCatching();\
		} \
		__except (catcher(GetExceptionInformation()))\
		{\
			exit(-1); \
		} \
		UnsetCurrentThreadBreakPoint();\
		LeaveHookedFunc(#x);\
	} while (0)

class CompDataRange{
public:
	bool operator () (ULONG_PTR Ptr, const DataRange_t& range) const
	{
		return ((range.NewOffset + range.Size) > Ptr);
	}
};

static void EmuMov(PCONTEXT pCon, PULONG_PTR IatSlot, ULONG_PTR NewAddr)
{
	PMovRM32 Ins = (PMovRM32)TlsGetValue(LastEipTlsIdx);
	switch (Ins->opcode)
	{
	case 0xA1U:
		if (Ins->rAxOv.addr != IatSlot)
		{
			abort();
		}
		pCon->Eax = NewAddr;
		break;
	case 0x8BU:
	{
		switch (Ins->GvEv.sib)
		{
		case 0x0DU:
		case 0x15U:
			if (Ins->GvEv.addr == IatSlot)
			{
				break;
			}
		default:
			abort();
			break;
		}
		switch (Ins->GvEv.sib)
		{
		case 0x0DU:
			pCon->Ecx = NewAddr;
			break;
		case 0x15U:
			pCon->Edx = NewAddr;
			break;
		}
	}
		break;
	default:
		abort();
		break;
	}
}

static int catcher(LPEXCEPTION_POINTERS pE)
{
	const char* actions[] = { "read from", "write to" };
	PCONTEXT pCon = pE->ContextRecord;
	if (pE->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		//Enter or Leave Catcher Block
		if (pCon->EFlags & (0x100U))
		{
			DbgPrint("#### End Tracing Data Access from %p\n", pCon->Eip);
		}
		else
		{
			DbgPrint("#### Begin Tracing Data Access from %p\n", pCon->Eip);
		}
		TlsSetValue(LastEipTlsIdx, 0);
		++pCon->Eip;
		pCon->EFlags ^= (0x100U);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pE->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (pCon->Eip - (ULONG_PTR)pKiUserExceptionDispatcher < 16) // Nested Exception Occurred
		{
			LPEXCEPTION_POINTERS pNested = (LPEXCEPTION_POINTERS)pCon->Esp;
			PEXCEPTION_RECORD pNestedE = pNested->ExceptionRecord;
			DbgPrint("#### Nested Exception %p at %p, Disabling Single Step\n", pNestedE->ExceptionCode, pNestedE->ExceptionAddress);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (pCon->Eip == (ULONG_PTR)EndCatching) // End Catching requested
		{
			DbgPrint("#### End Of Current Catching from %p\n", *(PULONG_PTR)(pCon->Ebp+4));
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		ThreadFlags_t ThreadFlag;
		ThreadFlag.TlsValue = TlsGetValue(ThreadFlagTlsIdx);
		pCon->EFlags |= (0x100U);
		SIZE_T sel;
		DWORD BitScanPos;
		//volatile unsigned i;
		//DbgPrintLevel(1, "#### (%05d) SingleStep to %p Esp = %p\n", ThreadFlag.InsCnt++, pCon->Eip, pCon->Esp);
		//for (i = 0; i < 500000000; ++i){}
		if (_BitScanForward(&BitScanPos, pCon->Dr6) && BitScanPos < 4) //Iat BreakPoint Hit
		{
			PULONG_PTR IatSlot;
			ULONG_PTR NewFuncAddr;
			sel = BitScanPos;
			DWORD BreakPoints[] = { pCon->Dr0, pCon->Dr1, pCon->Dr2, pCon->Dr3 };
			IatSlot = (PULONG_PTR)BreakPoints[sel];
			// Should Not check again. Otherwise we trigger nested SINGLE_STEP!
			/*if (*IatSlot != DataRanges[sel].OrigBase)
			{
				abort();
			}*/
			NewFuncAddr = (ULONG_PTR)TlsGetValue(PointerToCatcherArea) + DataRanges[sel].NewOffset;
			EmuMov(pCon, IatSlot, NewFuncAddr);
			pCon->Dr6 = 0;
		}
		else
		{
			LONG DataSelector = (LONG)(ULONG)ThreadFlag.DataSelector;
			if (_BitScanForward(&BitScanPos, DataSelector)) //Read/Write Complete
			{
				if (BitScanPos % 2)
				{
					abort();
				}
				sel = BitScanPos / 2;
				bool Op = !!(_bittest(&DataSelector, BitScanPos + 1));
				DataSelector &= ~((ULONG(3U) << BitScanPos));
				if (DataSelector)
				{
					abort();
				}
				DataCatcherArea_t* pArea = (DataCatcherArea_t*)TlsGetValue(PointerToCatcherArea);
				ULONG_PTR NewBase = (ULONG_PTR)pArea + DataRanges[sel].NewOffset;
				ULONG_PTR AccessOffset = (ULONG_PTR)TlsGetValue(LastDataAccessTlsIdx) - NewBase;
				DataRanges[sel].Handler((LPVOID)NewBase, AccessOffset, true, !!Op);
				{
					if (Op)
					{
						memcpy((void*)DataRanges[sel].OrigBase, (void*)NewBase, DataRanges[sel].Size);
					}
					DWORD tmp;
					VirtualProtect(pArea, sizeof(*pArea), PAGE_NOACCESS, &tmp);
				}
				ThreadFlag.DataSelector = 0;
			}
		}
		TlsSetValue(ThreadFlagTlsIdx, ThreadFlag.TlsValue);
		TlsSetValue(LastEipTlsIdx, (LPVOID)pE->ContextRecord->Eip);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pE->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) //attempt to access the watched area
	{
		DataCatcherArea_t* pArea = (DataCatcherArea_t*)TlsGetValue(PointerToCatcherArea);
		ULONG_PTR DataAddr = pE->ExceptionRecord->ExceptionInformation[1];
		ULONG_PTR Op = pE->ExceptionRecord->ExceptionInformation[0];
		const DataRange_t* i;
		const DataRange_t* end = DataRanges + _countof(DataRanges);
		if ((i = ::std::upper_bound(DataRanges, end, DataAddr - (ULONG_PTR)pArea, CompDataRange())) != end)
		{
			SIZE_T sel = i - DataRanges;
			LONG DataSelector = 0;
			ULONG_PTR NewBase = (ULONG_PTR)pArea + DataRanges[sel].NewOffset;
			ULONG_PTR AccessOffset = DataAddr - NewBase;
			_bittestandset(&DataSelector, sel * 2);
			if (Op)
			{
				_bittestandset(&DataSelector, sel * 2 + 1);
			}
			TlsSetValue(LastDataAccessTlsIdx, (LPVOID)DataAddr);
			ThreadFlags_t ThreadFlag;
			ThreadFlag.TlsValue = TlsGetValue(ThreadFlagTlsIdx);
			ThreadFlag.DataSelector = (BYTE)(ULONG)DataSelector;
			TlsSetValue(ThreadFlagTlsIdx, ThreadFlag.TlsValue);
			{
				DWORD tmp;
				VirtualProtect(pArea, sizeof(*pArea), PAGE_READWRITE, &tmp);
				memcpy((void*)NewBase, (void*)DataRanges[sel].OrigBase, DataRanges[sel].Size);
			}
			DbgPrint("#### Attempt to %s to %p from %p\n", actions[!!Op], DataAddr, pCon->Eip);
			DataRanges[sel].Handler((LPVOID)NewBase, AccessOffset, false, !!Op);
		}
		else
		{
			abort();
		}
		pCon->EFlags |= (0x100U);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

#pragma warning( push )
#pragma warning( disable : 4127 )

namespace BochsUserCatchDataAccess{
	namespace DBG{
		bool __stdcall init_debugger(const char *hostname, int portnum, const char *password)
		{
			CATCHER_RET(init_debugger(hostname, portnum, password));
		}
		void __stdcall set_exception_info(const exception_info_t *info, int qty)
		{
			CATCHER_NORET(set_exception_info(info, qty));
		}
		int __stdcall continue_after_event(const debug_event_t *event)
		{
			CATCHER_RET(continue_after_event(event));
		}
		bool __stdcall term_debugger(void)
		{
			CATCHER_RET(term_debugger());
		}
		int __stdcall exit_process(void)
		{
			CATCHER_RET(exit_process());
		}
		int __stdcall process_get_info(int n, process_info_t *info)
		{
			CATCHER_RET(process_get_info(n, info));
		}
		int __stdcall detach_process(void)
		{
			CATCHER_RET(detach_process());
		}
		int __stdcall prepare_to_pause_process(void)
		{
			CATCHER_RET(prepare_to_pause_process());
		}
		const char * _stdcall set_dbg_options(const char *keyword, int value_type, const void *value)
		{
			CATCHER_RET(set_dbg_options(keyword, value_type, value));
		}
		gdecode_t __stdcall get_debug_event(debug_event_t *event, int timeout_ms)
		{
			CATCHER_RET(get_debug_event(event, timeout_ms));
		}
		int __stdcall start_process(const char *path, const char *args, const char *startdir, int dbg_proc_flags, const char *input_path, uint32 input_file_crc32)
		{
			CATCHER_RET(start_process(path, args, startdir, dbg_proc_flags, input_path, input_file_crc32));
		}
		int __stdcall attach_process(pid_t pid, int event_id)
		{
			CATCHER_RET(attach_process(pid, event_id));
		}
		void __stdcall rebase_if_required_to(ea_t new_base)
		{
			CATCHER_NORET(rebase_if_required_to(new_base));
		}
		int __stdcall read_registers(thid_t tid, int clsmask, regval_t *values)
		{
			CATCHER_RET(read_registers(tid, clsmask, values));
		}
		int __stdcall write_register(thid_t tid, int regidx, const regval_t *value)
		{
			CATCHER_RET(write_register(tid, regidx, value));
		}
		ssize_t __stdcall read_memory(ea_t ea, void *buffer, size_t size)
		{
			CATCHER_RET(read_memory(ea, buffer, size));
		}
		ssize_t __stdcall write_memory(ea_t ea, const void *buffer, size_t size)
		{
			CATCHER_RET(write_memory(ea, buffer, size));
		}		
		
		void __stdcall stopped_at_debug_event(bool dlls_added)
		{
			CATCHER_NORET(stopped_at_debug_event(dlls_added));
		}

		int __stdcall thread_suspend(thid_t tid)
		{
			CATCHER_RET(thread_suspend(tid));
		}
		int __stdcall thread_continue(thid_t tid)
		{
			CATCHER_RET(thread_continue(tid));
		}
		int __stdcall thread_set_step(thid_t tid)
		{
			CATCHER_RET(thread_set_step(tid));
		}
	}
	namespace PLG{
		int __stdcall init(void)
		{
			CATCHER_PLG_RET(init());
		}
		void __stdcall term(void)
		{
			CATCHER_PLG_NORET(term());
		}
		void __stdcall run(int arg)
		{
			CATCHER_PLG_NORET(run(arg));
		}
	}
}
#pragma warning( pop )