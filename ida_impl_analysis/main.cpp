#include <Windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>

//#include <pc_local_impl.cpp>

#include <dbg.hpp>
#include "deb_pc.hpp"
#include "bochs_rpc.h"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTION INFORMATIONS
//
//--------------------------------------------------------------------------

const char *x86_register_classes[] =
{
	"General registers",
	"Segment registers",
	"FPU registers",
	"MMX registers",
	"XMM registers",
	NULL
};


static const char *const eflags[] =
{
	"CF",         //  0
	NULL,         //  1
	"PF",         //  2
	NULL,         //  3
	"AF",         //  4
	NULL,         //  5
	"ZF",         //  6
	"SF",         //  7
	"TF",         //  8
	"IF",         //  9
	"DF",         // 10
	"OF",         // 11
	"IOPL",       // 12
	"IOPL",       // 13
	"NT",         // 14
	NULL,         // 15
	"RF",         // 16
	"VM",         // 17
	"AC",         // 18
	"VIF",        // 19
	"VIP",        // 20
	"ID",         // 21
	NULL,         // 22
	NULL,         // 23
	NULL,         // 24
	NULL,         // 25
	NULL,         // 26
	NULL,         // 27
	NULL,         // 28
	NULL,         // 29
	NULL,         // 30
	NULL          // 31
};

static const char *const ctrlflags[] =
{
	"IM",
	"DM",
	"ZM",
	"OM",
	"UM",
	"PM",
	NULL,
	NULL,
	"PC",
	"PC",
	"RC",
	"RC",
	"X",
	NULL,
	NULL,
	NULL
};

static const char *const statflags[] =
{
	"IE",
	"DE",
	"ZE",
	"OE",
	"UE",
	"PE",
	"SF",
	"ES",
	"C0",
	"C1",
	"C2",
	"TOP",
	"TOP",
	"TOP",
	"C3",
	"B"
};

static const char *const tagsflags[] =
{
	"TAG0",
	"TAG0",
	"TAG1",
	"TAG1",
	"TAG2",
	"TAG2",
	"TAG3",
	"TAG3",
	"TAG4",
	"TAG4",
	"TAG5",
	"TAG5",
	"TAG6",
	"TAG6",
	"TAG7",
	"TAG7"
};

static const char *const xmm_format[] =
{
	"XMM_4_floats",
};

static const char *const mmx_format[] =
{
	"MMX_8_bytes",
};

static const char *const mxcsr_bits[] =
{
	"IE",         //  0 Invalid Operation Flag
	"DE",         //  1 Denormal Flag
	"ZE",         //  2 Divide-by-Zero Flag
	"OE",         //  3 Overflow Flag
	"UE",         //  4 Underflow Flag
	"PE",         //  5 Precision Flag
	"DAZ",        //  6 Denormals Are Zeros*
	"IM",         //  7 Invalid Operation Mask
	"DM",         //  8 Denormal Operation Mask
	"ZM",         //  9 Divide-by-Zero Mask
	"OM",         // 10 Overflow Mask
	"UM",         // 11 Underflow Mask
	"PM",         // 12 Precision Mask
	"RC",         // 13 Rounding Control
	"RC",         // 14 Rounding Control
	"FZ",         // 15 Flush to Zero
	NULL,         // 16
	NULL,         // 17
	NULL,         // 18
	NULL,         // 19
	NULL,         // 20
	NULL,         // 21
	NULL,         // 22
	NULL,         // 23
	NULL,         // 24
	NULL,         // 25
	NULL,         // 26
	NULL,         // 27
	NULL,         // 28
	NULL,         // 29
	NULL,         // 30
	NULL          // 31
};


register_info_t x86_registers[] =
{
	// FPU registers
	{ "ST0", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST1", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST2", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST3", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST4", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST5", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST6", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "ST7", 0, X86_RC_FPU, dt_tbyte, NULL, 0 },
	{ "CTRL", 0, X86_RC_FPU, dt_word, ctrlflags, 0x1F3F },
	{ "STAT", 0, X86_RC_FPU, dt_word, statflags, 0xFFFF },
	{ "TAGS", 0, X86_RC_FPU, dt_word, tagsflags, 0xFFFF },
	// segment registers
	{ "CS", REGISTER_CS | REGISTER_NOLF, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	{ "DS", REGISTER_NOLF, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	{ "ES", 0, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	{ "FS", REGISTER_NOLF, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	{ "GS", REGISTER_NOLF, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	{ "SS", REGISTER_SS, X86_RC_SEGMENTS, dt_word, NULL, 0 },
	// general registers
#ifdef __EA64__
	{ "RAX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RBX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RCX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RDX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RSI", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RDI", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RBP", REGISTER_ADDRESS | REGISTER_FP, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RSP", REGISTER_ADDRESS | REGISTER_SP, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "RIP", REGISTER_ADDRESS | REGISTER_IP, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R8", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R9", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R10", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R11", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R12", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R13", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R14", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
	{ "R15", REGISTER_ADDRESS, X86_RC_GENERAL, dt_qword, NULL, 0 },
#else
	{ "EAX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "EBX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "ECX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "EDX", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "ESI", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "EDI", REGISTER_ADDRESS, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "EBP", REGISTER_ADDRESS | REGISTER_FP, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "ESP", REGISTER_ADDRESS | REGISTER_SP, X86_RC_GENERAL, dt_dword, NULL, 0 },
	{ "EIP", REGISTER_ADDRESS | REGISTER_IP, X86_RC_GENERAL, dt_dword, NULL, 0 },
#endif
	{ "EFL", 0, X86_RC_GENERAL, dt_dword, eflags, 0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
	{ "XMM0", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM1", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM2", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM3", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM4", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM5", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM6", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM7", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
#ifdef __EA64__
	{ "XMM8", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM9", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM10", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM11", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM12", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM13", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM14", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
	{ "XMM15", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
#endif
	{ "MXCSR", 0, X86_RC_XMM, dt_dword, mxcsr_bits, 0xFFFF },
	{ "MM0", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM1", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM2", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM3", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM4", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM5", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM6", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
	{ "MM7", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
};
CASSERT(qnumber(x86_registers) == X86_NREGS);

#define REGISTERS                x86_registers
#define REGISTERS_SIZE           qnumber(x86_registers)
#define REGISTER_CLASSES         x86_register_classes
#define REGISTER_CLASSES_DEFAULT X86_RC_GENERAL
#define READ_REGISTERS           x86_read_registers
#define WRITE_REGISTER           x86_write_register
#define is_valid_bpt           is_x86_valid_bpt
#define BPT_CODE                 X86_BPT_CODE
#define BPT_CODE_SIZE            X86_BPT_SIZE

static const uint32 debugger_flags = 
DBG_FLAG_DEBUG_DLL | 
DBG_FLAG_FAKE_ATTACH | 
DBG_FLAG_CAN_CONT_BPT |
DBG_FLAG_DONT_DISTURB |
DBG_FLAG_SAFE |
DBG_FLAG_USE_SREGS 
;


static const uchar bpt_code[] = BPT_CODE;

areacb_t& AreaCB = segs;

static bool idaapi bochsdbg_init_debugger(const char *hostname, int port_num, const char *password)
{
	return true;
}

static bool idaapi bochsdbg_term_debugger(void)
{
	return true;
}

static int idaapi bochsdbg_start_process(const char *path,
	const char *args,
	const char *startdir,
	int dbg_proc_flags,
	const char *input_path,
	uint32 input_file_crc32)
{
	msg("try to start process args = %s, startdir = %s, dbg_proc_flags = %08X, input_path = %s\n",
		args, startdir, dbg_proc_flags, input_path);
	
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_attach_process(pid_t pid, int event_id)
{
	//MyRemoteProc(0, 0, 0, a);
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_prepare_to_pause_process(void)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_exit_process(void)
{
	__debugbreak();
	return 0;
}

static gdecode_t idaapi bochsdbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
	__debugbreak();
	return gdecode_t();
}
static int idaapi bochsdbg_continue_after_event(const debug_event_t *event)
{
	__debugbreak();
	return 0;
}
static void idaapi bochsdbg_set_exception_info(const exception_info_t *info, int qty)
{
	__debugbreak();
}

static const char* idaapi bochsdbg_set_dbg_options(
	const char *keyword,
	int value_type,
	const void *value)
{
	msg("setting bochsdbg options keyword = %s, valuetype = %X, value = %p\n", keyword, value_type, value);
	return 0;
}

static const void* idaapi bochsdbg_get_debmod_extensions(void)
{
	return 0;
}

static int idaapi bochsdbg_process_get_info(int n, process_info_t *info)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_detach_process(void)
{
	__debugbreak();
	return 0;
}

static void idaapi bochsdbg_stopped_at_debug_event(bool dlls_added)
{
	__debugbreak();
}

static int idaapi bochsdbg_thread_suspend(thid_t tid)
{
	__debugbreak();
	return 0;
}
static int idaapi bochsdbg_thread_continue(thid_t tid)
{
	__debugbreak();
	return 0;
}
static int idaapi bochsdbg_thread_set_step(thid_t tid)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_write_registers(thid_t tid, int regidx, const regval_t *value)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_thread_get_sreg_base(thid_t tid, int sreg_value, ea_t *answer)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_get_memory_info(meminfo_vec_t &areas)
{
	__debugbreak();
	return 0;
}

static ssize_t idaapi bochsdbg_read_memory(ea_t ea, void *buffer, size_t size)
{
	__debugbreak();
	return 0;
}

static ssize_t idaapi bochsdbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	__debugbreak();
	return 0; 
}

static int idaapi bochsdbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
	__debugbreak();
	return 0;
}

static ea_t idaapi bochsdbg_map_address(ea_t off, const regval_t *regs, int regnum)
{
	__debugbreak();
	return 0;
}

static ea_t idaapi bochsdbg_appcall(
	ea_t func_ea,
	thid_t tid,
	const struct func_type_info_t *fti,
	int nargs,
	const struct regobjs_t *regargs,
struct relobj_t *stkargs,
struct regobjs_t *retregs,
	qstring *errbuf,
	debug_event_t *event,
	int options)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_cleanup_appcall(thid_t tid)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_eval_lowcnd(thid_t tid, ea_t ea)
{
	__debugbreak();
	return 0;
}

static int idaapi bochsdbg_send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
	__debugbreak();
	return 0;
}

static debugger_t BOCHS_DBG = {
	IDD_INTERFACE_VERSION,
	"bochs debugger",
	DEBUGGER_ID_X86_IA32_BOCHS,
	"metapc",
	debugger_flags,

	REGISTER_CLASSES,
	REGISTER_CLASSES_DEFAULT,
	REGISTERS,
	REGISTERS_SIZE,
	MEMORY_PAGE_SIZE,

	bpt_code,
	sizeof(bpt_code),
	0,
	0,                    // reserved
	bochsdbg_init_debugger,
	bochsdbg_term_debugger,
	bochsdbg_process_get_info,
	bochsdbg_start_process,
	bochsdbg_attach_process,
	bochsdbg_detach_process, // detach_process:   patched at runtime if Windows XP/2K3
	NULL,
	bochsdbg_prepare_to_pause_process,
	bochsdbg_exit_process,

	bochsdbg_get_debug_event,
	bochsdbg_continue_after_event,
	bochsdbg_set_exception_info,
	bochsdbg_stopped_at_debug_event, //stopped_at_debug_event,

	bochsdbg_thread_suspend,
	bochsdbg_thread_continue,
	bochsdbg_thread_set_step,
	bochsdbg_read_registers,
	bochsdbg_write_registers,
	bochsdbg_thread_get_sreg_base,

	bochsdbg_get_memory_info,
	bochsdbg_read_memory,
	bochsdbg_write_memory,

	bochsdbg_is_ok_bpt,
	bochsdbg_update_bpts,
	bochsdbg_update_lowcnds,
	NULL,
	NULL,
	NULL,
	bochsdbg_map_address,
	bochsdbg_set_dbg_options, //SET_DBG_OPTIONS,
	bochsdbg_get_debmod_extensions, //GET_DEBMOD_EXTS,
	NULL, //UPDATE_CALL_STACK,
	bochsdbg_appcall,
	bochsdbg_cleanup_appcall,
	bochsdbg_eval_lowcnd, //s_eval_lowcnd,
	NULL,
	bochsdbg_send_ioctl,
};
/*

idaman plugin_t ida_export_data PlgExt;
debugger_t* BOCHS_DBG = reinterpret_cast<debugger_t*>(reinterpret_cast<char*>(&PlgExt) - 0xc4);


typedef struct{
__in_opt    LPCSTR lpApplicationName;
__inout_opt LPSTR lpCommandLine;
__in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes;
__in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes;
__in        BOOL bInheritHandles;
__in        DWORD dwCreationFlags;
__in_opt    LPVOID lpEnvironment;
__in_opt    LPCSTR lpCurrentDirectory;
__in        LPSTARTUPINFOA lpStartupInfo;
__out       LPPROCESS_INFORMATION lpProcessInformation;
}CreateProcessA_Args;
CreateProcessA_Args* _pCreateProcessA_Args;

typedef struct{
__in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes;
__in      SIZE_T dwStackSize;
__in      LPTHREAD_START_ROUTINE lpStartAddress;
__in_opt __deref __drv_aliasesMem LPVOID lpParameter;
__in      DWORD dwCreationFlags;
__out_opt LPDWORD lpThreadId;
}CreateThread_Args;
CreateThread_Args* _pCreateThread_Args;

typedef struct{
__out_ecount_full(1) PHANDLE hReadPipe;
__out_ecount_full(1) PHANDLE hWritePipe;
__in_opt LPSECURITY_ATTRIBUTES lpPipeAttributes;
__in     DWORD nSize;
}CreatePipe_Args;
CreatePipe_Args* _pCreatePipe_Args;

typedef struct{
__in        HANDLE hFile;
__out_bcount_part_opt(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer;
__in        DWORD nNumberOfBytesToRead;
__out_opt   LPDWORD lpNumberOfBytesRead;
__inout_opt LPOVERLAPPED lpOverlapped;
}ReadFile_Args;
ReadFile_Args* _pReadFile_Args;

typedef struct{
__in        HANDLE hFile;
__in_bcount_opt(nNumberOfBytesToWrite) LPCVOID lpBuffer;
__in        DWORD nNumberOfBytesToWrite;
__out_opt   LPDWORD lpNumberOfBytesWritten;
__inout_opt LPOVERLAPPED lpOverlapped;
}WriteFile_Args;
WriteFile_Args* _pWriteFile_Args;


*/
static int idaapi init(void)
{
	dbg = &BOCHS_DBG;
	return PLUGIN_KEEP;
}

static void idaapi term(void)
{
}

static void idaapi run(int arg)
{
}

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE | PLUGIN_DBG,
	init,
	term,
	run,
	"Bochs debugger plugin.",
	"Bochs debugger plugin\n",
	"Local Bochs debugger",
	"\0\0\0"
};
