#include <Windows.h>
#include <intrin.h>
#include "HookIAT.h"
#include "DbgPrintf.h"
#include "global_win.h"
#include "asm_stub.h"

#pragma warning(push,3)
#include <ida.hpp>
#include <idd.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <err.h>
#include <name.hpp>
#include <expr.hpp>
#include <auto.hpp>
#include <loader.hpp>
#pragma warning(pop)
#include "EnumToString.h"
#include "global.h"

DWORD __test()
{
	return __readfsdword(0);
}

DWORD LocalStorTlsIdx;

static void CheckRootNode(const netnode* p)
{
	if (*p == RootNode)
	{
		DbgPrint("&RootNode");
	}
	else
	{
		DbgPrint("%p, idx=%X", p, nodeidx_t(*p));
	}
}

static void CheckRootNode(nodeidx_t idx)
{
	if (RootNode == idx)
	{
		DbgPrint("RootNode");
	}
	else
	{
		DbgPrint("%X", idx);
	}
}

static const ULONG_PTR TF_LOCAL_STOR_MASK = ((ULONG_PTR)1 << (sizeof(ULONG_PTR) * 8 - 1));

extern "C"
{
	static LPVOID __stdcall GetLocalStor(VOID)
	{
		return TlsGetValue(LocalStorTlsIdx);
	}

	static VOID _stdcall SetLocalStor(LPVOID value)
	{
		TlsSetValue(LocalStorTlsIdx, value);
	}

	LPVOID __stdcall GetLocalStorRestoreTF(VOID)
	{
		ULONG_PTR ret = (ULONG_PTR)GetLocalStor();
		if (ret & TF_LOCAL_STOR_MASK)
		{
			ret &= ~TF_LOCAL_STOR_MASK;
			SetTF();
		}
		return (LPVOID)ret;
	}

	VOID _stdcall SetLocalStorResetTF(LPVOID value)
	{
		ULONG_PTR set = (ULONG_PTR)value;
		if (GetTF())
		{
			EndCatching();
			set |= TF_LOCAL_STOR_MASK;
		}
		SetLocalStor((LPVOID)set);
	}

	void __cdecl _callui_pre(ui_notification_t what, ...)
	{
		DbgPrint("callui called from %x, with what = %d(%s)\n details = ", GetLocalStor(), what, ui_notification_t_get_str(what));
		va_list args;
		va_start(args, what);
		switch (what)
		{
		case ui_form:
			// * Show a dialog form
			// Parameters:
			//      const char *format
			//      va_list va
			// Returns: bool 0-esc, 1-ok
		{
			const char* format = va_arg(args, const char*);
			//va_list para = va_arg(args, va_list);
			DbgPrint("%s", (LPVCSTR)format);
		}
			break;
		case ui_mbox:
			// * Show a message box
			// Parameters:
			//      mbox_kind_t kind
			//      const char *format
			//      va_list va
			// Returns: none
		{
			mbox_kind_t kind = va_arg(args, mbox_kind_t);
			const char* format = va_arg(args, const char*);
			//va_list va = va_arg(args, va_list);
			DbgPrint("kind = %s, format = %s", mbox_kind_t_get_str(kind), (LPVCSTR)format);
			//vDbgPrintfA(format, va);
		}
			break;
		case ui_install_cli:
			// * install command line interpreter
			// cli_t *cp,
			// bool install
			// Returns: nothing
		{
			cli_t* cp = va_arg(args, cli_t*);
			bool install = va_arg(args, bool);
			DbgPrint("cp = %p, install = %d", cp, install);
		}
			break;
		case ui_del_menu_item:
			// * del a menu item
			// Parameters: const char *menupath
			// Returns:    bool
		{
			const char* menupath = va_arg(args, const char*);
			DbgPrint("menupath = %s", (LPVCSTR)menupath);
		}
			break;
		case ui_add_menu_item:
			// * add a menu item
			// Parameters: const char *menupath,
			//             const char *name,
			//             const char *hotkey,
			//             int flags,
			//             menu_item_callback_t *callback,
			//             void *ud
			// Returns:    bool
		{
			const char* menupath = va_arg(args, const char*);
			const char* name = va_arg(args, const char*);
			const char* hotkey = va_arg(args, const char*);
			int flags = va_arg(args, int);
			menu_item_callback_t* callback = va_arg(args, menu_item_callback_t*);
			void* ud = va_arg(args, void*);
			DbgPrint("menupath=%s, name=%s, hotkey=%s, flags=%X, callback=%p, ud=%p", (LPVCSTR)menupath, (LPVCSTR)name, (LPVCSTR)hotkey, flags, callback, ud);
		}
			break;
		case ui_msg:
			// * Show a message in the message window
			// Parameters:
			//      const char *format
			//      va_list va
			// Returns: number of bytes output
		{
			const char* format = va_arg(args, const char*);
			//va_list va = va_arg(args, va_list);
			DbgPrint("%s", (LPVCSTR)format);
		}
			break;
		}
		DbgPrint("\n");
		va_end(args);
	}

	void __cdecl _callui_post(callui_t ret, ui_notification_t what, ...)
	{
		va_list args;
		va_start(args, what);
		switch (what)
		{
		case ui_readsel:
			// * Get the selected area boundaries
			// Parameters:
			//      ea_t *startea
			//      ea_t *endea
			// Returns: bool
			//          0 - no area is selected
			//          1 - ok, startea and endea are filled
			// See also: ui_readsel2
		{
			ea_t *startea = va_arg(args, ea_t*);
			ea_t *endea = va_arg(args, ea_t*);
			DbgPrint(" | ret=%d, startea=%p, endea=%p ", ret.cnd, *startea, *endea);
		}
			break;
		case ui_screenea:
			// * Return the address at the screen cursor
			// Parameters: ea_t *result
			// Returns:    none
		{
			ea_t* result = va_arg(args, ea_t*);
			DbgPrint(" | result=%p", *result);
		}
			break;
		}
		DbgPrint("\n");
		va_end(args);
	}

	callui_t __cdecl _callui_mod(ui_notification_t what, ...);

	void __cdecl qmakepath_pre(char* /*buf*/, size_t /*bufsize*/, const char *s1, ...)
	{
		DbgPrint("qmakepath called from %X with names=\n", GetLocalStor());
		va_list args;
		va_start(args, s1);
		for (const char* s = s1; s != NULL; s = va_arg(args, const char*))
		{
			DbgPrint("  str=%s\n", (LPVCSTR)s);
		}
		va_end(args);
	}

	void __cdecl qmakepath_post(char* /*ret*/, char *buf, size_t /*bufsize*/, const char* /*s1*/, ...)
	{
		DbgPrint("qmakepath returned with buf=%s\n", (LPVCSTR)buf);
	}
	char *__cdecl qmakepath_mod(char *buf, size_t bufsize, const char *s1, ...);
}

class DisableSingleStep{
	bool tf;
public:
	DisableSingleStep() : tf(!!GetTF())
	{
		EndCatching();
	}
	~DisableSingleStep()
	{
		if (tf)
		{
			SetTF();
		}
	}
};

#define DISABLE_CATCH DisableSingleStep _disable_catch

namespace IdaWllHook{

	static void __stdcall set_error_data(int n, size_t data)
	{
		DISABLE_CATCH;
		DbgPrint("set_error_data called with n=%d, data=%I\n", n, data);
		return ::set_error_data(n, data);
	}

	static const char *__stdcall get_error_string(int n)
	{
		DISABLE_CATCH;
		DbgPrint("get_error_string called with n=%d\n", n);
		const char* ret = ::get_error_string(n);
		DbgPrint("get_error_string returned = %s", (LPVCSTR)ret);
		return ret;
	}

	static void __stdcall set_error_string(int n, const char *str)
	{
		DISABLE_CATCH;
		DbgPrint("set_error_string called with n=%d, str=%s", n, (LPVCSTR)str);
		return ::set_error_string(n, str);
	}

	static ssize_t __stdcall get_root_filename(char *buf, size_t bufsize)
	{
		DISABLE_CATCH;
		ssize_t ret;
		memset(buf, 0, bufsize);
		DbgPrint("get_root_filename called | ");
		ret = ::get_root_filename(buf, bufsize);
		if (ret > 0)
		{
			DbgPrint("returned %s\n", (LPVCSTR)buf);
		}
		else
		{
			DbgPrint("\n");
		}
		return ret;
	}

	static bool  __stdcall netnode_check(netnode * pnode, const char *name, size_t namlen, bool create)
	{
		DISABLE_CATCH;
		bool ret;
		DbgPrint("netnode_check called with p=");
		CheckRootNode(pnode);
		DbgPrint(", name=%s, namlen=%d, create=%d", (LPVCSTR)name, namlen, create);
		ret = ::netnode_check(pnode, name, namlen, create);
		DbgPrint(" | returned idx=%X, %d\n", nodeidx_t(*pnode), ret);
		return ret;
	}

	static bool  __stdcall netnode_exist(const netnode &n)
	{
		DISABLE_CATCH;
		bool ret;
		DbgPrint("netnode_exist called with p=");
		CheckRootNode(&n);
		ret = ::netnode_exist(n);
		DbgPrint(" | returned %d\n", ret);
		return ret;
	}

	static nodeidx_t __stdcall netnode_altval(nodeidx_t num, nodeidx_t alt, char tag)
	{
		DISABLE_CATCH;
		nodeidx_t ret;
		DbgPrint("netnode_altval called with num=");
		CheckRootNode(num);
		DbgPrint(", alt=%d, tag=%c", alt, tag);
		ret = ::netnode_altval(num, alt, tag);
		DbgPrint(" | returned %d\n", ret);
		return ret;
	}

	static ssize_t __stdcall netnode_supstr(nodeidx_t num, nodeidx_t alt, char *buf, size_t bufsize, char tag)
	{
		DISABLE_CATCH;
		ssize_t ret;
		if (buf)
		{
			memset(buf, 0, bufsize);
		}
		DbgPrint("netnode_supstr called with num=");
		CheckRootNode(num);
		DbgPrint(", alt=%d, tag=%c | ", alt, tag);
		ret = ::netnode_supstr(num, alt, buf, bufsize, tag);
		if (ret > 0)
		{
			DbgPrint("returned %s\n", (LPVCSTR)buf);
		}
		else
		{
			DbgPrint("\n");
		}
		return ret;
	}

	static bool __stdcall netnode_supset(nodeidx_t num, nodeidx_t alt, const void *value, size_t length, char tag)
	{
		DISABLE_CATCH;
		bool ret;
		DbgPrint("netnode_supset called from %p, with num=", _ReturnAddress());
		CheckRootNode(num);
		DbgPrint(", alt=%d, value=%p, length=%d, tag=%c, ", alt, value, length, tag);
		switch (length)
		{
		case 0:
			DbgPrint("value is str = %s", (LPVCSTR)value);
			break;
		case 4:
			DbgPrint("value is int = %d", *(const int*)value);
			break;
		}
		ret = ::netnode_supset(num, alt, value, length, tag);
		DbgPrint(" | returned %d\n", ret);
		return ret;
	}

	static ssize_t __stdcall get_loader_name(char *buf, size_t bufsize)
	{
		DISABLE_CATCH;
		ssize_t ret;
		if (buf)
		{
			memset(buf, 0, bufsize);
		}
		DbgPrint("get_loader_name called | ");
		ret = ::get_loader_name(buf, bufsize);
		if (ret > 0)
		{
			DbgPrint("returned %s", (LPVCSTR)buf);
		}
		else
		{
			DbgPrint("\n");
		}
		return ret;
	}

	static int __stdcall set_debug_names(const ea_t *addrs, const char *const *names, int qty)
	{
		DISABLE_CATCH;
		DbgPrint("set_debug_names called");
		if (qty > 0)
		{
			DbgPrint(" details:\n");
			for (int i = 0; i != qty; ++i)
			{
				DbgPrint("  addr=%X, name=%s\n", addrs[i], (LPVCSTR)names[i]);
			}
		}
		return ::set_debug_names(addrs, names, qty);
	}

	static bool  __stdcall qfileexist(const char *file)
	{
		DISABLE_CATCH;
		DbgPrint("qfileexist called with file=%s", (LPVCSTR)file);
		bool ret = ::qfileexist(file);
		DbgPrint(" | returned %d\n", ret);
		return ret;
	}

	static bool __stdcall CompileEx(const char *file, int cpl_flags, char *errbuf, size_t errbufsize)
	{
		DISABLE_CATCH;
		DbgPrint("CompileLine called with file=%s, cpl_flags=%X", (LPVCSTR)file, cpl_flags);
		bool ret = ::CompileEx(file, cpl_flags, errbuf, errbufsize);
		DbgPrint(" | returned %d\n", ret);
		if (!ret)
		{
			DbgPrint("  Error Str=%s\n", (LPVCSTR)errbuf);
		}
		return ret;
	}

	static bool __stdcall CompileLineEx(const char *line, char *errbuf, size_t errbufsize, uval_t(idaapi*_getname)(const char *name), bool only_safe_funcs)
	{
		DISABLE_CATCH;
		DbgPrint("CompileLine called with line=%s, _getname=%p, only_safe_funcs=%d", (LPVCSTR)line, _getname, only_safe_funcs);
		bool ret = ::CompileLineEx(line, errbuf, errbufsize, _getname, only_safe_funcs);
		DbgPrint(" | returned %d\n", ret);
		if (!ret)
		{
			DbgPrint("  Error Str=%s\n", (LPVCSTR)errbuf);
		}
		return ret;
	}

	static FILE *__stdcall qfopen(const char *file, const char *mode)
	{
		DISABLE_CATCH;
		DbgPrint("qfopen called with file=%s, mode=%s\n", (LPVCSTR)file, (LPVCSTR)mode);
		return ::qfopen(file, mode);
	}

	static callui_t(__cdecl* callui)(ui_notification_t what, ...) = _callui_mod;
}

#define IDA_WLL_EXPORT_ENT(x)\
	{ #x, (&IdaWllHook::x != &x)?&IdaWllHook::x :0 }

#define IDA_WLL_EXPORT_ENT_LOCAL(x, y)\
	{ #x, (&x != &y)?&y :0 }

static FuncDesc_t ImpHookers[] =
{
	IDA_WLL_EXPORT_ENT(set_error_data),
	IDA_WLL_EXPORT_ENT(set_error_data),
	IDA_WLL_EXPORT_ENT(get_error_string),
	IDA_WLL_EXPORT_ENT(callui),
	IDA_WLL_EXPORT_ENT(get_root_filename),
	IDA_WLL_EXPORT_ENT(netnode_check),
	IDA_WLL_EXPORT_ENT(netnode_exist),
	IDA_WLL_EXPORT_ENT(netnode_altval),
	IDA_WLL_EXPORT_ENT(netnode_supstr),
	IDA_WLL_EXPORT_ENT(netnode_supset),
	IDA_WLL_EXPORT_ENT(get_loader_name),
	IDA_WLL_EXPORT_ENT(set_error_string),
	IDA_WLL_EXPORT_ENT(set_debug_names),
	IDA_WLL_EXPORT_ENT(qfileexist),
	IDA_WLL_EXPORT_ENT_LOCAL(qmakepath, qmakepath_mod),
	IDA_WLL_EXPORT_ENT(CompileEx),
	IDA_WLL_EXPORT_ENT(CompileLineEx),
	IDA_WLL_EXPORT_ENT(qfopen),
	//IDA_WLL_EXPORT_ENT_LOCAL(debug, local_debug),
	//IDA_WLL_EXPORT_ENT_LOCAL(extlang, local_extlang),
	//IDA_WLL_EXPORT_ENT_LOCAL(dbg, local_dbg),
	//IDA_WLL_EXPORT_ENT_LOCAL(inf, local_inf),
	//IDA_WLL_EXPORT_ENT_LOCAL(ph, local_ph),
	//IDA_WLL_EXPORT_ENT_LOCAL(auto_display, local_auto_display),
	{ NULL, NULL }
};

static SlotDesc_t ImpOrigStore[_countof(ImpHookers)];

static LPCSTR FuncsExcluded[] = {
	"qalloc",
	"qrealloc",
	"qcalloc",
	"qfree",
	"qalloc_or_throw",
	"qrealloc_or_throw",
	"qvsnprintf",
	"qvsscanf",
	"qsnprintf",
	"qvprintf",
	"append_snprintf",
	"qsscanf",
	"qstrlen",
	"qstrchr",
	"qstrstr",
	"qstrrchr",
	"qstrcmp",
	"qstrdup",
	"qfopen",
	"qfread",
	"qfwrite",
	"qftell",
	"qfseek",
	"qfclose",
	"qflush",
	"qtmpfile",
	"qrename",
	"qstrncat",
	"qstrncpy",
	"qstpncpy",
	"qsplitfile",
	"qsem_free",
	"qsem_post",
	"qsem_wait",
	"qsem_create",
	"qisdir",
	"qdirname",
	"qbasename",
	"qfputc",
	"qfgets",
	"qlread",
	"qlsize",
	"qlseek",
	"qlgets",
	"lread",
	"qlgetz",
	"idadir",
	"interr",
	"qstrerror",
	"strrpl",
	"u2cstr",
	"c2ustr",
	"get_file_ext",
	"get_qerrno",
	"RootNode",
	"winerr",
	"skipSpaces",
	"database_idb",
	NULL
};

void HookCallsToIdaWll()
{
	HookImpCalls(hBochsUserImpl, "IDA.WLL", ImpHookers, ImpOrigStore, TRUE, FuncsExcluded);
}

