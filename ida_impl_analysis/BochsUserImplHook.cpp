#include <type_traits>
#include <typeinfo>
#include "global_win.h"
#include "DbgPrintf.h"

#pragma warning(push,3)
#include <ida.hpp>
#include <idd.hpp>
#include <idp.hpp>
#include <loader.hpp>
#pragma warning(pop)
#include "exception_clause_hooks.h"
#include "global.h"
#include "EnumToString.h"

static void print_event_id_t(const debug_event_t* event)
{
	const char* buf[event_id_t_buff_size];
	event_id_t_get_str(buf, event->eid);
	DbgPrint("{ eid (%X)=", event->eid);
	for (size_t i = 0; buf[i] != NULL; ++i)
	{
		DbgPrint("%s | ", buf[i]);
	}
	DbgPrint(", pid=%d, tid=%d, ea=%X, handled=%d}", event->pid, event->tid, event->ea, event->handled);
}

#define REDIRECT_TO_CATCHER(x) (BochsUserCatchDataAccess::DBG::x)
#define REDIRECT_TO_CATCHER_PLG(x) (BochsUserCatchDataAccess::PLG::x)

namespace BochsUserImplHook{

	namespace DBG{
		static void __stdcall set_exception_info(const exception_info_t *info, int qty)
		{
			DbgPrint("[set_exception_info] called with qty=%d, detail:\n", qty);
			for (int i = 0; i < qty; ++i)
			{
				DbgPrint("  exception %d, name=%s\n", i, (LPVCSTR)info[i].name.c_str());
			}
			REDIRECT_TO_CATCHER(set_exception_info(info, qty));
			DbgPrint("[set_exception_info] returned\n");
		}

		static int __stdcall continue_after_event(const debug_event_t *event)
		{
			int ret;
			DbgPrint("[continue_after_event] called\n  event=\n");
			print_event_id_t(event);
			DbgPrint("\n");
			ret = REDIRECT_TO_CATCHER(continue_after_event(event));
			DbgPrint("[continue_after_event] returned %d\n", ret);
			return ret;
		}

		static bool __stdcall term_debugger(void)
		{
			bool ret;
			DbgPrint("[term_debugger] called\n");
			ret = REDIRECT_TO_CATCHER(term_debugger());
			DbgPrint("[term_debugger] returned %d\n", ret);
			return ret;
		}

		static int __stdcall exit_process(void)
		{
			int ret;
			DbgPrint("[exit_process] called\n");
			ret = REDIRECT_TO_CATCHER(exit_process());
			DbgPrint("[exit_process] returned %d\n", ret);
			return ret;
		}

		static int __stdcall process_get_info(int n, process_info_t *info)
		{
			int ret;
			DbgPrint("[process_get_info] called with n=%d, info=%p\n", n, info);
			ret = REDIRECT_TO_CATCHER(process_get_info(n, info));
			DbgPrint("[process_get_info] returned %d\n", ret);
			return ret;
		}

		static int __stdcall detach_process(void)
		{
			int ret;
			DbgPrint("[detach_process] called\n");
			ret = REDIRECT_TO_CATCHER(detach_process());
			DbgPrint("[detach_process] returned %d\n", ret);
			return ret;
		}

		static int __stdcall prepare_to_pause_process(void)
		{
			int ret;
			DbgPrint("[prepare_to_pause_process] called\n");
			ret = REDIRECT_TO_CATCHER(prepare_to_pause_process());
			DbgPrint("[prepare_to_pause_process] returned %d\n", ret);
			return ret;
		}

		static const char * _stdcall set_dbg_options(const char *keyword, int value_type, const void *value)
		{
			const char* ret;
			DbgPrint("[set_dbg_options] called with keyword=%s, valuetype=%d, value=%p\n  type: %s value=", (LPVCSTR)keyword, value_type, value, IDPOPT_TYPE_get_str(value_type));
			switch (value_type)
			{
			case IDPOPT_STR:
				// string constant (char *)
				DbgPrint("%s", (LPVCSTR)value);
				break;
			case IDPOPT_NUM:
				// number (uval_t *)
				DbgPrint("%d", *(uval_t*)value);
				break;
			case IDPOPT_BIT:
				// bit, yes/no (int *)
				DbgPrint("%d", *(int*)value);
				break;
			case IDPOPT_FLT:
				// float (double *)
				DbgPrint("%f", *(double*)value);
				break;
			case IDPOPT_I64:
				// 64bit number (int64 *)
				DbgPrint("%I64", *(int64*)value);
				break;
			}
			DbgPrint("\n");
			ret = REDIRECT_TO_CATCHER(set_dbg_options(keyword, value_type, value));
			DbgPrint("[set_dbg_options] returned %s\n", (LPVCSTR)ret);
			return ret;
		}

		static bool __stdcall init_debugger(const char *hostname, int portnum, const char *password)
		{
			bool ret;
			DbgPrint("[init_debugger] called with hostname=%p, portnum=%d, password=%p\n", (void*)hostname, portnum, (void*)password);
			ret = REDIRECT_TO_CATCHER(init_debugger(hostname, portnum, password));
			if (pBochsDbg->detach_process)
			{
				BochsDbgShadow.detach_process = pBochsDbg->detach_process;
				pBochsDbg->detach_process = detach_process;
			}
			if (pBochsDbg->process_get_info)
			{
				BochsDbgShadow.process_get_info = pBochsDbg->process_get_info;
				pBochsDbg->process_get_info = process_get_info;
			}
			DbgPrint("[init_debugger] returned %d\n", ret);
			return ret;
		}

		static gdecode_t __stdcall get_debug_event(debug_event_t *event, int timeout_ms)
		{
			DbgPrint("[get_debug_event] called with event=%p, timeout_ms=%d\n", event, timeout_ms);
			gdecode_t ret = REDIRECT_TO_CATCHER(get_debug_event(event, timeout_ms));
			DbgPrint("[get_debug_event] returned ret=%s, event=", gdecode_t_get_str(ret));
			print_event_id_t(event);
			DbgPrint("\n");
			return ret;
		}

		static int __stdcall start_process(const char *path, const char *args, const char *startdir, int dbg_proc_flags, const char *input_path, uint32 input_file_crc32)
		{
			int ret;
			DbgPrint("[start_process] called with path=%s, args=%s, startdir=%s, dbg_proc_flags=%X, input_path=%s, input_file_crc32=%X\n", (LPVCSTR)path, (LPVCSTR)args, (LPVCSTR)startdir, dbg_proc_flags, (LPVCSTR)input_path, input_file_crc32);
			ret = REDIRECT_TO_CATCHER(start_process(path, args, startdir, dbg_proc_flags, input_path, input_file_crc32));
			DbgPrint("[start_process] returned %d\n", ret);
			return ret;
		}

		static int __stdcall attach_process(pid_t pid, int event_id)
		{
			int ret;
			DbgPrint("[attach_process] called with pid=%d, event_id=%d\n", pid, event_id);
			ret = REDIRECT_TO_CATCHER(attach_process(pid, event_id));
			DbgPrint("[attach_process] returned %d\n", ret);
			return ret;
		}

		static void __stdcall rebase_if_required_to(ea_t new_base)
		{
			DbgPrint("[rebase_if_required_to] called with new_base = %X\n", new_base);
			REDIRECT_TO_CATCHER(rebase_if_required_to(new_base));
			DbgPrint("[rebase_if_required_to] returned\n");
		}

		static int __stdcall read_registers(thid_t tid, int clsmask, regval_t *values)
		{
			return REDIRECT_TO_CATCHER(read_registers(tid, clsmask, values));
		}

		static int __stdcall write_register(thid_t tid, int regidx, const regval_t *value)
		{
			return REDIRECT_TO_CATCHER(write_register(tid, regidx, value));
		}
		static ssize_t __stdcall read_memory(ea_t ea, void *buffer, size_t size)
		{
			return REDIRECT_TO_CATCHER(read_memory(ea, buffer, size));
		}
		static ssize_t __stdcall write_memory(ea_t ea, const void *buffer, size_t size)
		{
			return REDIRECT_TO_CATCHER(write_memory(ea, buffer, size));
		}
		static void __stdcall stopped_at_debug_event(bool dlls_added)
		{
			return REDIRECT_TO_CATCHER(stopped_at_debug_event(dlls_added));
		}
		static int __stdcall thread_suspend(thid_t tid)
		{
			return REDIRECT_TO_CATCHER(thread_suspend(tid));
		}
		static int __stdcall thread_continue(thid_t tid)
		{
			return REDIRECT_TO_CATCHER(thread_continue(tid));
		}
		static int __stdcall thread_set_step(thid_t tid)
		{
			return REDIRECT_TO_CATCHER(thread_set_step(tid));
		}
	}

	namespace PLG{
		static int __stdcall init(void)
		{
			return REDIRECT_TO_CATCHER_PLG(init());
		}
		static void __stdcall term(void)
		{
			return REDIRECT_TO_CATCHER_PLG(term());
		}
		static void __stdcall run(int arg)
		{
			return REDIRECT_TO_CATCHER_PLG(run(arg));
		}
	}
}

template <class P>
static const inline bool CheckIfFuncPointer(P)
{
	//DbgPrintfA("CHECKING TYPE: %s\n", typeid(P).name());
	return (
		::std::is_pointer<P>::value 
		&& 
		::std::is_function<::std::remove_pointer<P>::type>::value
	);
}

#define HOOK_DBG_FUNC(name)\
	do{\
		if(!pBochsDbg->name)\
		{\
			DbgPrint("DBG Function "#name"should not be hooked\n");\
			abort();\
		}\
		pBochsDbg->name = BochsUserImplHook::DBG::name;\
		DbgPrint("BochsDbg->" #name " hooked\n");\
			}while(0)

#define HOOK_PLG_FUNC(name)\
	do{\
		pBochsPlugin->name = BochsUserImplHook::PLG::name;\
		DbgPrint("BochsPlugin->" #name " hooked\n");\
				}while(0)

#define CHECK_DBG_FUNC_HOOK(name)\
	do{\
		if(CheckIfFuncPointer(pBochsDbg->name) && (BochsDbgShadow.name))\
		{\
			if(pBochsDbg->name == BochsDbgShadow.name)\
			{\
				DbgPrint("$$$$BochsDbg->"#name" has not been hooked\n");\
			}\
		}\
	}while(0)


plugin_t R();

void HookCallsFromIda()
{
	BochsDbgShadow = *pBochsDbg;
	BochsPlgShadow = *pBochsPlugin;
#pragma warning( push )
#pragma warning( disable : 4127 )
	HOOK_DBG_FUNC(init_debugger);
	HOOK_DBG_FUNC(term_debugger);
	//HOOK_DBG_FUNC(process_get_info);
	HOOK_DBG_FUNC(start_process);
	HOOK_DBG_FUNC(attach_process);
	//HOOK_DBG_FUNC(detach_process);
	HOOK_DBG_FUNC(rebase_if_required_to);
	HOOK_DBG_FUNC(prepare_to_pause_process);
	HOOK_DBG_FUNC(exit_process);
	HOOK_DBG_FUNC(get_debug_event);
	HOOK_DBG_FUNC(continue_after_event);
	HOOK_DBG_FUNC(set_dbg_options);
	HOOK_DBG_FUNC(set_exception_info);
	HOOK_DBG_FUNC(read_registers);
	HOOK_DBG_FUNC(write_register);
	HOOK_DBG_FUNC(read_memory);
	HOOK_DBG_FUNC(write_memory);
	HOOK_DBG_FUNC(stopped_at_debug_event);
	HOOK_DBG_FUNC(thread_suspend);
	HOOK_DBG_FUNC(thread_continue);
	HOOK_DBG_FUNC(thread_set_step);

	HOOK_PLG_FUNC(init);
	HOOK_PLG_FUNC(term);
	HOOK_PLG_FUNC(run);

	CHECK_DBG_FUNC_HOOK(version);
	CHECK_DBG_FUNC_HOOK(name);
	CHECK_DBG_FUNC_HOOK(id);
	CHECK_DBG_FUNC_HOOK(processor);
	CHECK_DBG_FUNC_HOOK(flags);
	CHECK_DBG_FUNC_HOOK(register_classes);
	CHECK_DBG_FUNC_HOOK(register_classes_default);
	CHECK_DBG_FUNC_HOOK(registers);
	CHECK_DBG_FUNC_HOOK(registers_size);
	CHECK_DBG_FUNC_HOOK(memory_page_size);
	CHECK_DBG_FUNC_HOOK(bpt_bytes);
	CHECK_DBG_FUNC_HOOK(bpt_size);
	CHECK_DBG_FUNC_HOOK(filetype);
	CHECK_DBG_FUNC_HOOK(reserved);
	CHECK_DBG_FUNC_HOOK(init_debugger);
	CHECK_DBG_FUNC_HOOK(term_debugger);
	CHECK_DBG_FUNC_HOOK(process_get_info);
	CHECK_DBG_FUNC_HOOK(start_process);
	CHECK_DBG_FUNC_HOOK(attach_process);
	CHECK_DBG_FUNC_HOOK(detach_process);
	CHECK_DBG_FUNC_HOOK(rebase_if_required_to);
	CHECK_DBG_FUNC_HOOK(prepare_to_pause_process);
	CHECK_DBG_FUNC_HOOK(exit_process);
	CHECK_DBG_FUNC_HOOK(get_debug_event);
	CHECK_DBG_FUNC_HOOK(continue_after_event);
	CHECK_DBG_FUNC_HOOK(set_exception_info);
	CHECK_DBG_FUNC_HOOK(stopped_at_debug_event);
	CHECK_DBG_FUNC_HOOK(thread_suspend);
	CHECK_DBG_FUNC_HOOK(thread_continue);
	CHECK_DBG_FUNC_HOOK(thread_set_step);
	CHECK_DBG_FUNC_HOOK(read_registers);
	CHECK_DBG_FUNC_HOOK(write_register);
	CHECK_DBG_FUNC_HOOK(thread_get_sreg_base);
	CHECK_DBG_FUNC_HOOK(get_memory_info);
	CHECK_DBG_FUNC_HOOK(read_memory);
	CHECK_DBG_FUNC_HOOK(write_memory);
	CHECK_DBG_FUNC_HOOK(is_ok_bpt);
	CHECK_DBG_FUNC_HOOK(update_bpts);
	CHECK_DBG_FUNC_HOOK(update_lowcnds);
	CHECK_DBG_FUNC_HOOK(open_file);
	CHECK_DBG_FUNC_HOOK(close_file);
	CHECK_DBG_FUNC_HOOK(read_file);
	CHECK_DBG_FUNC_HOOK(map_address);
	CHECK_DBG_FUNC_HOOK(set_dbg_options);
	CHECK_DBG_FUNC_HOOK(get_debmod_extensions);
	CHECK_DBG_FUNC_HOOK(update_call_stack);
	CHECK_DBG_FUNC_HOOK(appcall);
	CHECK_DBG_FUNC_HOOK(cleanup_appcall);
	CHECK_DBG_FUNC_HOOK(eval_lowcnd);
	CHECK_DBG_FUNC_HOOK(write_file);
	CHECK_DBG_FUNC_HOOK(send_ioctl);

#pragma warning( pop )
}

void RestoreHallsFromIda()
{
	*pBochsPlugin = BochsPlgShadow;
	*pBochsDbg = BochsDbgShadow;
}