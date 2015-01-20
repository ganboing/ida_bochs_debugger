#pragma once
#pragma warning( push )
#pragma warning( disable : 4127 )

#define ENUM_STRING_BEGIN(name) \
namespace {\
	namespace name##_get_str_namespace{\
		struct trival_base {\
			static const int value = -1;\
			static __forceinline const char* get_name(int) {\
				return NULL;\
			}\
		};\
		typedef trival_base 

#define ENUM_STRING_CLASS_DEF(name) \
		name##_base;\
		struct name##_classdef : name##_base\
		{\
			static const int value = name##_base::value + 1;\
			static_assert(value == name, "enum value mismatch");\
			static __forceinline const char* get_name(int idx){\
				if (idx == value)\
				{\
					return #name;\
				}\
				return name##_base::get_name(idx);\
			}\
		};\
		typedef name##_classdef 

#define ENUM_STRING_CLASS_DEF_VALUE(name, _value) \
		name##_base;\
		struct name##_classdef : name##_base\
		{\
			static const int value = _value;\
			static_assert(value == name, "enum value mismatch");\
			static __forceinline const char* get_name(int idx){\
				if (idx == value)\
				{\
					return #name;\
				}\
				return name##_base::get_name(idx);\
			}\
		};\
		typedef name##_classdef

#define ENUM_STRING_END(name) \
		final_base;\
	}\
	const char* name##_get_str(int idx)\
	{\
		return name##_get_str_namespace::final_base::get_name(idx);\
	}\
}

#define ENUM_BITFIELD_STRING_BEGIN(name) \
namespace {\
	namespace name##_get_str_namespace{\
		struct trival_base {\
			static const unsigned int value = unsigned(-1);\
			static const unsigned int nth = 0;\
			static __forceinline void get_name(const char** buf, unsigned int, bool) {\
				*buf = NULL;\
			}\
		};\
		typedef trival_base 

#define ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(name, _value) \
		name##_base;\
		struct name##_classdef : name##_base\
		{\
			static const unsigned int value = _value;\
			static_assert(value == name, "enum value mismatch");\
			static const unsigned int nth = name##_base::nth + 1;\
			static __forceinline void get_name(const char** buf, unsigned int idx, bool entry){\
				if ((!value && !entry) || (value & idx))\
				{\
					*buf = #name;\
					++buf;\
					idx ^= value;\
					entry = true;\
				}\
				return name##_base::get_name(buf, idx, entry);\
			}\
		};\
		typedef name##_classdef

#define ENUM_BITFIELD_STRING_END(name) \
		final_base;\
	}\
	void name##_get_str(const char** buf, unsigned int idx)\
	{\
		name##_get_str_namespace::final_base::get_name(buf, idx, false);\
	}\
	const unsigned int name##_buff_size = name##_get_str_namespace::final_base::nth + 1;\
}

/*#define ENUM_STRING_DECLAR(name)\
const char* name##_get_str(int idx);

#define ENUM_BITFIELD_STRING_DECLAR(name)\
void name##_get_str(const char** buf, unsigned int idx);
*/

/*ENUM_STRING_DECLAR(ui_notification_t)
ENUM_STRING_DECLAR(mbox_kind_t)
ENUM_STRING_DECLAR(gdecode_t)
ENUM_BITFIELD_STRING_DECLAR(event_id_t)
*/

ENUM_STRING_BEGIN(IDPOPT_TYPE)
ENUM_STRING_CLASS_DEF_VALUE(IDPOPT_STR, 1)
ENUM_STRING_CLASS_DEF_VALUE(IDPOPT_NUM, 2)
ENUM_STRING_CLASS_DEF_VALUE(IDPOPT_BIT, 3)
ENUM_STRING_CLASS_DEF_VALUE(IDPOPT_FLT, 4)
ENUM_STRING_CLASS_DEF_VALUE(IDPOPT_I64, 5)
ENUM_STRING_END(IDPOPT_TYPE)

ENUM_BITFIELD_STRING_BEGIN(event_id_t)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(NO_EVENT,			0x00000000)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(PROCESS_START,		0x00000001)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(PROCESS_EXIT,		0x00000002)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(THREAD_START,		0x00000004)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(THREAD_EXIT,		0x00000008)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(BREAKPOINT,		0x00000010)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(STEP,				0x00000020)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(EXCEPTION,			0x00000040)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(LIBRARY_LOAD,		0x00000080)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(LIBRARY_UNLOAD,	0x00000100)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(INFORMATION,		0x00000200)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(SYSCALL,			0x00000400)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(WINMESSAGE,		0x00000800)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(PROCESS_ATTACH,	0x00001000)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(PROCESS_DETACH,	0x00002000)
ENUM_BITFIELD_STRING_CLASS_DEF_VALUE(PROCESS_SUSPEND,	0x00004000)
ENUM_BITFIELD_STRING_END(event_id_t)

ENUM_STRING_BEGIN(gdecode_t)
ENUM_STRING_CLASS_DEF_VALUE(GDE_ERROR, -1)
ENUM_STRING_CLASS_DEF(GDE_NO_EVENT)
ENUM_STRING_CLASS_DEF(GDE_ONE_EVENT)
ENUM_STRING_CLASS_DEF(GDE_MANY_EVENTS)
ENUM_STRING_END(gdecode_t)

ENUM_STRING_BEGIN(ui_notification_t)
ENUM_STRING_CLASS_DEF_VALUE(ui_null, 0)
ENUM_STRING_CLASS_DEF(ui_range)
ENUM_STRING_CLASS_DEF(ui_list)
ENUM_STRING_CLASS_DEF(ui_idcstart)
ENUM_STRING_CLASS_DEF(ui_idcstop)
ENUM_STRING_CLASS_DEF(ui_suspend)
ENUM_STRING_CLASS_DEF(ui_resume)
ENUM_STRING_CLASS_DEF(ui_jumpto)
ENUM_STRING_CLASS_DEF(ui_readsel)
ENUM_STRING_CLASS_DEF(ui_unmarksel)
ENUM_STRING_CLASS_DEF(ui_screenea)
ENUM_STRING_CLASS_DEF(ui_saving)
ENUM_STRING_CLASS_DEF(ui_saved)
ENUM_STRING_CLASS_DEF(ui_refreshmarked)
ENUM_STRING_CLASS_DEF(ui_refresh)
ENUM_STRING_CLASS_DEF(ui_choose)
ENUM_STRING_CLASS_DEF(ui_close_chooser)
ENUM_STRING_CLASS_DEF(ui_banner)
ENUM_STRING_CLASS_DEF(ui_setidle)
ENUM_STRING_CLASS_DEF(ui_noabort)
ENUM_STRING_CLASS_DEF(ui_term)
ENUM_STRING_CLASS_DEF(ui_mbox)
ENUM_STRING_CLASS_DEF(ui_beep)
ENUM_STRING_CLASS_DEF(ui_msg)
ENUM_STRING_CLASS_DEF(ui_askyn)
ENUM_STRING_CLASS_DEF(ui_askfile)
ENUM_STRING_CLASS_DEF(ui_form)
ENUM_STRING_CLASS_DEF(ui_close_form)
ENUM_STRING_CLASS_DEF(ui_clearbreak)
ENUM_STRING_CLASS_DEF(ui_wasbreak)
ENUM_STRING_CLASS_DEF(ui_asktext)
ENUM_STRING_CLASS_DEF(ui_askstr)
ENUM_STRING_CLASS_DEF(ui_askident)
ENUM_STRING_CLASS_DEF(ui_askaddr)
ENUM_STRING_CLASS_DEF(ui_askseg)
ENUM_STRING_CLASS_DEF(ui_asklong)
ENUM_STRING_CLASS_DEF(ui_showauto)
ENUM_STRING_CLASS_DEF(ui_setstate)
ENUM_STRING_CLASS_DEF(ui_add_idckey)
ENUM_STRING_CLASS_DEF(ui_del_idckey)
ENUM_STRING_CLASS_DEF(ui_old_get_marker)
ENUM_STRING_CLASS_DEF(ui_analyzer_options)
ENUM_STRING_CLASS_DEF(ui_is_msg_inited)
ENUM_STRING_CLASS_DEF(ui_load_file)
ENUM_STRING_CLASS_DEF(ui_run_dbg)
ENUM_STRING_CLASS_DEF(ui_get_cursor)
ENUM_STRING_CLASS_DEF(ui_get_curline)
ENUM_STRING_CLASS_DEF(ui_get_hwnd)
ENUM_STRING_CLASS_DEF(ui_copywarn)
ENUM_STRING_CLASS_DEF(ui_getvcl)
ENUM_STRING_CLASS_DEF(ui_idp_event)
ENUM_STRING_CLASS_DEF(ui_lock_range_refresh)
ENUM_STRING_CLASS_DEF(ui_unlock_range_refresh)
ENUM_STRING_CLASS_DEF(ui_setbreak)
ENUM_STRING_CLASS_DEF(ui_genfile_callback)
ENUM_STRING_CLASS_DEF(ui_open_url)
ENUM_STRING_CLASS_DEF(ui_hexdumpea)
ENUM_STRING_CLASS_DEF(ui_set_xml)
ENUM_STRING_CLASS_DEF(ui_get_xml)
ENUM_STRING_CLASS_DEF(ui_del_xml)
ENUM_STRING_CLASS_DEF(ui_push_xml)
ENUM_STRING_CLASS_DEF(ui_pop_xml)
ENUM_STRING_CLASS_DEF(ui_get_key_code)
ENUM_STRING_CLASS_DEF(ui_setup_plugins_menu)
ENUM_STRING_CLASS_DEF(ui_refresh_navband)
ENUM_STRING_CLASS_DEF(ui_new_custom_viewer)
ENUM_STRING_CLASS_DEF(ui_add_menu_item)
ENUM_STRING_CLASS_DEF(ui_del_menu_item)
ENUM_STRING_CLASS_DEF(ui_debugger_menu_change)
ENUM_STRING_CLASS_DEF(ui_get_curplace)
ENUM_STRING_CLASS_DEF(ui_create_tform)
ENUM_STRING_CLASS_DEF(ui_open_tform)
ENUM_STRING_CLASS_DEF(ui_close_tform)
ENUM_STRING_CLASS_DEF(ui_switchto_tform)
ENUM_STRING_CLASS_DEF(ui_find_tform)
ENUM_STRING_CLASS_DEF(ui_get_current_tform)
ENUM_STRING_CLASS_DEF(ui_get_tform_handle)
ENUM_STRING_CLASS_DEF(ui_tform_visible)
ENUM_STRING_CLASS_DEF(ui_tform_invisible)
ENUM_STRING_CLASS_DEF(ui_get_ea_hint)
ENUM_STRING_CLASS_DEF(ui_get_item_hint)
ENUM_STRING_CLASS_DEF(ui_set_nav_colorizer)
ENUM_STRING_CLASS_DEF(ui_refresh_custom_viewer)
ENUM_STRING_CLASS_DEF(ui_destroy_custom_viewer)
ENUM_STRING_CLASS_DEF(ui_jump_in_custom_viewer)
ENUM_STRING_CLASS_DEF(ui_set_custom_viewer_popup)
ENUM_STRING_CLASS_DEF(ui_add_custom_viewer_popup)
ENUM_STRING_CLASS_DEF(ui_set_custom_viewer_handlers)
ENUM_STRING_CLASS_DEF(ui_get_custom_viewer_curline)
ENUM_STRING_CLASS_DEF(ui_get_current_viewer)
ENUM_STRING_CLASS_DEF(ui_is_idaview)
ENUM_STRING_CLASS_DEF(ui_get_custom_viewer_hint)
ENUM_STRING_CLASS_DEF(ui_readsel2)
ENUM_STRING_CLASS_DEF(ui_set_custom_viewer_range)
ENUM_STRING_CLASS_DEF(ui_database_inited)
ENUM_STRING_CLASS_DEF(ui_ready_to_run)
ENUM_STRING_CLASS_DEF(ui_set_custom_viewer_handler)
ENUM_STRING_CLASS_DEF(ui_refresh_chooser)
ENUM_STRING_CLASS_DEF(ui_add_chooser_cmd)
ENUM_STRING_CLASS_DEF(ui_open_builtin)
ENUM_STRING_CLASS_DEF(ui_preprocess)
ENUM_STRING_CLASS_DEF(ui_postprocess)
ENUM_STRING_CLASS_DEF(ui_set_custom_viewer_mode)
ENUM_STRING_CLASS_DEF(ui_gen_disasm_text)
ENUM_STRING_CLASS_DEF(ui_gen_idanode_text)
ENUM_STRING_CLASS_DEF(ui_install_cli)
ENUM_STRING_CLASS_DEF(ui_execute_sync)
ENUM_STRING_CLASS_DEF(ui_enable_input_hotkeys)
ENUM_STRING_CLASS_DEF(ui_get_chooser_obj)
ENUM_STRING_CLASS_DEF(ui_enable_chooser_item_attrs)
ENUM_STRING_CLASS_DEF(ui_get_chooser_item_attrs)
ENUM_STRING_CLASS_DEF(ui_set_dock_pos)
ENUM_STRING_CLASS_DEF(ui_get_opnum)
ENUM_STRING_CLASS_DEF(ui_install_custom_datatype_menu)
ENUM_STRING_CLASS_DEF(ui_install_custom_optype_menu)
ENUM_STRING_CLASS_DEF(ui_get_range_marker)
ENUM_STRING_CLASS_DEF(ui_get_highlighted_identifier)
ENUM_STRING_CLASS_DEF(ui_lookup_key_code)
ENUM_STRING_CLASS_DEF(ui_load_custom_icon_file)
ENUM_STRING_CLASS_DEF(ui_load_custom_icon)
ENUM_STRING_CLASS_DEF(ui_free_custom_icon)
ENUM_STRING_CLASS_DEF(ui_process_action)
ENUM_STRING_CLASS_DEF(ui_last)
ENUM_STRING_CLASS_DEF_VALUE(ui_dbg_begin, 1000)
ENUM_STRING_CLASS_DEF_VALUE(ui_dbg_run_requests, ui_dbg_begin)
ENUM_STRING_CLASS_DEF(ui_dbg_get_running_request)
ENUM_STRING_CLASS_DEF(ui_dbg_get_running_notification)
ENUM_STRING_CLASS_DEF(ui_dbg_clear_requests_queue)
ENUM_STRING_CLASS_DEF(ui_dbg_get_process_state)
ENUM_STRING_CLASS_DEF(ui_dbg_start_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_start_process)
ENUM_STRING_CLASS_DEF(ui_dbg_suspend_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_suspend_process)
ENUM_STRING_CLASS_DEF(ui_dbg_continue_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_continue_process)
ENUM_STRING_CLASS_DEF(ui_dbg_exit_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_exit_process)
ENUM_STRING_CLASS_DEF(ui_dbg_get_thread_qty)
ENUM_STRING_CLASS_DEF(ui_dbg_getn_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_select_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_request_select_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_step_into)
ENUM_STRING_CLASS_DEF(ui_dbg_request_step_into)
ENUM_STRING_CLASS_DEF(ui_dbg_step_over)
ENUM_STRING_CLASS_DEF(ui_dbg_request_step_over)
ENUM_STRING_CLASS_DEF(ui_dbg_run_to)
ENUM_STRING_CLASS_DEF(ui_dbg_request_run_to)
ENUM_STRING_CLASS_DEF(ui_dbg_step_until_ret)
ENUM_STRING_CLASS_DEF(ui_dbg_request_step_until_ret)
ENUM_STRING_CLASS_DEF(ui_dbg_get_oldreg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_set_oldreg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_request_set_oldreg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_get_bpt_qty)
ENUM_STRING_CLASS_DEF(ui_dbg_getn_oldbpt)
ENUM_STRING_CLASS_DEF(ui_dbg_get_oldbpt)
ENUM_STRING_CLASS_DEF(ui_dbg_add_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_request_add_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_del_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_request_del_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_update_oldbpt)
ENUM_STRING_CLASS_DEF(ui_dbg_enable_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_request_enable_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_set_trace_size)
ENUM_STRING_CLASS_DEF(ui_dbg_clear_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_request_clear_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_is_step_trace_enabled)
ENUM_STRING_CLASS_DEF(ui_dbg_enable_step_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_request_enable_step_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_get_step_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_set_step_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_request_set_step_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_is_insn_trace_enabled)
ENUM_STRING_CLASS_DEF(ui_dbg_enable_insn_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_request_enable_insn_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_get_insn_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_set_insn_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_request_set_insn_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_is_func_trace_enabled)
ENUM_STRING_CLASS_DEF(ui_dbg_enable_func_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_request_enable_func_trace)
ENUM_STRING_CLASS_DEF(ui_dbg_get_func_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_set_func_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_request_set_func_trace_options)
ENUM_STRING_CLASS_DEF(ui_dbg_get_tev_qty)
ENUM_STRING_CLASS_DEF(ui_dbg_get_tev_info)
ENUM_STRING_CLASS_DEF(ui_dbg_get_insn_tev_oldreg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_get_insn_tev_oldreg_result)
ENUM_STRING_CLASS_DEF(ui_dbg_get_call_tev_callee)
ENUM_STRING_CLASS_DEF(ui_dbg_get_ret_tev_return)
ENUM_STRING_CLASS_DEF(ui_dbg_get_bpt_tev_ea)
ENUM_STRING_CLASS_DEF(ui_dbg_get_reg_value_type)
ENUM_STRING_CLASS_DEF(ui_dbg_get_process_qty)
ENUM_STRING_CLASS_DEF(ui_dbg_get_process_info)
ENUM_STRING_CLASS_DEF(ui_dbg_attach_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_attach_process)
ENUM_STRING_CLASS_DEF(ui_dbg_detach_process)
ENUM_STRING_CLASS_DEF(ui_dbg_request_detach_process)
ENUM_STRING_CLASS_DEF(ui_dbg_get_first_module)
ENUM_STRING_CLASS_DEF(ui_dbg_get_next_module)
ENUM_STRING_CLASS_DEF(ui_dbg_bring_to_front)
ENUM_STRING_CLASS_DEF(ui_dbg_get_current_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_wait_for_next_event)
ENUM_STRING_CLASS_DEF(ui_dbg_get_debug_event)
ENUM_STRING_CLASS_DEF(ui_dbg_set_debugger_options)
ENUM_STRING_CLASS_DEF(ui_dbg_set_remote_debugger)
ENUM_STRING_CLASS_DEF(ui_dbg_load_debugger)
ENUM_STRING_CLASS_DEF(ui_dbg_retrieve_exceptions)
ENUM_STRING_CLASS_DEF(ui_dbg_store_exceptions)
ENUM_STRING_CLASS_DEF(ui_dbg_define_exception)
ENUM_STRING_CLASS_DEF(ui_dbg_suspend_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_request_suspend_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_resume_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_request_resume_thread)
ENUM_STRING_CLASS_DEF(ui_dbg_get_process_options)
ENUM_STRING_CLASS_DEF(ui_dbg_check_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_set_process_state)
ENUM_STRING_CLASS_DEF(ui_dbg_get_manual_regions)
ENUM_STRING_CLASS_DEF(ui_dbg_set_manual_regions)
ENUM_STRING_CLASS_DEF(ui_dbg_enable_manual_regions)
ENUM_STRING_CLASS_DEF(ui_dbg_set_process_options)
ENUM_STRING_CLASS_DEF(ui_dbg_is_busy)
ENUM_STRING_CLASS_DEF(ui_dbg_hide_all_bpts)
ENUM_STRING_CLASS_DEF(ui_dbg_edit_manual_regions)
ENUM_STRING_CLASS_DEF(ui_dbg_get_reg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_set_reg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_request_set_reg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_get_insn_tev_reg_val)
ENUM_STRING_CLASS_DEF(ui_dbg_get_insn_tev_reg_result)
ENUM_STRING_CLASS_DEF(ui_dbg_register_provider)
ENUM_STRING_CLASS_DEF(ui_dbg_unregister_provider)
ENUM_STRING_CLASS_DEF(ui_dbg_handle_debug_event)
ENUM_STRING_CLASS_DEF(ui_dbg_add_vmod)
ENUM_STRING_CLASS_DEF(ui_dbg_del_vmod)
ENUM_STRING_CLASS_DEF(ui_dbg_compare_bpt_locs)
ENUM_STRING_CLASS_DEF(ui_dbg_save_bpts)
ENUM_STRING_CLASS_DEF(ui_dbg_getn_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_get_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_update_bpt)
ENUM_STRING_CLASS_DEF(ui_dbg_set_bptloc_string)
ENUM_STRING_CLASS_DEF(ui_dbg_get_bptloc_string)
ENUM_STRING_CLASS_DEF(ui_dbg_internal_appcall)
ENUM_STRING_CLASS_DEF(ui_dbg_internal_cleanup_appcall)
ENUM_STRING_CLASS_DEF(ui_dbg_internal_get_sreg_base)
ENUM_STRING_CLASS_DEF(ui_dbg_internal_ioctl)
ENUM_STRING_CLASS_DEF(ui_dbg_end)
ENUM_STRING_END(ui_notification_t)

ENUM_STRING_BEGIN(mbox_kind_t)
ENUM_STRING_CLASS_DEF(mbox_internal)               // internal error
ENUM_STRING_CLASS_DEF(mbox_info)
ENUM_STRING_CLASS_DEF(mbox_warning)
ENUM_STRING_CLASS_DEF(mbox_error)
ENUM_STRING_CLASS_DEF(mbox_nomem)
ENUM_STRING_CLASS_DEF(mbox_feedback)
ENUM_STRING_CLASS_DEF(mbox_readerror)
ENUM_STRING_CLASS_DEF(mbox_writeerror)
ENUM_STRING_CLASS_DEF(mbox_filestruct)
ENUM_STRING_CLASS_DEF(mbox_wait)
ENUM_STRING_CLASS_DEF(mbox_hide)
ENUM_STRING_CLASS_DEF(mbox_replace)
ENUM_STRING_END(mbox_kind_t)

ENUM_STRING_BEGIN(processor_id)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_386, 0)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_Z80, 1)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_I860, 2)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_8051, 3)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMS, 4)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_6502, 5)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_PDP, 6)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_68K, 7)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_JAVA, 8)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_6800, 9)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_ST7, 10)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_MC6812, 11)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_MIPS, 12)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_ARM, 13)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMSC6, 14)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_PPC, 15)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_80196, 16)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_Z8, 17)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_SH, 18)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_NET, 19)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_AVR, 20)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_H8, 21)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_PIC, 22)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_SPARC, 23)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_ALPHA, 24)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_HPPA, 25)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_H8500, 26)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TRICORE, 27)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_DSP56K, 28)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_C166, 29)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_ST20, 30)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_IA64, 31)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_I960, 32)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_F2MC, 33)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMS320C54, 34)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMS320C55, 35)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TRIMEDIA, 36)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_M32R, 37)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_NEC_78K0, 38)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_NEC_78K0S, 39)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_M740, 40)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_M7700, 41)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_ST9, 42)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_FR, 43)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_MC6816, 44)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_M7900, 45)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMS320C3, 46)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_KR1878, 47)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_AD218X, 48)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_OAKDSP, 49)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TLCS900, 50)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_C39, 51)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_CR16, 52)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_MN102L00, 53)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_TMS320C1X, 54)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_NEC_V850X, 55)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_SCR_ADPT, 56)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_EBC, 57)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_MSP430, 58)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_SPU, 59)
ENUM_STRING_CLASS_DEF_VALUE(PLFM_DALVIK, 60)
ENUM_STRING_END(processor_id)

#pragma warning( pop )