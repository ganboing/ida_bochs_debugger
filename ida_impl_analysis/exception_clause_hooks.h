namespace BochsUserCatchDataAccess{
	namespace DBG{
		bool __stdcall init_debugger(const char *hostname, int portnum, const char *password);
		void __stdcall set_exception_info(const exception_info_t *info, int qty);
		int __stdcall continue_after_event(const debug_event_t *event);
		bool __stdcall term_debugger(void);
		int __stdcall exit_process(void);
		int __stdcall process_get_info(int n, process_info_t *info);
		int __stdcall detach_process(void);
		int __stdcall prepare_to_pause_process(void);
		const char * _stdcall set_dbg_options(const char *keyword, int value_type, const void *value);
		gdecode_t __stdcall get_debug_event(debug_event_t *event, int timeout_ms);
		int __stdcall start_process(const char *path, const char *args, const char *startdir, int dbg_proc_flags, const char *input_path, uint32 input_file_crc32);
		int __stdcall attach_process(pid_t pid, int event_id);
		void __stdcall rebase_if_required_to(ea_t new_base);
		int __stdcall read_registers(thid_t tid, int clsmask, regval_t *values);
		int __stdcall write_register(thid_t tid, int regidx, const regval_t *value);
		ssize_t __stdcall read_memory(ea_t ea, void *buffer, size_t size);
		ssize_t __stdcall write_memory(ea_t ea, const void *buffer, size_t size);
		void __stdcall stopped_at_debug_event(bool dlls_added);
		int __stdcall thread_suspend(thid_t tid);
		int __stdcall thread_continue(thid_t tid);
		int __stdcall thread_set_step(thid_t tid);
	}
	namespace PLG{
		int __stdcall init(void);
		void __stdcall term(void);
		void __stdcall run(int arg);
	}
}