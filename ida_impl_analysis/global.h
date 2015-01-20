struct processor_t;
struct idainfo;
struct auto_display_t;
struct debugger_t;
class plugin_t;
struct extlang_t;

/*extern processor_t local_ph;
extern idainfo local_inf;
extern uint32 local_debug;
extern auto_display_t local_auto_display;
extern debugger_t *local_dbg;
extern extlang_t* local_extlang;*/

extern debugger_t* pBochsDbg;
extern plugin_t* pBochsPlugin;
extern debugger_t BochsDbgShadow;
extern plugin_t BochsPlgShadow;