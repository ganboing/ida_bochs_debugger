

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Sat Aug 09 17:46:53 2014
 */
/* Compiler settings for bochs_rpc.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0603 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if !defined(_M_IA64) && !defined(_M_AMD64) && !defined(_ARM_)


#pragma warning( disable: 4049 )  /* more than 64k source lines */
#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/
#pragma warning( disable: 4100 ) /* unreferenced arguments in x86 call */

#pragma optimize("", off ) 

#include <string.h>

#include "bochs_rpc.h"

#define TYPE_FORMAT_STRING_SIZE   7                                 
#define PROC_FORMAT_STRING_SIZE   35                                
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _bochs_rpc_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } bochs_rpc_MIDL_TYPE_FORMAT_STRING;

typedef struct _bochs_rpc_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } bochs_rpc_MIDL_PROC_FORMAT_STRING;

typedef struct _bochs_rpc_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } bochs_rpc_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};


extern const bochs_rpc_MIDL_TYPE_FORMAT_STRING bochs_rpc__MIDL_TypeFormatString;
extern const bochs_rpc_MIDL_PROC_FORMAT_STRING bochs_rpc__MIDL_ProcFormatString;
extern const bochs_rpc_MIDL_EXPR_FORMAT_STRING bochs_rpc__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: RefPtrInterface, ver. 1.0,
   GUID={0xba209999,0x0c6c,0x11d2,{0x97,0xcf,0x00,0xc0,0x4f,0x8e,0xea,0x45}} */



static const RPC_CLIENT_INTERFACE RefPtrInterface___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0xba209999,0x0c6c,0x11d2,{0x97,0xcf,0x00,0xc0,0x4f,0x8e,0xea,0x45}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE RefPtrInterface_v1_0_c_ifspec = (RPC_IF_HANDLE)& RefPtrInterface___RpcClientInterface;

extern const MIDL_STUB_DESC RefPtrInterface_StubDesc;

static RPC_BINDING_HANDLE RefPtrInterface__MIDL_AutoBindHandle;


void RemoteFn( 
    /* [in] */ handle_t IDL_handle,
    /* [unique][in] */ unsigned char *ach)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RefPtrInterface_StubDesc,
                  (PFORMAT_STRING) &bochs_rpc__MIDL_ProcFormatString.Format[0],
                  ( unsigned char * )&IDL_handle);
    
}


#if !defined(__RPC_WIN32__)
#error  Invalid build platform for this stub.
#endif

#if !(TARGET_IS_NT50_OR_LATER)
#error You need Windows 2000 or later to run this stub because it uses these features:
#error   /robust command line switch.
#error However, your C/C++ compilation flags indicate you intend to run this app on earlier systems.
#error This app will fail with the RPC_X_WRONG_STUB_VERSION error.
#endif


static const bochs_rpc_MIDL_PROC_FORMAT_STRING bochs_rpc__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure RemoteFn */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x19 ),	/* 25 */
/* 16 */	NdrFcShort( 0x0 ),	/* 0 */
/* 18 */	0x40,		/* Oi2 Flags:  has ext, */
			0x1,		/* 1 */
/* 20 */	0x8,		/* 8 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter IDL_handle */

/* 28 */	NdrFcShort( 0xa ),	/* Flags:  must free, in, */
/* 30 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 32 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

			0x0
        }
    };

static const bochs_rpc_MIDL_TYPE_FORMAT_STRING bochs_rpc__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/*  4 */	0x2,		/* FC_CHAR */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

static const unsigned short RefPtrInterface_FormatStringOffsetTable[] =
    {
    0
    };


static const MIDL_STUB_DESC RefPtrInterface_StubDesc = 
    {
    (void *)& RefPtrInterface___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &RefPtrInterface__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    bochs_rpc__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x50002, /* Ndr library version */
    0,
    0x800025b, /* MIDL Version 8.0.603 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x1, /* MIDL flag */
    0, /* cs routines */
    0,   /* proxy/server info */
    0
    };
#pragma optimize("", on )
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* !defined(_M_IA64) && !defined(_M_AMD64) && !defined(_ARM_) */

