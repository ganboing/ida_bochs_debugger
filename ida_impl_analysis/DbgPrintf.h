#pragma once

#include <tuple>
#include <stdint.h>
#include <atomic>
#include <type_traits>

typedef volatile const char* LPVCSTR;
//typedef volatile char* LPVSTR;

#pragma warning(push)
#pragma warning( disable : 4200)

void __vDbgPrintfA(const char* format, va_list args);
void __DbgPrintfA(const char* format...);
void __vDbgPrintfW(const wchar_t* format, va_list args);
void __DbgPrintfW(const wchar_t* format...);

namespace DbgPrintfInternal{

	static const size_t DbgBuffObjSize = 0x400UL;
	static const size_t DbgBuffObjLines = 0x100UL;

	void CheckIfStaticStr(const char* Str);
	void CheckIfDynamicStr(volatile const char* Str);
	size_t MyStrNCpy(char* Dest, const volatile char* Src, size_t n);

	class PrintSlot{
	public:
		virtual void Print() const = 0;
	};	

	template<size_t ...>
	struct seq{};

	template<size_t N, size_t ...S>
	struct gens : gens < N - 1, N - 1, S... > { };

	template<size_t ...S>
	struct gens < 0, S... > {
		typedef seq<S...> type;
	};

	template <typename ...Args>
	class SpecializedSlot : public PrintSlot
	{
		char* StrDup(const volatile char* Str)
		{
			if (!Str)
			{
				return NULL;
			}
			size_t SpaceLeft = DbgBuffPrintSlotMaxSize - (StrBuffPtr - (char*)this);
			if (SpaceLeft)
			{
				char* ret = StrBuffPtr;
				size_t DupSize = MyStrNCpy(StrBuffPtr, Str, SpaceLeft);
				StrBuffPtr += DupSize;
				return ret;
			}
			else
			{
				return "[<<No Space>>]";
			}
		}

		template<typename S>
		struct qual{
			typedef S type;
			static_assert(!::std::is_class<S>::value, "parameter is class type");
		};

		template<>
		struct qual<volatile char*> {
			typedef char* type;
		};

		template<>
		struct qual < const volatile char* > {
			typedef char* type;
		};

		template<typename S>
		typename qual<S>::type StrDupFilter(S Para)
		{
			return Para;
		}

		template<>
		char* StrDupFilter(const volatile char* Str)
		{
			CheckIfDynamicStr(Str);
			return StrDup(Str);
		}

		template<>
		char* StrDupFilter(volatile char* Str)
		{
			CheckIfDynamicStr(Str);
			return StrDup(Str);
		}

		template<>
		const char* StrDupFilter(const char* Str)
		{
			CheckIfStaticStr(Str);
			return Str;
		}

		template<>
		char* StrDupFilter(char* Str)
		{
			CheckIfStaticStr(Str);
			return Str;
		}

		typedef ::std::tuple<typename qual<Args>::type ...> ParameterPack_t;
		struct _paras
		{
			char* buf;
			ParameterPack_t pack;
		}paras;
		char padding[
			DbgBuffObjSize - sizeof(paras) - sizeof(void*) //take care of the vptr
		];

		template <size_t... S>
		void apply(seq<S...>) const
		{
			__DbgPrintfA(::std::get<S>(paras.pack)...);
		}
	public:
		SpecializedSlot(Args... args) : paras{ pack, ParameterPack_t(StrDupFilter(args)...) }{

		}
		virtual void Print() const{
			apply(typename gens<sizeof...(Args)>::type());
		}
	};

	PrintSlot* ReQuestSlotAt(size_t Level);
	PrintSlot* ReQuestSlotLess(size_t Level);
	void CommitSlot(PrintSlot* pSlot);
}

#pragma warning(pop)

template <typename ...Args>
void DbgPrint(Args... args)
{
	static_assert(offsetof(DbgPrintfInternal::SpecializedSlot<Args...>, StrBuff) < DbgPrintfInternal::DbgBuffPrintSlotMaxSize,
		 "Parameter Pack Too large!");
	DbgPrintfInternal::PrintSlot* pPrintSlot = DbgPrintfInternal::ReQuestSlotAt(0);
	new (pPrintSlot)DbgPrintfInternal::SpecializedSlot<Args...>(args...);
	DbgPrintfInternal::CommitSlot(pPrintSlot);
}

/*template <typename ...Args>
void DbgPrintLevel(size_t Level, Args... args)
{
	static_assert(offsetof(DbgPrintfInternal::SpecializedSlot<Args...>, StrBuff) < DbgPrintfInternal::DbgBuffPrintSlotMaxSize,
		"Parameter Pack Too large!");
	DbgPrintfInternal::PrintSlot* pPrintSlot = DbgPrintfInternal::ReQuestSlotLess(Level);
	new (pPrintSlot)DbgPrintfInternal::SpecializedSlot<Args...>(args...);
	DbgPrintfInternal::CommitSlot(pPrintSlot);
}
*/
void InitDbgPrint();

void DeInitDbgPrint();
