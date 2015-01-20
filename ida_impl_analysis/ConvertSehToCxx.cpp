#include <Windows.h>
#include "ConvertSehToCxx.h"

static void __cdecl trans_func(unsigned int code, EXCEPTION_POINTERS*)
{
	throw EhStatus(code);
}

SehToCxxExcept::SehToCxxExcept(){
	old_translator = _set_se_translator(trans_func);
}

SehToCxxExcept::~SehToCxxExcept(){
	_set_se_translator(old_translator);
}

EhStatus::EhStatus(unsigned int _code) : code(_code){}