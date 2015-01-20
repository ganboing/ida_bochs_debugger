#pragma once
#include <stdexcept>

class SehToCxxExcept{
private:
	_se_translator_function old_translator;
public:
	SehToCxxExcept();
	~SehToCxxExcept();
};

class EhStatus{
public:
	unsigned int code;
	EhStatus(unsigned int);
};