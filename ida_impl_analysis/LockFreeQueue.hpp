#pragma once
#include <Windows.h>
#include <cstdint>

template<size_t size>
class CheckSize;

template<>
class CheckSize < 0 > {};

template<size_t Capacity>
class AtomicBitMap : CheckSize < Capacity % 8 > {
private:
	volatile uint8_t map[Capacity / 8];
public:
	AtomicBitMap();
	bool IsSet(size_t nth);
	void Set(size_t nth);
	void Unset(size_t nth);
	void Flip(size_t nth);
};

template<size_t Capacity>
AtomicBitMap<Capacity>::AtomicBitMap()
{
	memset((void*)map, 0, Capacity / 8);
}

template<size_t Capacity>
bool AtomicBitMap<Capacity>::IsSet(size_t nth)
{
	size_t idx = nth / 8;
	uint8_t mask = uint8_t(1) << nth % unsigned(8);
	return !!(map[idx] & mask);
}

template<size_t Capacity>
void AtomicBitMap<Capacity>::Set(size_t nth)
{
	size_t idx = nth / 8;
	uint8_t mask = uint8_t(1) << nth % unsigned(8);
	_InterlockedOr8((volatile char*)map + idx, mask);
}

template<size_t Capacity>
void AtomicBitMap<Capacity>::Unset(size_t nth)
{
	size_t idx = nth / 8;
	uint8_t mask = uint8_t(1) << nth % unsigned(8);
	_InterlockedAnd8((volatile char*)map + idx, ~mask);
}

template<size_t Capacity>
void AtomicBitMap<Capacity>::Flip(size_t nth)
{
	size_t idx = nth / 8;
	uint8_t mask = uint8_t(1) << nth % unsigned(8);
	_InterlockedXor8((volatile char*)map + idx, mask);
}

template<class T, size_t Capacity>
class LockFreeQueue {
private:
	AtomicBitMap<Capacity> Bitmap;
	volatile T queue[Capacity];
	volatile unsigned long ptrval;
	union packed_ptr{
		unsigned long val;
		struct{
			unsigned short size;
			unsigned short head;
		};
	};
public:
	static const size_t Cap = Capacity;
	volatile T* Acquire();
	void Commit(volatile const T* pElement);
	volatile T* Front();
	void Dequeue();
	uint32_t Size() const;
	bool Empty() const;
};

template<class T, size_t Capacity>
void LockFreeQueue<T, Capacity>::Commit(volatile const T* pElement)
{
	MemoryBarrier();
	Bitmap.Set(pElement - queue);
}

template<class T, size_t Capacity>
volatile T* LockFreeQueue<T, Capacity>::Front()
{
	packed_ptr old_ptrs;
	old_ptrs.val = ptrval;
	if (Bitmap.IsSet(old_ptrs.head))
	{
		return queue + old_ptrs.head;
	}
	else
	{
		return NULL;
	}
}

template<class T, size_t Capacity>
uint32_t LockFreeQueue<T, Capacity>::Size() const
{
	packed_ptr old_ptrs;
	old_ptrs.val = ptrval;
	return old_ptrs.size;
}

template<class T, size_t Capacity>
bool LockFreeQueue<T, Capacity>::Empty() const
{
	return !Size();
}

template<class T, size_t Capacity>
void LockFreeQueue<T, Capacity>::Dequeue()
{
	MemoryBarrier();
	packed_ptr old_ptrs;
	old_ptrs.val = ptrval;
	Bitmap.Unset(old_ptrs.head);
	packed_ptr new_ptrs;
	do
	{
		old_ptrs.val = ptrval;
		new_ptrs.head = old_ptrs.head;
		new_ptrs.head %= Capacity;
		new_ptrs.size = old_ptrs.size - 1;
	} while (InterlockedCompareExchange(&ptrval, new_ptrs.val, old_ptrs.val) != old_ptrs.val);
}

template<class T, size_t Capacity>
volatile T* LockFreeQueue<T, Capacity>::Acquire()
{
	packed_ptr old_ptrs;
	for (;;)
	{
		old_ptrs.val = ptrval;
		if (old_ptrs.size < Capacity)
		{
			packed_ptr new_ptrs;
			new_ptrs.head = old_ptrs.head;
			new_ptrs.size = old_ptrs.size + 1;
			if (InterlockedCompareExchange(&ptrval, new_ptrs.val, old_ptrs.val) == old_ptrs.val)
			{
				return queue + (old_ptrs.head + old_ptrs.size) % Capacity;
			}
		}
		else
		{
			return NULL;
		}
	}
}
