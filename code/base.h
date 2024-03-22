/* date = March 22nd 2024 6:52 pm */

#ifndef BASE_H
#define BASE_H

#include <stdint.h>
typedef   uint8_t u8;
typedef    int8_t s8;

typedef uint16_t u16;
typedef  int16_t s16;

typedef uint32_t u32;
typedef  int32_t s32;

typedef uint64_t u64;
typedef  int64_t s64;

typedef s32 b32;

#include <stdio.h>

#define unused(v) (void)v
#define array_count(a) (sizeof(a)/sizeof(*(a)))
#define minimum(a,b) ((a)<(b)?(a):(b))
#define maximum(a,b) ((a)>(b)?(a):(b))
#define null 0

#define align_a_to_b(a,b) ((a)+((b)-1))&(~((b)-1))
#define kb(v) (1024llu*(v))
#define mb(v) (1024llu*kb(v))
#define copy_memory(dst,src,sz) memcpy(dst,src,sz)
#define clear_memory(d,sz) memset(d,'\0',sz)

#define invalid_index_u64 0xFFFFFFFFFFFFFFFF

#define function static
#define global static
#define local static

#define true 1
#define false 0

#define stmnt(s) do{s}while(0)
#define assert_break() (*(volatile int *)0=0)
#if defined(CDEBUG)
# define _assert(c) stmnt( if(!(c)) { assert_break(); } )
#else
# define _assert(c)
#endif

#define assert_true(c) _assert((c)==true)
#define assert_false(c) _assert((c)==false)

#define thread_var __declspec(thread)

#define sll_push_back(s, e, n) ((s)==0?((s)=(e)=(n),(n)->next=0):((e)->next=(n),(e)=(n)))
#define sll_push_front(s, n) ((s)==0?((s)=(n),(s)->next=0):(n)->next=(s),(s)=(n))

#define dll_push_back(first,last,node) ((first)==0)?((first)=(last)=(node)):((last)->next=(node),(node)->prev=(last),(last)=(node))
#define dll_remove(first,last,node) \
do {\
if((node)->prev){\
(node)->prev->next=(node)->next;\
}else{\
(first)=(node)->next;\
}\
if ((node)->next){\
(node)->next->prev=(node)->prev;\
}else{\
(last)=(node)->prev;\
}\
}while(0)

#endif //BASE_H
