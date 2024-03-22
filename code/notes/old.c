#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef near
#undef far

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

#define fn static
#define glb static
#define loc static

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

inline void *
os_reserve_memory(u64 reserve_size) {
	void *result = VirtualAlloc(0, reserve_size, MEM_RESERVE, PAGE_NOACCESS);
	return(result);
}

inline b32
os_commit_memory(void *memory_to_commit, u64 commit_size) {
    b32 result = VirtualAlloc(memory_to_commit, commit_size, MEM_COMMIT, PAGE_READWRITE) != null;
	return(result);
}

inline b32
os_decommit_memory(void *memory_to_decommit, u64 decommit_size) {
    b32 result = VirtualFree(memory_to_decommit, decommit_size, MEM_DECOMMIT) != 0;
    return(result);
}

inline b32
os_released_memory(void *memory_to_release) {
    b32 result = VirtualFree(memory_to_release, 0, MEM_RELEASE) != 0;
    return(result);
}

#define memory_arena_default_commit kb(256llu)
typedef struct {
	u8 *memory;
	u64 capacity;
	u64 stack_ptr;
	u64 commit_ptr;
} Memory_Arena;

typedef struct {
	Memory_Arena *base;
	u64 start_stack_ptr;
} Temporary_Memory;

fn Memory_Arena *
arena_reserve(u64 reserve_size_bytes) {
    Memory_Arena *result = null;
    void *block = os_reserve_memory(reserve_size_bytes);
    
    if (block) {
        u64 initial_commit = align_a_to_b(sizeof(Memory_Arena), 8);
        if (os_commit_memory(block, initial_commit)) {
            result = (Memory_Arena *)(block);
            result->memory = (u8 *)(block);
            result->capacity = reserve_size_bytes;
            result->stack_ptr = initial_commit;
            result->commit_ptr = initial_commit;
        }
    }
    
    return(result);
}

#define arena_push_array(arena,type,count) (type *)(arena_push_size(arena,sizeof(type)*(count)))
#define arena_push_struct(arena,type) arena_push_array(arena,type,1)
fn void *
arena_push_size(Memory_Arena *arena, u64 push_size_bytes) {
    void *block = null;
    push_size_bytes = align_a_to_b(push_size_bytes, 8);
    u64 desired_new_stack_ptr = arena->stack_ptr + push_size_bytes;
    if (desired_new_stack_ptr <= arena->capacity) {
        void *result_block_on_success = arena->memory + arena->stack_ptr;
        u64 desired_new_commit_ptr = arena->commit_ptr;
        
        if (desired_new_stack_ptr > arena->commit_ptr) {
            const u64 commit_size = memory_arena_default_commit;
            u64 new_commit_ptr = align_a_to_b(desired_new_stack_ptr, commit_size);
            u64 new_commit_ptr_clamped = minimum(new_commit_ptr, arena->capacity);
            
            if (os_commit_memory(arena->memory + arena->commit_ptr,
                                 new_commit_ptr_clamped - arena->commit_ptr)) {
                desired_new_commit_ptr = new_commit_ptr_clamped;
            }
        }
        
        if (desired_new_stack_ptr <= desired_new_commit_ptr) {
            block = result_block_on_success;
            arena->stack_ptr = desired_new_stack_ptr;
            arena->commit_ptr = desired_new_commit_ptr;
        }
    }
    
    return(block);
}

#define arena_push_array_zero(arena,type,count) (type *)(arena_push_size_zero(arena,sizeof(type)*(count)))
#define arena_push_struct_zero(arena,type) arena_push_array_zero(arena,type,1)
fn void *
arena_push_size_zero(Memory_Arena *arena, u64 push_size_bytes) {
    void *result = arena_push_size(arena, push_size_bytes);
    clear_memory(result, align_a_to_b(push_size_bytes, 8));
    return(result);
}

fn void
arena_pop_size(Memory_Arena *arena, u64 pop_size_bytes)
{
    pop_size_bytes = align_a_to_b(pop_size_bytes, 8);
    if (pop_size_bytes <= (arena->stack_ptr + align_a_to_b(sizeof(Memory_Arena), 8))) {
        arena->stack_ptr -= pop_size_bytes;
        const u64 commit_size = memory_arena_default_commit;
        u64 new_commit_ptr = align_a_to_b(arena->stack_ptr, commit_size);
        
        if (new_commit_ptr < arena->commit_ptr) {
            os_decommit_memory(arena->memory + new_commit_ptr, arena->commit_ptr - new_commit_ptr);
            arena->commit_ptr = new_commit_ptr;
        }
    }
}

inline Temporary_Memory
temp_mem_begin(Memory_Arena *arena) {
    Temporary_Memory result;
    result.base = arena;
    result.start_stack_ptr = arena->stack_ptr;
    return(result);
}

inline void
temp_mem_end(Temporary_Memory temp) {
    if (temp.base && (temp.start_stack_ptr < temp.base->stack_ptr)) {
        arena_pop_size(temp.base, temp.base->stack_ptr - temp.start_stack_ptr);
    }
}

#define scratch_count 4
glb thread_var Memory_Arena *per_thread_scratch[scratch_count] = { 0 };

fn Memory_Arena *
arena_get_scratch(Memory_Arena **conflict_array, u32 conflict_count) {
	if (per_thread_scratch[0] == null) {
		for (u32 index = 0; index < scratch_count; ++index) {
			per_thread_scratch[index] = arena_reserve(mb(8));
		}
	}
    
	Memory_Arena *result = null;
	for (u32 scratch_index = 0; scratch_index < scratch_count; ++scratch_index) {
		Memory_Arena *possible_arena = per_thread_scratch[scratch_index];
        b32 is_non_conflict = 1;
        
		for (u32 conflict_index = 0; conflict_index < conflict_count; ++conflict_index) {
			if (possible_arena == conflict_array[conflict_index]) {
				is_non_conflict = 0;
				break;
			}
		}
        
		if (is_non_conflict) {
			result = possible_arena;
			break;
		}
	}
    
	return(result);
}

inline b32 
is_alpha(u8 c) {
    b32 result = ((c >= 'a') && (c <= 'z') ||
                  (c >= 'A') && (c <= 'Z'));
    return(result);
}

inline b32
is_digit(u8 c) {
    b32 result = (c >= '0') && (c <= '9');
    return(result);
}

inline b32
is_alpha_numeric(u8 c) {
    b32 result = is_alpha(c) || is_digit(c);
    return(result);
}

#define str8(s) str8_from_cstr_view(s,sizeof(s)-1)
typedef struct {
    u8 *str;
    u64 char_count;
    u64 char_capacity;
} String_U8;

typedef String_U8 String_Const_U8;

inline String_Const_U8
str8_from_cstr_view(char *str, u64 char_count) {
    String_Const_U8 result;
    result.str = (u8 *)str;
    result.char_count = char_count;
    result.char_capacity = char_count;
    
    return(result);
}

inline String_U8
str8_reserve(Memory_Arena *arena, u64 char_count) {
    String_U8 result;
    result.str = arena_push_array(arena, u8, char_count);
    result.char_count = 0;
    result.char_capacity = char_count;
    return(result);
}

inline String_U8
str8_copy(Memory_Arena *arena, String_Const_U8 source) {
    String_U8 result = str8_reserve(arena, source.char_capacity);
    result.char_count = source.char_count;
    copy_memory(result.str, source.str, result.char_capacity);
    return(result);
}

inline String_Const_U8
str8_substring_view(String_Const_U8 source, u64 start_index, u64 end_index) {
    u64 end_index_prime = minimum(end_index, source.char_count);
    u64 start_index_prime = minimum(start_index, end_index_prime);
    
    String_Const_U8 result;
    result.str = source.str + start_index_prime;
    result.char_count = end_index_prime - start_index_prime;
    result.char_capacity = result.char_count;
    return(result);
}

inline String_U8
str8_format(Memory_Arena *arena, String_Const_U8 fmt, ...) {
    va_list arg_list;
    va_start(arg_list, fmt);
    
    String_U8 result;
    u64 num_chars = (u64)vsnprintf(null, 0, (char *)fmt.str, arg_list);
    //assert_true(num_chars != 0);
    result.str = arena_push_array(arena, u8, num_chars + 1);
    result.char_count = num_chars;
    result.char_capacity = num_chars;
    vsnprintf((char *)result.str, num_chars + 1, (char *)fmt.str, arg_list);
    
    va_end(arg_list);
    return(result);
}

fn b32
str8_equal_strings(String_Const_U8 a, String_Const_U8 b) {
    b32 result = false;
    
    if (a.char_count == b.char_count) {
        u64 N = a.char_count;
        
        while (N && (a.str[N - 1] == b.str[N - 1])) {
            N -= 1;
        }
        
        result = (N == 0);
    }
    
    return(result);
}

fn u64
str8_compute_hash(u64 base, String_Const_U8 string) {
    u64 hash_value = base;
    for (u64 char_index = 0;
         char_index < string.char_count;
         char_index += 1) {
        hash_value = (hash_value << 5) + string.str[char_index];
    }
    
    return(hash_value);
}

typedef u16 Lexeme_Type;

// NOTE(christian): all keywords are lowercase
enum {
    LexemeType_Null, // no type
    
    //~
    LexemeType_While,
    LexemeType_Static,
    LexemeType_New,
    
    //~
    LexemeType_LogicalOr,
    LexemeType_BitwiseOr,
    
    LexemeType_LogicalAnd,
    LexemeType_BitwiseAnd,
    
    LexemeType_LogicalNot,
    LexemeType_BitwiseNot,
    
    LexemeType_BitwiseXOR,
    
    //~ NOTE(christian): my identifier - should start with an alphabetic character or underscore,
    // and can be followed by alphanumeric characters and underscore.
    LexemeType_Identifier,
    
    //~ NOTE(christian): the scanner emits this when EOF
    LexemeType_EOF,
    
    //~
    LexemeType_Total
};

typedef struct Token Token;
struct Token {
    String_Const_U8 lexeme;
    Lexeme_Type type;
    Token *next;
};

typedef struct {
    b32 has_error;
} Comiler_State;

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

typedef struct Error_Node Error_Node;
struct Error_Node {
    String_U8 message;
    Error_Node *next;
};

String_U8
w32_read_entire_file(Memory_Arena *arena, String_Const_U8 file_path) {
    String_U8 result = { 0 };
    
    // TODO(christian): read this https://learn.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files
    HANDLE handle = CreateFileA((char *)file_path.str, GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, null);
    
    if (handle != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li_file_size;
        if (GetFileSizeEx(handle, &li_file_size) != 0) {
            void *buffer = arena_push_size(arena, li_file_size.QuadPart + 1);
            DWORD bytes_to_read = (DWORD)li_file_size.QuadPart;
            DWORD bytes_read;
            if ((ReadFile(handle, buffer, bytes_to_read, &bytes_read, null) == TRUE) &&
                (bytes_read == bytes_to_read)) {
                result.str = (u8 *)buffer;
                result.char_count = li_file_size.QuadPart;
                result.char_capacity = li_file_size.QuadPart;
                
                result.str[result.char_count] = '\0';
            } else {
                arena_pop_size(arena, li_file_size.QuadPart + 1);
            }
        }
    }
    
    return(result);
}

typedef struct {
    String_Const_U8 code;
    u64 current_char_index;
    
    Error_Node *error_first;
    Error_Node *error_last;
    
    Token *token_first;
    Token *token_last;
} Scanner_State;

inline u8
scan_next_char(Scanner_State *scanner) {
    u8 result = '\0';
    if (scanner->current_char_index < scanner->code.char_count) {
        result = scanner->code.str[scanner->current_char_index++];
    }
    
    return(result);
}

inline u8
scan_peek_char(Scanner_State *scanner) {
    u8 result = '\0';
    if (scanner->current_char_index < scanner->code.char_count) {
        result = scanner->code.str[scanner->current_char_index];
    }
    
    return(result);
}

// TODO(christian): should output token list
fn void
scan_begin(Memory_Arena *arena, String_Const_U8 code) {
    Scanner_State state;
    state.code = code;
    state.current_char_index = 0;
    state.error_first = state.error_last = null;
    state.token_first = state.token_last = null;
    
    while (scan_peek_char(&state) != '\0') {
        u64 begin_char_index = state.current_char_index;
        u8 current_char = scan_next_char(&state);
        
        // TODO(christian): switch statement and default case for identifiers and hash table lookup for resevered words otherwise its valid identifier
        if (current_char == 'n') {
            current_char = scan_next_char(&state);
            if (current_char == 'e') {
                current_char = scan_next_char(&state);
                if (current_char == 'w') {
                    Token *token_node = arena_push_struct(arena, Token);
                    token_node->lexeme = str8_substring_view(state.code, begin_char_index, state.current_char_index);
                    token_node->type = LexemeType_New;
                    sll_push_back(state.token_first, state.token_last, token_node);
                } else {
                    Error_Node *error_node = arena_push_struct(arena, Error_Node);
                    error_node->message = str8_copy(arena, str8("Error: expected 'w'"));
                    sll_push_back(state.error_first, state.error_last, error_node);
                }
            } else {
                Error_Node *error_node = arena_push_struct(arena, Error_Node);
                error_node->message = str8_copy(arena, str8("Error: expected 'e'"));
                sll_push_back(state.error_first, state.error_last, error_node);
            }
        } else if (is_digit(current_char)) {
            // NOTE(christian): unsigned integer
            while (is_digit(scan_peek_char(&state))) {
                current_char = scan_next_char(&state);
            }
            
            Token *token_node = arena_push_struct(arena, Token);
            token_node->lexeme = str8_substring_view(state.code, begin_char_index, state.current_char_index);
            token_node->type = LexemeType_Null;
            sll_push_back(state.token_first, state.token_last, token_node);
        } else {
            Error_Node *error_node = arena_push_struct(arena, Error_Node);
            error_node->message = str8_copy(arena, str8("Error: unexpected character"));
            sll_push_back(state.error_first, state.error_last, error_node);
        }
    }
    
    for (Error_Node *node = state.error_first;
         node;
         node = node->next) {
        printf("%s\n", (char *)node->message.str);
    }
    
    for (Token *node = state.token_first;
         node;
         node = node->next) {
        printf("------------\n");
        printf("Lexeme: ");
        for (u32 char_index = 0;
             char_index < node->lexeme.char_count;
             char_index += 1) {
            putc(node->lexeme.str[char_index], stdout);
        }
        
        printf("\nToken Type: ");
        switch (node->type) {
            case LexemeType_Null: {
                printf("null");
            } break;
            
            case LexemeType_New: {
                printf("new");
            } break;
        }
        
        printf("\n\n");
    }
}

typedef u8 NFA_State_Flags;
enum {
    NFAStateFlag_IsAccepting = 0x1
};

typedef struct nfa_state nfa_state;
struct nfa_state {
    u64 index_in_list;
    NFA_State_Flags flags;
    String_U8 identifier;
    nfa_state *next;
};

typedef struct nfa_transition_node nfa_transition_node;
struct nfa_transition_node {
    nfa_state *state;
    u8 edge_label;
    b32 is_epsilon_transition;
    nfa_transition_node *next;
};

typedef struct nfa_transition nfa_transition;
struct nfa_transition {
    nfa_state *transitions_for;
    nfa_transition_node *transitions;
    nfa_transition *next_in_hash;
};

#if 0
typedef struct nfa_accepting_node nfa_accepting_node;
struct nfa_accepting_node {
    nfa_state *state;
    nfa_accepting_node *next;
};
#endif

// TODO(christian): rename this to Finite_Automata!
typedef struct {
    nfa_state *first_state;
    nfa_state *last_state;
    u64 state_count;
    nfa_transition *transitions[32];
    String_U8 alphabet;
    
    //nfa_accepting_node *first_accepting_state;
} nfa;

inline u64
nfa_compute_hash(nfa *fa, String_Const_U8 string) {
    u64 hash_value = str8_compute_hash(0, string) % array_count(fa->transitions);
    return(hash_value);
}

fn nfa_state *
nfa_insert_state(Memory_Arena *arena, nfa *fa, String_U8 identifier) {
    nfa_state *new_state = arena_push_struct(arena, nfa_state);
    new_state->index_in_list = fa->state_count;
    new_state->identifier = identifier;
    new_state->flags = 0;
    new_state->next = null;
    
    //nfa_state *previous_state = fa->last_state;
    sll_push_back(fa->first_state, fa->last_state, new_state);
    
    fa->state_count += 1;
    
    return(new_state);
}

fn void
nfa_add_transition(Memory_Arena *arena, nfa *fa, nfa_state *transition_from,
                   u8 edge_label, b32 is_e_transition, nfa_state *transition_to) {
    u64 transition_from_hash = nfa_compute_hash(fa, transition_from->identifier);
    assert_true(transition_from_hash < array_count(fa->transitions));
    
    nfa_transition *transition_list = fa->transitions[transition_from_hash];
    while (transition_list && !str8_equal_strings(transition_list->transitions_for->identifier, transition_from->identifier)) {
        transition_list = transition_list->next_in_hash;
    }
    
    // NOTE(christian): transition_from's adjacency is nonexistent. (first time). so create
    // new adj. list
    if (!transition_list) {
        transition_list = arena_push_struct(arena, nfa_transition);
        
        transition_list->transitions_for = transition_from;
        transition_list->transitions = null;
        transition_list->next_in_hash = fa->transitions[transition_from_hash];
        
        fa->transitions[transition_from_hash] = transition_list;
    }
    
    assert_true(transition_list != null);
    
    nfa_transition_node *new_transition = arena_push_struct(arena, nfa_transition_node);
    new_transition->state = transition_to;
    new_transition->edge_label = edge_label;
    new_transition->is_epsilon_transition = is_e_transition;
    new_transition->next = transition_list->transitions;
    transition_list->transitions = new_transition;
}

fn nfa_transition *
nfa_get_transitions_for_state(nfa *fa, nfa_state *state) {
    nfa_transition *transition_list = null;
    
    u64 transition_from_hash = nfa_compute_hash(fa, state->identifier);
    assert_true(transition_from_hash < array_count(fa->transitions));
    
    transition_list = fa->transitions[transition_from_hash];
    while (transition_list && !str8_equal_strings(transition_list->transitions_for->identifier, state->identifier)) {
        transition_list = transition_list->next_in_hash;
    }
    
    return(transition_list);
}

inline b32
is_regex_operator(u8 c) {
    b32 result = ((c == '.') || // concat
                  (c == '|') || // alternate
                  (c == '*')); // kleene
    
    return(result);
}

fn void
nfa_print_states_and_transitions(nfa *fa) {
    for (nfa_state *current_state = fa->first_state;
         current_state;
         current_state = current_state->next) {
        nfa_transition *transitions = nfa_get_transitions_for_state(fa, current_state);
        if (transitions) {
            printf("(%s)", current_state->identifier.str);
            assert_true(transitions->transitions_for != null);
            assert_true(str8_equal_strings(transitions->transitions_for->identifier, current_state->identifier));
            
            for (nfa_transition_node *transition = transitions->transitions;
                 transition;
                 transition = transition->next) {
                assert_true(transition->state != null);
                if (transition->is_epsilon_transition) {
                    printf(" -> {%c}", transition->edge_label);
                } else {
                    printf(" -> %c", transition->edge_label);
                }
                if (transition->state->flags & NFAStateFlag_IsAccepting) {
                    printf(" -> ((%s))", transition->state->identifier.str);
                } else {
                    printf(" -> (%s)", transition->state->identifier.str);
                }
            }
            
            printf("\n");
        }
    }
}

#define invalid_index_u64 0xffffffffffffffff

fn u64
find_dividing_point(String_Const_U8 regex) {
    u64 result = invalid_index_u64;
    u8 precedence_value = 0;
    
    for (u64 char_index = 0;
         char_index < regex.char_count;
         char_index += 1) {
        u8 char_this_iter = regex.str[char_index];
        if (char_this_iter == '(') {
            while ((regex.str[char_index] != ')') && (char_index < regex.char_count)) {
                ++char_index;
            }
            
            if (char_index == regex.char_count) {
                _assert(!"please end with closing paren");
            }
        } else {
            u8 prec = 0;
            switch (char_this_iter) {
                case '*': {
                    prec = 1;
                } break;
                
                case '|': {
                    prec = 2;
                } break;
                
                case '.': {
                    prec = 3;
                } break;
            }
            
            if (prec > precedence_value) {
                precedence_value = prec;
                result = char_index;
            }
        }
    }
    
    return(result);
}

typedef struct {
    nfa_state *start;
    nfa_state *end;
} single_nfa_result;

fn String_Const_U8
regex_substring_without_parens(String_Const_U8 regex, u64 start, u64 dividing_pt) {
    u64 paren_count = 0;
    for (u64 char_index = 0;
         char_index < regex.char_count;
         char_index += 1) {
        if ((regex.str[char_index] == '(') ||
            (regex.str[char_index] == ')')) {
            paren_count += 1;
        }
    }
    
    if ((regex.str[0] == '(') && ((regex.str[dividing_pt - 1] == ')')) && (paren_count == 2)) {
        return str8_substring_view(regex, start + 1, dividing_pt - 1);
    } else if ((regex.str[0] == '(') && (regex.str[dividing_pt] == '*')) {
        assert_true(dividing_pt > 1);
        return str8_substring_view(regex, start + 1, dividing_pt - 1);
    } else {
        return str8_substring_view(regex, start, dividing_pt);
    }
}

// NOTE(christian): flaws: it assumes that regex has no space!!!! And prob. some stuff that I do not know about!!!!!
fn single_nfa_result
nfa_from_regex_inner(Memory_Arena *arena, nfa *result_nfa, String_Const_U8 regex) {
    if (regex.char_count > 1) {
        single_nfa_result combined = {0};
        
        u64 div_pt = find_dividing_point(regex);
        if (div_pt == invalid_index_u64) {
            regex = regex_substring_without_parens(regex, 0, regex.char_count);
            div_pt = find_dividing_point(regex);
        }
        
        single_nfa_result fa0 = nfa_from_regex_inner(arena, result_nfa, regex_substring_without_parens(regex, 0, div_pt));
        u8 op = regex.str[div_pt];
        if (op != '*') {
            single_nfa_result fa1 = nfa_from_regex_inner(arena, result_nfa, regex_substring_without_parens(regex, div_pt + 1, regex.char_count));
            
            switch (op) {
                case '|': {
                    combined.start = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
                    nfa_add_transition(arena, result_nfa, combined.start, 'e', true, fa0.start);
                    nfa_add_transition(arena, result_nfa, combined.start, 'e', true, fa1.start);
                    
                    combined.end = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
                    nfa_add_transition(arena, result_nfa, fa0.end, 'e', true, combined.end);
                    nfa_add_transition(arena, result_nfa, fa1.end, 'e', true, combined.end);
                } break;
                
                case '.': {
                    nfa_add_transition(arena, result_nfa, fa0.end, 'e', true, fa1.start);
                    combined.start = fa0.start;
                    combined.end = fa1.end;
                } break;
                
                default: {
                    _assert(!"how did you got here?");
                } break;
            }
        } else {
            combined.start = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
            combined.end = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
            
            nfa_add_transition(arena, result_nfa, combined.start, 'e', true, fa0.start);
            nfa_add_transition(arena, result_nfa, fa0.end, 'e', true, combined.end);
            nfa_add_transition(arena, result_nfa, fa0.end, 'e', true, fa0.start);
            nfa_add_transition(arena, result_nfa, combined.start, 'e', true, combined.end);
        }
        
        return combined;
    } else {
        assert_true(regex.char_count == 1);
        single_nfa_result result;
        result.start = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
        result.end = nfa_insert_state(arena, result_nfa, str8_format(arena, str8("n_%llu"), result_nfa->state_count));
        nfa_add_transition(arena, result_nfa, result.start, regex.str[0], false, result.end);
        
        assert_true(result_nfa->alphabet.char_count < result_nfa->alphabet.char_capacity);
        result_nfa->alphabet.str[result_nfa->alphabet.char_count++] = regex.str[0];
        return(result);
    }
}

fn nfa
nfa_from_regex(Memory_Arena *arena, String_Const_U8 regex) {
    nfa result = {0};
    result.alphabet = str8_reserve(arena, 64);
    nfa_from_regex_inner(arena, &result, regex);
    result.last_state->flags |= NFAStateFlag_IsAccepting;
    return(result);
}

typedef u16 dfs_state;
enum {
    DFSState_Undiscovered,
    DFSState_Discovered,
    DFSState_Processsed,
};
typedef struct nfa_valid_configuration nfa_valid_configuration;
struct nfa_valid_configuration {
    nfa_state *state;
    nfa_valid_configuration *next;
};

typedef struct nfa_valid_configuration_node nfa_valid_configuration_node;
struct nfa_valid_configuration_node {
    nfa_valid_configuration *config_list;
    String_U8 identifier;
    nfa_valid_configuration_node *next;
};

typedef struct nfa_configuration_transition_node nfa_configuration_transition_node; 
struct nfa_configuration_transition_node {
    nfa_valid_configuration_node *transition_to;
    u8 edge_label;
    nfa_configuration_transition_node *next;
};

typedef struct nfa_configuration_transition nfa_configuration_transition;
struct nfa_configuration_transition {
    nfa_valid_configuration_node *transitions_for;
    nfa_configuration_transition_node *transitions;
    nfa_configuration_transition *next_in_hash;
};

typedef struct {
    nfa_state *state;
    dfs_state dfs_visit_state;
} dfs_node;

fn nfa_valid_configuration *
nfa_follow_epsilon(Memory_Arena *arena, nfa *fa, nfa_state *follow_from, b32 *contains_accepting_state) {
    nfa_valid_configuration *result = arena_push_struct(arena, nfa_valid_configuration);
    result->state = follow_from;
    result->next = null;
    
    Memory_Arena *dfs_memory = arena_get_scratch(&arena, 1);
    Temporary_Memory dfs_temp_memory = temp_mem_begin(dfs_memory);
    
    dfs_node *dfs_nodes = arena_push_array(dfs_memory, dfs_node, fa->state_count);
    
    {
        u64 dfa_node_count = 0;
        for (nfa_state *state = fa->first_state;
             state;
             state = state->next) {
            dfs_node *node = dfs_nodes + dfa_node_count++;
            node->state = state;
            node->dfs_visit_state = DFSState_Undiscovered;
        }
        
        if (contains_accepting_state) {
            *contains_accepting_state = false;
        }
    }
    
    dfs_node **state_stack = arena_push_array(dfs_memory, dfs_node *, fa->state_count);
    u64 dfs_stack_ptr = 0;
    state_stack[dfs_stack_ptr++] = dfs_nodes + follow_from->index_in_list;
    dfs_nodes[follow_from->index_in_list].dfs_visit_state = DFSState_Discovered;
    
    //nfa_state *accepting_state = fa->last_state;
    
    while (dfs_stack_ptr) {
        dfs_node *popped_node = state_stack[dfs_stack_ptr - 1];
        assert_true(popped_node->dfs_visit_state == DFSState_Discovered);
        assert_true(popped_node->state != null);
        
        nfa_transition *transition_for_popped = nfa_get_transitions_for_state(fa, popped_node->state);
        if (transition_for_popped) {
            b32 pushed_in_stack = false;
            
            for (nfa_transition_node *adjacent_node = transition_for_popped->transitions;
                 adjacent_node;
                 adjacent_node = adjacent_node->next) {
                if (adjacent_node->is_epsilon_transition) {
                    dfs_node *adjacent_dfs_node = dfs_nodes + adjacent_node->state->index_in_list;
                    if (adjacent_dfs_node->dfs_visit_state == DFSState_Undiscovered) {
                        adjacent_dfs_node->dfs_visit_state = DFSState_Discovered;
                        
                        if (contains_accepting_state && (adjacent_dfs_node->state->flags & NFAStateFlag_IsAccepting)) {
                            *contains_accepting_state = true;
                        }
                        
                        nfa_valid_configuration *new_configuration = arena_push_struct(arena, nfa_valid_configuration);
                        new_configuration->state = adjacent_dfs_node->state;
                        new_configuration->next = result;
                        result = new_configuration;
                        
                        state_stack[dfs_stack_ptr++] = adjacent_dfs_node;
                        pushed_in_stack = true;
                        break;
                    }
                }
            }
            
            if (!pushed_in_stack) {
                popped_node->dfs_visit_state = DFSState_Processsed;
                --dfs_stack_ptr;
            }
        } else {
            --dfs_stack_ptr;
        }
    }
    
    temp_mem_end(dfs_temp_memory);
    return(result);
}

// TODO(christian): optimize this horrendous function / Remove Unecessary code!!! 
// TODO(christian): there is a bug. I dont know what. I might need to reread. Basically, it outputs wrong DFA for certain NFAs!
fn nfa
dfa_from_nfa(Memory_Arena *arena, nfa* fa) {
    Memory_Arena *scratch_memory = arena_get_scratch(&arena, 1);
    Temporary_Memory temporary_memory = temp_mem_begin(scratch_memory);
    
    b32 contains_accepting_state = false;
    u64 config_count = 0;
    
    // NOTE(christian): this should actually be dfa struct.
    nfa result = { 0 };
    nfa_configuration_transition *transitions[32] = { null };
    
    nfa_valid_configuration *first_config = nfa_follow_epsilon(scratch_memory, fa, fa->first_state, &contains_accepting_state);
    
    // NOTE(christian): in the book, this is called Q
    nfa_valid_configuration_node *first_configuration = arena_push_struct(scratch_memory, nfa_valid_configuration_node);
    nfa_valid_configuration_node *last_configuration = first_configuration;
    
    first_configuration->config_list = first_config;
    first_configuration->identifier = str8_format(scratch_memory, str8("q_%llu"), config_count++);
    first_configuration->next = null;
    
    {
        nfa_state *state = nfa_insert_state(arena, &result, str8_format(arena, str8("q_%llu"), result.state_count));
        if (contains_accepting_state) {
            state->flags |= NFAStateFlag_IsAccepting;
        }
    }
    
    typedef struct work_queue work_queue;
    struct work_queue {
        nfa_valid_configuration_node *work;
        nfa_state *dfa_state;
        work_queue *next;
    };
    
    // NOTE(christian): in the book this is called WorkList!
    work_queue *first_work = arena_push_struct(scratch_memory, work_queue);
    work_queue *last_work = first_work;
    first_work->work = first_configuration;
    first_work->dfa_state = result.first_state;
    first_work->next = null;
    
    while (first_work) {
        if (first_work == last_work) {
            last_work = null;
        }
        
        nfa_state *dequeued_dfa_state = first_work->dfa_state;
        nfa_valid_configuration_node *dequeued_from_work = first_work->work;
        first_work = first_work->next;
        
        for (u64 char_index = 0; char_index < fa->alphabet.char_count; ++char_index) {
            u8 character = fa->alphabet.str[char_index];
            
            nfa_valid_configuration *possible_configuration = null;
            
            for (nfa_valid_configuration *dequeued = dequeued_from_work->config_list;
                 dequeued;
                 dequeued = dequeued->next) {
                nfa_transition *transitions_for_dequeued = nfa_get_transitions_for_state(fa, dequeued->state);
                if (transitions_for_dequeued) {
                    for (nfa_transition_node *node = transitions_for_dequeued->transitions;
                         node;
                         node = node->next) {
                        if ((node->edge_label == character) && !node->is_epsilon_transition) {
                            nfa_valid_configuration *e_closure_for_dequeued = nfa_follow_epsilon(scratch_memory, fa, node->state, &contains_accepting_state);
                            
#if 0
                            if (possible_configuration) {
                                for (; e_closure_for_dequeued;) {
                                    nfa_valid_configuration *temp = possible_configuration;
                                    for (; temp; temp = temp->next) {
                                        if (temp->state == e_closure_for_dequeued->state) {
                                            break;
                                        }
                                    }
                                    
                                    if (temp == null) {
                                        nfa_valid_configuration *new_config_node = e_closure_for_dequeued;
                                        e_closure_for_dequeued = e_closure_for_dequeued->next;
                                        
                                        new_config_node->next = possible_configuration;
                                        possible_configuration = new_config_node;
                                    }
                                }
                            } else {
                                possible_configuration = e_closure_for_dequeued;
                            }
#else
                            possible_configuration = e_closure_for_dequeued;
#endif
                            break;
                        }
                    }
                }
            }
            
            if (possible_configuration) {
                b32 is_already_queued = false;
                
                nfa_valid_configuration_node *queued_equivalent = null;
                for (nfa_valid_configuration_node *queued_configs = first_configuration;
                     queued_configs;
                     queued_configs = queued_configs->next) {
                    nfa_valid_configuration *first_list = possible_configuration;
                    nfa_valid_configuration *second_list = queued_configs->config_list;
                    
                    while (first_list != null) {
                        b32 found_element = false;
                        
                        nfa_valid_configuration *_second_list = second_list;
                        while (_second_list != null) {
                            if (first_list->state == _second_list->state) {
                                found_element = true;
                                break;
                            } else {
                                _second_list = _second_list->next;
                            }
                        }
                        
                        if (!found_element) {
                            break;
                        }
                        
                        first_list = first_list->next;
                    }
                    
                    if (first_list == null) {
                        queued_equivalent = queued_configs;
                        is_already_queued = true;
                        break;
                    }
                }
                
                if (!is_already_queued) {
                    nfa_valid_configuration_node *new_config_list_node = arena_push_struct(scratch_memory, nfa_valid_configuration_node);
                    new_config_list_node->config_list = possible_configuration;
                    new_config_list_node->identifier = str8_format(arena, str8("q_%llu"), config_count++);
                    sll_push_back(first_configuration, last_configuration, new_config_list_node);
                    
                    for (nfa_valid_configuration *test = possible_configuration;
                         test;
                         test = test->next) {
                        if (test->state == fa->last_state) {
                            contains_accepting_state = true;
                            break;
                        }
                    }
                    
                    queued_equivalent = new_config_list_node;
                    
                    nfa_state *new_dfa_state = nfa_insert_state(arena, &result, str8_format(arena, str8("q_%llu"), result.state_count));
                    if (contains_accepting_state) {
                        new_dfa_state->flags |= NFAStateFlag_IsAccepting;
                    }
                    
                    work_queue *new_work = arena_push_struct(scratch_memory, work_queue);
                    new_work->work = new_config_list_node;
                    new_work->dfa_state = new_dfa_state;
                    sll_push_back(first_work, last_work, new_work);
                }
                
                assert_true(queued_equivalent != null);
                
                nfa_state *queued_dfa_equivalent = null;
                for (nfa_state *state = result.first_state;
                     state;
                     state = state->next) {
                    if (str8_equal_strings(queued_equivalent->identifier, state->identifier)) {
                        queued_dfa_equivalent = state;
                        break;
                    }
                }
                
                assert_true(queued_dfa_equivalent != null);
                
                u64 transition_hash = str8_compute_hash(0, dequeued_from_work->identifier) % array_count(transitions);
                nfa_configuration_transition *transition_list = transitions[transition_hash];
                while (transition_list && !str8_equal_strings(transition_list->transitions_for->identifier, dequeued_from_work->identifier)) {
                    transition_list = transition_list->next_in_hash;
                }
                
                if (!transition_list) {
                    transition_list = arena_push_struct(scratch_memory, nfa_configuration_transition);
                    transition_list->transitions_for = dequeued_from_work;
                    transition_list->transitions = null;
                    transition_list->next_in_hash = transitions[transition_hash];
                    
                    transitions[transition_hash] = transition_list;
                }
                
                nfa_configuration_transition_node *new_transition_to = arena_push_struct(scratch_memory, nfa_configuration_transition_node);
                new_transition_to->transition_to = queued_equivalent;
                new_transition_to->edge_label = character;
                new_transition_to->next = transition_list->transitions;
                transition_list->transitions = new_transition_to;
                
                nfa_add_transition(arena, &result, dequeued_dfa_state, character, false, queued_dfa_equivalent);
            }
        }
    }
    
    for (nfa_valid_configuration_node *config_group = first_configuration;
         config_group;
         config_group = config_group->next) {
        nfa_valid_configuration *config_list = config_group->config_list;
        while (config_list) {
            printf("%s ", (char *)config_list->state->identifier.str);
            config_list = config_list->next;
        }
        
        printf("\n");
    }
    
    printf("\n");
    
    for (nfa_valid_configuration_node *configuration = first_configuration;
         configuration;
         configuration = configuration->next) {
        printf("{");
        for (nfa_valid_configuration *config_element = configuration->config_list;
             config_element;
             config_element = config_element->next) {
            printf("%s ", (char *)config_element->state->identifier.str);
        }
        printf("}");
        
        u64 transition_hash = str8_compute_hash(0, configuration->identifier) % array_count(transitions);
        nfa_configuration_transition *transition_list = transitions[transition_hash];
        while (transition_list && !str8_equal_strings(transition_list->transitions_for->identifier, configuration->identifier)) {
            transition_list = transition_list->next_in_hash;
        }
        
        if (transition_list) {
            for (nfa_configuration_transition_node *transition = transition_list->transitions;
                 transition;
                 transition = transition->next) {
                printf(" -> %c -> {", transition->edge_label);
                for (nfa_valid_configuration *config_element = transition->transition_to->config_list;
                     config_element;
                     config_element = config_element->next) {
                    printf("%s ", (char *)config_element->state->identifier.str);
                }
                printf("}");
            }
        }
        
        printf("\n");
    }
    
    printf("\n\n\n");
    
    result.alphabet = str8_copy(arena, fa->alphabet);
    temp_mem_end(temporary_memory);
    return(result);
}

typedef struct Hopcroft_DFA_State_Node Hopcroft_DFA_State_Node;
struct Hopcroft_DFA_State_Node {
    nfa_state *state;
    Hopcroft_DFA_State_Node *next;
};

typedef struct Hopcroft_DFA_States Hopcroft_DFA_States;
struct Hopcroft_DFA_States {
    Hopcroft_DFA_State_Node *first;
    Hopcroft_DFA_State_Node *last;
    Hopcroft_DFA_States *next;
    Hopcroft_DFA_States *prev;
};

typedef struct {
    Hopcroft_DFA_States *first;
    Hopcroft_DFA_States *last;
} Hopcroft_Partition;

// TODO(christian): rename nfa struct to Finite_Automata

fn Hopcroft_DFA_States *
hopcroft_dfa_states_copy(Memory_Arena *arena, Hopcroft_DFA_States *source) {
    Hopcroft_DFA_States *dest = arena_push_struct_zero(arena, Hopcroft_DFA_States);
    for (Hopcroft_DFA_State_Node *source_node = source->first;
         source_node;
         source_node = source_node->next) {
        Hopcroft_DFA_State_Node *new_node = arena_push_struct(arena, Hopcroft_DFA_State_Node);
        new_node->state = source_node->state;
        sll_push_back(dest->first, dest->last, new_node);
    }
    
    return(dest);
}

// Hopcroft Algorithm notes:
// - It constructs a minimal DFA from an arbitrary DFA by grouping together states into sets that are equivalent.
// - Two DFA states are equivalent when they produce the same behavior on input string.
// - It finds the largest possible sets of equivalent states; each set becomes a state in the minimal DFA. 
//    - From my understanding, it condenses these equivalent states into one state.
// - It constructs a set partition, P = { p_1, ..., p_m } of DFA states. Each p_i contains a set of equivalent
//   DFA States. Basically, P is a set of sets! Remember this!
// - It constructs a partition with the smallest number of sets. Here are the following rules without annoying math formalness:
// 
//   1. Suppose we have character c in the alphabet. Suppose we have DFA States d_i and d_j in some partition p_j in P.
//      Suppose we have DFA states d_x and d_y such that d_i transitions to d_x with respect to character c and
//      d_j transitions to d_y with respect to character c. Then, d_x and d_j must belong into the same partition
//      p_t in P!
//      - In other words, two states in the same set must, for every character c in alphabet, transition to states that are themselves, members
//        of a single set in partition!
// 
//   2. Suppose we have DFA states d_i and d_j in some partition p_k in P. Then both d_i and d_j must be an accepting state!
//      Or both d_i and d_j must be a nonaccepting state! But not both!
//      - Any single set contains either accepting states or nonaccepting states, but not both!

// - The algorithm starts with P containg two sets: {accepting states} and {all DFA states without accepting states}.
// - The algorithm refines P's contents until both properties 1 and 2 holds for each set in P.
// - The algorithm splits sets based on the transitions out of DFA states in the set.

// NOTE(christian): the image: the set of DFA states that can reach a state in s on a transition labeled c.
// s = transition_to
// c = character
fn Hopcroft_DFA_State_Node *
dfa_get_states_that_transition_to_another_states(Memory_Arena *arena,
                                                 nfa *dfa, u8 character,
                                                 Hopcroft_DFA_States *transition_to) {
    Hopcroft_DFA_State_Node *result = null;
    
    for (nfa_state *possible_candidate = dfa->first_state;
         possible_candidate;
         possible_candidate = possible_candidate->next) {
        nfa_transition *transitions = nfa_get_transitions_for_state(dfa, possible_candidate);
        if (transitions) {
            for (nfa_transition_node *transition = transitions->transitions;
                 transition;
                 transition = transition->next) {
                b32 accept_candidate = false;
                if (!transition->is_epsilon_transition && (transition->edge_label == character)) {
                    for (Hopcroft_DFA_State_Node *possible_transition_to = transition_to->first;
                         possible_transition_to;
                         possible_transition_to = possible_transition_to->next) {
                        if (possible_transition_to->state == transition->state) {
                            accept_candidate = true;
                            break;
                        }
                    }
                }
                
                if (accept_candidate) {
                    Hopcroft_DFA_State_Node *new_state_node = arena_push_struct(arena, Hopcroft_DFA_State_Node);
                    new_state_node->state = possible_candidate;
                    new_state_node->next = result;
                    result = new_state_node;
                    break;
                }
            }
        }
    }
    
    return(result);
}

// TODO(christian): after this, review BFS and DFS in CLRS!
// TODO(christian): still flawed and I don't know where. Re read this!
// TODO(christian): read the entire chapter again after this !!
fn void
dfa_minimize_hopcroft(Memory_Arena *arena, nfa *dfa) {
    nfa result_minimized = { 0 }; // TODO(christian): this thang.
    
    Memory_Arena *partition_scratch = arena_get_scratch(&arena, 1);
    Temporary_Memory partition_temporary_memory = temp_mem_begin(partition_scratch);
    
    Hopcroft_Partition partition = { 0 };
    Hopcroft_Partition work_list = { 0 };
    
    {
        Hopcroft_DFA_States *accepting_states[2], *without_accepting_states[2];
        
        for (u32 state_index = 0;
             state_index < 2;
             state_index += 1) {
            accepting_states[state_index] = arena_push_struct_zero(partition_scratch, Hopcroft_DFA_States);
            for (nfa_state *state = dfa->first_state;
                 state;
                 state = state->next) {
                if (state->flags & NFAStateFlag_IsAccepting) {
                    Hopcroft_DFA_State_Node *new_state_node = arena_push_struct(partition_scratch, Hopcroft_DFA_State_Node);
                    new_state_node->state = state;
                    new_state_node->next = null;
                    sll_push_back(accepting_states[state_index]->first,
                                  accepting_states[state_index]->last,
                                  new_state_node);
                }
            }
        }
        
        for (u32 state_index = 0;
             state_index < 2;
             state_index += 1) {
            without_accepting_states[state_index] = arena_push_struct_zero(partition_scratch, Hopcroft_DFA_States);
            for (nfa_state *state = dfa->first_state;
                 state;
                 state = state->next) {
                if ((state->flags & NFAStateFlag_IsAccepting) == 0) {
                    Hopcroft_DFA_State_Node *new_state_node = arena_push_struct(partition_scratch, Hopcroft_DFA_State_Node);
                    new_state_node->state = state;
                    new_state_node->next = null;
                    sll_push_back(without_accepting_states[state_index]->first,
                                  without_accepting_states[state_index]->last,
                                  new_state_node);
                }
            }
        }
        
        dll_push_back(partition.first, partition.last, accepting_states[0]);
        dll_push_back(partition.first, partition.last, without_accepting_states[0]);
        
        dll_push_back(work_list.first, work_list.last, accepting_states[1]);
        dll_push_back(work_list.first, work_list.last, without_accepting_states[1]);
    }
    
    while (work_list.first) {
        Hopcroft_DFA_States *popped_states_from_work = work_list.first;
        dll_remove(work_list.first, work_list.last, popped_states_from_work);
        
        for (u32 alphabet_index = 0;
             alphabet_index < dfa->alphabet.char_count;
             alphabet_index += 1) {
            u8 character = dfa->alphabet.str[alphabet_index];
            Hopcroft_DFA_State_Node *image = dfa_get_states_that_transition_to_another_states(partition_scratch,
                                                                                              dfa, character,
                                                                                              popped_states_from_work);
            
            typedef struct State_In_Image_View State_In_Image_View;
            struct State_In_Image_View {
                Hopcroft_DFA_States *states;
                State_In_Image_View *next;
            };
            
            State_In_Image_View *states_in_partition_with_state_in_image = null;
            for (Hopcroft_DFA_States *states_in_partition = partition.first;
                 states_in_partition; 
                 states_in_partition = states_in_partition->next) {
                State_In_Image_View *accepted  = null;
                for (Hopcroft_DFA_State_Node *state_in_partition = states_in_partition->first;
                     state_in_partition && !accepted;
                     state_in_partition = state_in_partition->next) {
                    for (Hopcroft_DFA_State_Node *state_in_image = image;
                         state_in_image;
                         state_in_image = state_in_image->next) {
                        // NOTE(christian): we have found a state in image.
                        if (state_in_image->state == state_in_partition->state) {
                            accepted = arena_push_struct_zero(partition_scratch, State_In_Image_View);
                            accepted->states = states_in_partition;
                            accepted->next = states_in_partition_with_state_in_image;
                            states_in_partition_with_state_in_image = accepted;
                            break;
                        }
                    }
                }
            }
            
            for (; states_in_partition_with_state_in_image; 
                 states_in_partition_with_state_in_image = states_in_partition_with_state_in_image->next) {
                u64 intersected_with_image_count = 0;
                Hopcroft_DFA_State_Node *intersected_with_image = null;
                Hopcroft_DFA_State_Node *last_in_intersected_with_image = null;
                
                u64 not_intersected_with_image_count = 0;
                Hopcroft_DFA_State_Node *not_intersected_with_image = null;
                Hopcroft_DFA_State_Node *last_in_not_intersected_with_image = null;
                
                for (Hopcroft_DFA_State_Node *state_node = states_in_partition_with_state_in_image->states->first;
                     state_node;
                     state_node = state_node->next) {
                    b32 in_intersection = false;
                    for (Hopcroft_DFA_State_Node *state_in_image = image;
                         state_in_image;
                         state_in_image = state_in_image->next) {
                        if (state_in_image->state == state_node->state) {
                            in_intersection = true;
                            break;
                        }
                    }
                    
                    if (in_intersection) {
                        Hopcroft_DFA_State_Node *new_node = arena_push_struct(partition_scratch, Hopcroft_DFA_State_Node);
                        new_node->next = intersected_with_image;
                        new_node->state = state_node->state;
                        intersected_with_image = new_node;
                        if (!last_in_intersected_with_image) {
                            last_in_intersected_with_image = new_node;
                        }
                        
                        intersected_with_image_count += 1;
                    }
                }
                
                for (Hopcroft_DFA_State_Node *state_node = states_in_partition_with_state_in_image->states->first;
                     state_node;
                     state_node = state_node->next) {
                    b32 not_in_intersection = true;
                    for (Hopcroft_DFA_State_Node *state_in_intersected_with_image = intersected_with_image;
                         state_in_intersected_with_image;
                         state_in_intersected_with_image = state_in_intersected_with_image->next) {
                        if (state_in_intersected_with_image->state == state_node->state) {
                            not_in_intersection = false;
                            break;
                        }
                    }
                    
                    if (not_in_intersection) {
                        Hopcroft_DFA_State_Node *new_node = arena_push_struct(partition_scratch, Hopcroft_DFA_State_Node);
                        new_node->state = state_node->state;
                        new_node->next = not_intersected_with_image;
                        not_intersected_with_image = new_node;
                        if (!last_in_not_intersected_with_image) {
                            last_in_not_intersected_with_image = new_node;
                        }
                        
                        not_intersected_with_image_count += 1;
                    }
                }
                
                if (not_intersected_with_image != null) {
                    dll_remove(partition.first, partition.last, states_in_partition_with_state_in_image->states);
                    
                    Hopcroft_DFA_States *new_partition_state = arena_push_struct_zero(partition_scratch, Hopcroft_DFA_States);
                    new_partition_state->first = intersected_with_image;
                    new_partition_state->last = last_in_intersected_with_image;
                    dll_push_back(partition.first, partition.last, new_partition_state);
                    
                    new_partition_state = arena_push_struct_zero(partition_scratch, Hopcroft_DFA_States);
                    new_partition_state->first = not_intersected_with_image;
                    new_partition_state->last = last_in_not_intersected_with_image;
                    dll_push_back(partition.first, partition.last, new_partition_state);
                    
                    // TODO(christian): we clearly need a function of linked list set equality!
                    Hopcroft_DFA_States *position_of_queued = null;
                    for (Hopcroft_DFA_States *queued_states = work_list.first;
                         queued_states;
                         queued_states = queued_states->next) {
                        Hopcroft_DFA_State_Node *first_list = states_in_partition_with_state_in_image->states->first;
                        Hopcroft_DFA_State_Node *second_list = queued_states->first;
                        
                        while (first_list != null) {
                            b32 found_element = false;
                            Hopcroft_DFA_State_Node *_second_list = second_list;
                            while (_second_list) {
                                if (first_list->state == _second_list->state) {
                                    found_element = true;
                                    break;
                                } else {
                                    _second_list = _second_list->next;
                                }
                            }
                            
                            if (!found_element) {
                                break;
                            }
                            
                            first_list = first_list->next;
                        }
                        
                        if (first_list == null) {
                            position_of_queued = queued_states;
                            break;
                        }
                    }
                    
                    if (position_of_queued) {
                        dll_remove(work_list.first, work_list.last, position_of_queued);
                        
                        new_partition_state = hopcroft_dfa_states_copy(partition_scratch, partition.last->prev);
                        dll_push_back(work_list.first, work_list.last, new_partition_state);
                        
                        new_partition_state = hopcroft_dfa_states_copy(partition_scratch, partition.last);
                        dll_push_back(work_list.first, work_list.last, new_partition_state);
                    } else if (intersected_with_image_count <= not_intersected_with_image_count) {
                        new_partition_state = hopcroft_dfa_states_copy(partition_scratch, partition.last->prev);
                        dll_push_back(work_list.first, work_list.last, new_partition_state);
                    } else {
                        new_partition_state = hopcroft_dfa_states_copy(partition_scratch, partition.last);
                        dll_push_back(work_list.first, work_list.last, new_partition_state);
                    }
                    
                    Hopcroft_DFA_State_Node *first_list = popped_states_from_work->first;
                    while (first_list != null) {
                        b32 found_element = false;
                        Hopcroft_DFA_State_Node *_second_list = states_in_partition_with_state_in_image->states->first;
                        while (_second_list) {
                            if (first_list->state == _second_list->state) {
                                found_element = true;
                                break;
                            } else {
                                _second_list = _second_list->next;
                            }
                        }
                        
                        if (!found_element) {
                            break;
                        }
                        
                        first_list = first_list->next;
                    }
                    
                    if (first_list == null) {
                        break;
                    }
                }
            }
        }
    }
    
    temp_mem_end(partition_temporary_memory);
}

// NOTE(christian): useful chapters in algorithm
// - Combinatorial Search, CPT 9 (specifically, subset construction)
// - Finite State Minimization CPT 21.7

int
main(int argc, char *argv[]) {
    unused(argc);
    unused(argv);
    Memory_Arena *main_arena = arena_reserve(mb(128llu));
    String_U8 buf = w32_read_entire_file(main_arena, str8("..\\code\\scratch\\test_program.c"));
    scan_begin(main_arena, buf);
    
    nfa test_nfa = nfa_from_regex(main_arena, str8("a.(b|c)*"));
    //nfa_follow_epsilon_result *aaa = nfa_follow_epsilon(main_arena, &test_nfa, test_nfa.first_state->next);
    //nfa test_nfa = nfa_from_regex(main_arena, str8("a.(b|c)*.f")); // a(b|c)*f
    //nfa test_nfa = nfa_from_regex(main_arena, str8("a.a*.b"));
    // TODO(christian): this thing doesnt work with this regex. YIIIKES! FIX THIS!
    //nfa test_nfa = nfa_from_regex(main_arena, str8("(b.g.h)|(f.i.e)"));
    
    nfa test_dfa = dfa_from_nfa(main_arena, &test_nfa);
    //nfa_valid_configuration *c = nfa_follow_epsilon(main_arena, &test_nfa, test_nfa.first_state->next->next->next);
    
    nfa_print_states_and_transitions(&test_dfa);
    puts("\n\n");
    nfa_print_states_and_transitions(&test_nfa);
    dfa_minimize_hopcroft(main_arena, &test_dfa);
    printf("\nnfa alphabet: %s", (char *)test_nfa.alphabet.str);
    //getc(stdin);
    return(0);
} 