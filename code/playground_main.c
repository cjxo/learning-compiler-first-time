#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "base.h"

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
os_release_memory(void *memory_to_release) {
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

function Memory_Arena *
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
function void *
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
function void *
arena_push_size_zero(Memory_Arena *arena, u64 push_size_bytes) {
    void *result = arena_push_size(arena, push_size_bytes);
    clear_memory(result, align_a_to_b(push_size_bytes, 8));
    return(result);
}

function void
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
global thread_var Memory_Arena *per_thread_scratch[scratch_count] = { 0 };

function Memory_Arena *
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

inline b32
str8_contains_char(String_Const_U8 source, u8 c) {
    b32 result = false;
    
    for (u64 char_index = 0;
         char_index < source.char_count;
         ++char_index) {
        if (source.str[char_index] == c) {
            result = true;
            break;
        }
    }
    
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

function b32
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

function u64
str8_compute_hash(u64 base, String_Const_U8 string) {
    u64 hash_value = base;
    for (u64 char_index = 0;
         char_index < string.char_count;
         char_index += 1) {
        hash_value = (hash_value << 5) + string.str[char_index];
    }
    
    return(hash_value);
}

typedef u16 Automaton_Type;
enum {
    Automaton_Nondeterministic,
    Automaton_Deterministic,
};

typedef u16 Automaton_Flags;
enum {
    AutomatonFlag_Inital = 0x1,
    AutomatonFlag_Accepting = 0x2,
};

typedef struct Automaton_State Automaton_State;
struct Automaton_State {
    String_U8 identifier;
    u8 flags;
    u64 subscript; // in other words, the ith node among the n nodes.
    Automaton_State *next;
    Automaton_State *prev;
};

typedef struct Automaton_State_Transition_Node Automaton_State_Transition_Node;
struct Automaton_State_Transition_Node {
    Automaton_State *transition_to;
    u8 edge_label; // TODO(christian): this should be a string for multiple characters.
    String_U8 edge_label_; // NOTE(christian): for minimized dfa
    b32 is_epsilon_transition;
    Automaton_State_Transition_Node *next;
};

typedef struct Automaton_State_Transition Automaton_State_Transition;
struct Automaton_State_Transition {
    Automaton_State *transition_from;
    Automaton_State_Transition_Node *first;
    Automaton_State_Transition_Node *last;
    Automaton_State_Transition *next_in_hash;
};

// NOTE(christian): we use an adjacency list representation.
// FA is DIRECTED GRAPH
// adjacency list -> are transitions
// vertices / nodes -> are states
typedef struct {
    Automaton_Type type;
    Automaton_State *first_state;
    Automaton_State *last_state;
    
    Automaton_State *start_state;
    Automaton_State *end_state;
    
    u64 state_count;
    Automaton_State_Transition *transitions[32];
    String_Const_U8 alphabet;
} Finite_Automaton;

function b32
fa_contains_state(Finite_Automaton *fa, Automaton_State *state) {
    b32 result = false;
    for (Automaton_State *state_in_list = fa->first_state;
         state_in_list;
         state_in_list = state_in_list->next) {
        if (state_in_list == state) {
            result = true;
            break;
        }
    }
    
    return(result);
}

function Automaton_State *
fa_insert_state(Finite_Automaton *fa, Memory_Arena *arena) {
    Automaton_State *result = arena_push_struct_zero(arena, Automaton_State);
    result->subscript = fa->state_count;
    result->identifier = str8_format(arena, str8("f%llu"), fa->state_count++);
    dll_push_back(fa->first_state, fa->last_state, result);
    return(result);
}

function void
fa_add_transition(Finite_Automaton *fa, Memory_Arena *arena,
                  Automaton_State *from, Automaton_State *to,
                  u8 edge_label, b32 is_epsilon) {
    assert_true(from != null);
    assert_true(to != null);
    
    assert_true(fa_contains_state(fa, from));
    assert_true(fa_contains_state(fa, to));
    
    u64 hash = str8_compute_hash(0, from->identifier) % array_count(fa->transitions);
    Automaton_State_Transition *transitions = fa->transitions[hash];
    while (transitions && (transitions->transition_from != from)) {
        transitions = transitions->next_in_hash;
    }
    
    if (!transitions) {
        transitions = arena_push_struct(arena, Automaton_State_Transition);
        transitions->transition_from = from;
        transitions->first = transitions->last = null;
        transitions->next_in_hash = fa->transitions[hash];
        fa->transitions[hash] = transitions;
    }
    
    Automaton_State_Transition_Node *transition_to = arena_push_struct(arena, Automaton_State_Transition_Node);
    transition_to->transition_to = to;
    transition_to->edge_label = edge_label;
    transition_to->is_epsilon_transition = is_epsilon;
    sll_push_back(transitions->first, transitions->last, transition_to);
}

function void
fa_add_transition2(Finite_Automaton *fa, Memory_Arena *arena,
                   Automaton_State *from, Automaton_State *to,
                   String_U8 edge_label) {
    assert_true(from != null);
    assert_true(to != null);
    
    assert_true(fa_contains_state(fa, from));
    assert_true(fa_contains_state(fa, to));
    
    u64 hash = str8_compute_hash(0, from->identifier) % array_count(fa->transitions);
    Automaton_State_Transition *transitions = fa->transitions[hash];
    while (transitions && (transitions->transition_from != from)) {
        transitions = transitions->next_in_hash;
    }
    
    if (!transitions) {
        transitions = arena_push_struct(arena, Automaton_State_Transition);
        transitions->transition_from = from;
        transitions->first = transitions->last = null;
        transitions->next_in_hash = fa->transitions[hash];
        fa->transitions[hash] = transitions;
    }
    
    Automaton_State_Transition_Node *transition_to = arena_push_struct(arena, Automaton_State_Transition_Node);
    transition_to->transition_to = to;
    transition_to->edge_label_ = edge_label;
    transition_to->is_epsilon_transition = false;
    sll_push_back(transitions->first, transitions->last, transition_to);
}

function Automaton_State_Transition *
fa_transitions_for_state(Finite_Automaton *fa, Automaton_State *from) {
    assert_true(fa_contains_state(fa, from));
    
    u64 hash = str8_compute_hash(0, from->identifier) % array_count(fa->transitions);
    Automaton_State_Transition *transitions = fa->transitions[hash];
    while (transitions && (transitions->transition_from != from)) {
        transitions = transitions->next_in_hash;
    }
    
    return(transitions);
}

typedef struct {
    Automaton_State *start;
    Automaton_State *end;
} RE_To_NFA_Connection;

function String_Const_U8
regex_substring_without_parens(String_Const_U8 regex, u64 start, u64 dividing_pt, u32 paren_count) {
    if ((regex.str[start] == '(') && (regex.str[dividing_pt - 1] == ')') && (paren_count == 2)) {
        return str8_substring_view(regex, start + 1, dividing_pt - 1);
    } else {
        return str8_substring_view(regex, start, dividing_pt);
    }
}

function RE_To_NFA_Connection
nfa_from_regex_r(Finite_Automaton *fa, Memory_Arena *arena, String_Const_U8 regex) {
    assert_true(regex.char_count != 0);
    // NOTE(christian): base case
    if (regex.char_count == 1) {
        RE_To_NFA_Connection connection;
        connection.start = fa_insert_state(fa, arena);
        connection.end = fa_insert_state(fa, arena);
        
        fa_add_transition(fa, arena, connection.start, connection.end, regex.str[0], false);
        
        b32 char_already_in_str = true;
        for (u64 char_index = 0;
             (char_index < fa->alphabet.char_capacity);
             ++char_index) {
            if ((fa->alphabet.str[char_index] == '\0') ||
                (fa->alphabet.str[char_index] == regex.str[0])) {
                char_already_in_str = false;
                break;
            }
        }
        
        if (!char_already_in_str) {
            fa->alphabet.str[fa->alphabet.char_count++] = regex.str[0];
        }
        return(connection);
    } else {
        // NOTE(christian): recursive case
        
        // NOTE(christian): find dividing point.
        u32 paren_count = 0;
        u64 dividing_point = invalid_index_u64;
        u8 influence_value = 0;
        b32 previous_symbol_is_character = false;
        for (u64 regex_index = 0;
             regex_index < regex.char_count;
             ++regex_index) {
            u8 current_char = regex.str[regex_index];
            u8 test_influence_value = 0;
            u64 next_index = regex_index;
            
            switch (current_char) {
                case '|': {
                    test_influence_value = 3;
                    previous_symbol_is_character = false;
                } break;
                
                case '*': {
                    test_influence_value = 1;
                    previous_symbol_is_character = false;
                } break;
                
                default: {
                    if (current_char == '(') {
#if 0
                        u32 open_paren_count = 0;
                        u32 close_paren_count = 0;
                        while ((next_index < regex.char_count) && (regex.str[next_index] != ')')) {
                            switch (regex.str[next_index]) {
                                case '(': {
                                    ++open_paren_count;
                                } break;
                                
                                case ')': {
                                    ++close_paren_count;
                                } break;
                            }
                            
                            ++next_index;
                        }
                        
                        if (next_index == regex.char_count) {
                            _assert(!"please end with closing parenthesis");
                        }
                        
                        if ((open_paren_count == 1) && (close_paren_count == 1)) {
                            paren_count += 2;
                        } else {
                            next_index = regex_index;
                        }
#endif
                        while ((next_index < regex.char_count) && (regex.str[next_index] != ')')) {
                            ++next_index;
                        }
                        
                        if (next_index == regex.char_count) {
                            _assert(!"please end with closing parenthesis");
                        }
                        
                        paren_count += 2;
                    }
                    
                    if (previous_symbol_is_character) {
                        // NOTE(christian): then this is concat operator.
                        test_influence_value = 2;
                    }
                    
                    previous_symbol_is_character = true;
                } break;
            }
            
            if (test_influence_value > influence_value) {
                influence_value = test_influence_value;
                dividing_point = regex_index;
            }
            
            regex_index = next_index;
        }
        
        assert_true(dividing_point != invalid_index_u64);
        
        RE_To_NFA_Connection combined = { 0 };
        String_Const_U8 left_regex = regex_substring_without_parens(regex, 0, dividing_point, paren_count);
        RE_To_NFA_Connection left_recurse_result = nfa_from_regex_r(fa, arena, left_regex);
        u8 operator = regex.str[dividing_point];
        if (operator != '*') {
            if (operator == '|') {
                String_Const_U8 right_regex = regex_substring_without_parens(regex, dividing_point + 1, regex.char_count, paren_count);
                RE_To_NFA_Connection right_recurse_result = nfa_from_regex_r(fa, arena, right_regex);
                combined.start = fa_insert_state(fa, arena);
                fa_add_transition(fa, arena, combined.start, left_recurse_result.start, 'e', true);
                fa_add_transition(fa, arena, combined.start, right_recurse_result.start, 'e', true);
                
                combined.end = fa_insert_state(fa, arena);
                fa_add_transition(fa, arena, left_recurse_result.end, combined.end, 'e', true);
                fa_add_transition(fa, arena, right_recurse_result.end, combined.end, 'e', true);
            } else {
                String_Const_U8 right_regex = regex_substring_without_parens(regex, dividing_point, regex.char_count, paren_count);
                RE_To_NFA_Connection right_recurse_result = nfa_from_regex_r(fa, arena, right_regex);
                
                fa_add_transition(fa, arena, left_recurse_result.end, right_recurse_result.start, 'e', true);
                combined.start = left_recurse_result.start;
                combined.end = right_recurse_result.end;
            }
        } else {
            combined.start = fa_insert_state(fa, arena);
            combined.end = fa_insert_state(fa, arena);
            fa_add_transition(fa, arena, combined.start, left_recurse_result.start, 'e', true);
            fa_add_transition(fa, arena, left_recurse_result.end, combined.end, 'e', true);
            fa_add_transition(fa, arena, left_recurse_result.end, left_recurse_result.start, 'e', true);
            fa_add_transition(fa, arena, combined.start, combined.end, 'e', true);
        }
        
        return(combined);
    }
}

function void
nfa_print_states_and_transitions(Finite_Automaton *nfa) {
    for (Automaton_State *current_state = nfa->first_state;
         current_state;
         current_state = current_state->next) {
        Automaton_State_Transition *transitions = fa_transitions_for_state(nfa, current_state);
        if (transitions) {
            printf("(%s)", current_state->identifier.str);
            assert_true(transitions->transition_from != null);
            assert_true(str8_equal_strings(transitions->transition_from->identifier, current_state->identifier));
            
            for (Automaton_State_Transition_Node *transition = transitions->first;
                 transition;
                 transition = transition->next) {
                assert_true(transition->transition_to != null);
                if (transition->is_epsilon_transition) {
                    printf(" -> {%c}", transition->edge_label);
                } else {
                    printf(" -> %c", transition->edge_label);
                }
                if (transition->transition_to->flags & AutomatonFlag_Accepting) {
                    printf(" -> ((%s))", transition->transition_to->identifier.str);
                } else {
                    printf(" -> (%s)", transition->transition_to->identifier.str);
                }
            }
            
            printf("\n");
        }
    }
}

function void
nfa_print_states_and_transitions2(Finite_Automaton *nfa) {
    for (Automaton_State *current_state = nfa->first_state;
         current_state;
         current_state = current_state->next) {
        Automaton_State_Transition *transitions = fa_transitions_for_state(nfa, current_state);
        if (transitions) {
            printf("(%s)", current_state->identifier.str);
            assert_true(transitions->transition_from != null);
            assert_true(str8_equal_strings(transitions->transition_from->identifier, current_state->identifier));
            
            for (Automaton_State_Transition_Node *transition = transitions->first;
                 transition;
                 transition = transition->next) {
                assert_true(transition->transition_to != null);
                if (transition->is_epsilon_transition) {
                    printf(" -> {%s}", transition->edge_label_.str);
                } else {
                    printf(" -> %s", transition->edge_label_.str);
                }
                if (transition->transition_to->flags & AutomatonFlag_Accepting) {
                    printf(" -> ((%s))", transition->transition_to->identifier.str);
                } else {
                    printf(" -> (%s)", transition->transition_to->identifier.str);
                }
            }
            
            printf("\n");
        }
    }
}

// NOTE(christian): nice property of NFA from Regex
// - No transition other that the initial transition enters the start state
// - No transition leaves the accepting state
// - Each state has at most two entering and two exiting epsilon moves.
// - At most one entering and one exiting move on a symbol in the alphabet.
function Finite_Automaton
nfa_from_regex(Memory_Arena *arena, String_Const_U8 regex) {
    Finite_Automaton result = { 0 };
    result.type = Automaton_Nondeterministic;
    result.alphabet = str8_reserve(arena, 256); // max 256 characters
    clear_memory(result.alphabet.str, 256);
    nfa_from_regex_r(&result, arena, regex);
    
    // TODO(christian): Surely there is a graph algorithm for this!
    for (Automaton_State *state = result.first_state;
         state;
         state = state->next) {
        b32 transitions_to_state = false;
        for (Automaton_State *inner_state = result.first_state;
             inner_state && !transitions_to_state;
             inner_state = inner_state->next) {
            Automaton_State_Transition *transition = fa_transitions_for_state(&result, inner_state);
            if (transition) {
                for (Automaton_State_Transition_Node *tnode = transition->first;
                     tnode;
                     tnode = tnode->next) {
                    if (tnode->transition_to == state) {
                        transitions_to_state = true;
                        break;
                    }
                }
            }
        }
        
        if (!transitions_to_state) {
            result.start_state = state;
            state->flags |= AutomatonFlag_Inital;
            break;
        }
    }
    
    for (Automaton_State *state = result.first_state;
         state;
         state = state->next) {
        if (state != result.first_state) {
            Automaton_State_Transition *transition = fa_transitions_for_state(&result, state);
            if (!transition) {
                state->flags |= AutomatonFlag_Accepting;
                result.end_state = state;
                break;
            }
        }
    }
    
    return(result);
}

// DFN: dfa_from_nfa
typedef struct DFN_Work_Node DFN_Work_Node;

struct DFN_Work_Node {
    Automaton_State *state;
    DFN_Work_Node *next;
};

// NOTE(christian): a set
typedef struct DFN_Work_Config DFN_Work_Config;
struct DFN_Work_Config {
    DFN_Work_Node *first;
    DFN_Work_Node *last;
    Automaton_State *dfa_equivalent;
    
    DFN_Work_Config *next;
    DFN_Work_Config *prev;
};

typedef u8 DFS_State;
enum {
    DFSState_NotDiscovered,
    DFSState_Discovered,
    DFSState_Proccessed,
    DFSState_Count,
};

typedef struct {
    Automaton_State *automaton_node;
    DFS_State dfs_state;
} Follow_Epsilon_DFS_Node;

function DFN_Work_Config *
dfn_follow_epsilon(Memory_Arena *arena, Finite_Automaton *nfa, Automaton_State *emanate_from) {
    assert_true(nfa->type == Automaton_Nondeterministic);
    DFN_Work_Config *result = arena_push_struct_zero(arena, DFN_Work_Config);
    
    Temporary_Memory follow_memory = temp_mem_begin(arena_get_scratch(&arena, 1));
    Follow_Epsilon_DFS_Node *nodes = arena_push_array(follow_memory.base, Follow_Epsilon_DFS_Node,
                                                      nfa->state_count);
    {
        u32 node_index = 0;
        for (Automaton_State *state = nfa->first_state; state; state = state->next) {
            Follow_Epsilon_DFS_Node *node = nodes + node_index++;
            node->automaton_node = state;
            node->dfs_state = DFSState_NotDiscovered;
        }
    }
    
    u64 dfs_node_stack_ptr = 0;
    Follow_Epsilon_DFS_Node **dfs_node_stack = arena_push_array(follow_memory.base,
                                                                Follow_Epsilon_DFS_Node *,
                                                                nfa->state_count);
    
    dfs_node_stack[dfs_node_stack_ptr++] = nodes + emanate_from->subscript;
    {
        dfs_node_stack[dfs_node_stack_ptr - 1]->dfs_state = DFSState_Discovered;
        DFN_Work_Node *initial_node = arena_push_struct(arena, DFN_Work_Node);
        initial_node->state = emanate_from;
        initial_node->next = null;
        sll_push_back(result->first, result->last, initial_node);
    }
    
    while (dfs_node_stack_ptr) {
        Follow_Epsilon_DFS_Node *popped_node = dfs_node_stack[dfs_node_stack_ptr - 1];
        Automaton_State_Transition *transitions_for_popped = fa_transitions_for_state(nfa, popped_node->automaton_node);
        assert_true(popped_node->dfs_state == DFSState_Discovered);
        b32 pushed_to_stack = false;
        if (transitions_for_popped) {
            for (Automaton_State_Transition_Node *adjacent_from_popped = transitions_for_popped->first;
                 adjacent_from_popped;
                 adjacent_from_popped = adjacent_from_popped->next) {
                if (adjacent_from_popped->is_epsilon_transition) {
                    Follow_Epsilon_DFS_Node *adjacent_dfs_node = nodes + adjacent_from_popped->transition_to->subscript;
                    if (adjacent_dfs_node->dfs_state == DFSState_NotDiscovered) {
                        adjacent_dfs_node->dfs_state = DFSState_Discovered;
                        pushed_to_stack = true;
                        
                        dfs_node_stack[dfs_node_stack_ptr++] = adjacent_dfs_node;
                        
                        DFN_Work_Node *new_node = arena_push_struct(arena, DFN_Work_Node);
                        new_node->state = adjacent_dfs_node->automaton_node;
                        sll_push_back(result->first, result->last, new_node);
                        break;
                    }
                }
            }
        }
        
        if (!pushed_to_stack) {
            --dfs_node_stack_ptr;
            popped_node->dfs_state = DFSState_Proccessed;
        }
    }
    
    temp_mem_end(follow_memory);
    return(result);
}

function DFN_Work_Config *
dfn_copy_configs(Memory_Arena *arena,  DFN_Work_Config *source) {
    DFN_Work_Config *result = arena_push_struct_zero(arena, DFN_Work_Config);
    for (DFN_Work_Node *node = source->first;
         node;
         node = node->next) {
        DFN_Work_Node *copied_node = arena_push_struct(arena, DFN_Work_Node);
        copied_node->state = node->state;
        copied_node->next = null;
        sll_push_back(result->first, result->last, copied_node);
    }
    
    return(result);
}

function Finite_Automaton
dfa_from_nfa(Memory_Arena *arena, Finite_Automaton *nfa) {
    Finite_Automaton result_dfa = { 0 };
    result_dfa.type = Automaton_Deterministic;
    result_dfa.alphabet = str8_copy(arena, nfa->alphabet);
    
    Temporary_Memory conversion_memory = temp_mem_begin(arena_get_scratch(&arena, 1));
    
    // NOTE(christian): WorkList in book
    DFN_Work_Config *work_queue_first = dfn_follow_epsilon(conversion_memory.base, nfa, nfa->start_state);
    DFN_Work_Config *work_queue_last = work_queue_first;
    
    // NOTE(christian): Q in Book
    DFN_Work_Config *dfa_state_model_first = dfn_copy_configs(conversion_memory.base, work_queue_first);
    DFN_Work_Config *dfa_state_model_last = dfa_state_model_first;
    
    {
        Automaton_State *dfa_state = fa_insert_state(&result_dfa, arena);
        dfa_state->flags |= AutomatonFlag_Inital;
        result_dfa.start_state = dfa_state;
        work_queue_first->dfa_equivalent = dfa_state;
        dfa_state_model_first->dfa_equivalent = dfa_state;
    }
    
    while (work_queue_first) {
        DFN_Work_Config *dequeued_from_work = work_queue_first;
        dll_remove(work_queue_first, work_queue_last, dequeued_from_work);
        
        for (u32 character_index = 0;
             character_index < nfa->alphabet.char_count;
             ++character_index) {
            DFN_Work_Config *another_nfa_config = null;
            for (DFN_Work_Node *dequeued_nfa_state_from_work = dequeued_from_work->first;
                 dequeued_nfa_state_from_work && !another_nfa_config;
                 dequeued_nfa_state_from_work = dequeued_nfa_state_from_work->next) {
                Automaton_State_Transition *transition_list = fa_transitions_for_state(nfa, dequeued_nfa_state_from_work->state);
                
                if (transition_list) {
                    for (Automaton_State_Transition_Node *transition_node = transition_list->first;
                         transition_node && !another_nfa_config;
                         transition_node = transition_node->next) {
                        if ((transition_node->edge_label == nfa->alphabet.str[character_index]) &&
                            (!transition_node->is_epsilon_transition)) {
                            // NOTE(christian): NFA Construction Property Used:
                            // "At most one entering and one exiting move on a symbol in the alphabet."
                            // That is, we can end here and not check for other configs. Easy.
                            another_nfa_config = dfn_follow_epsilon(conversion_memory.base,
                                                                    nfa,
                                                                    transition_node->transition_to);
                        }
                    }
                }
            }
            
            if (another_nfa_config) {
                // NOTE(christian): is another_nfa_config in dfa_state_model?
                b32 is_already_queued = false;
                DFN_Work_Config *queued_equivalent = null;
                for (DFN_Work_Config *config_in_model = dfa_state_model_first;
                     config_in_model;
                     config_in_model = config_in_model->next) {
                    // NOTE(christian): set equality
                    DFN_Work_Node *outer_node = another_nfa_config->first;
                    while (outer_node) {
                        b32 has_element = false;
                        for (DFN_Work_Node *inner_node = config_in_model->first;
                             inner_node; 
                             inner_node = inner_node->next) {
                            if (outer_node->state == inner_node->state) {
                                has_element = true;
                                break;
                            }
                        }
                        
                        if (!has_element) {
                            break;
                        }
                        
                        outer_node = outer_node->next;
                    }
                    
                    if (outer_node == null) {
                        queued_equivalent = config_in_model;
                        is_already_queued = true;
                        break;
                    }
                }
                
                if (!is_already_queued) {
                    dll_push_back(work_queue_first, work_queue_last, another_nfa_config);
                    DFN_Work_Config *copied = dfn_copy_configs(conversion_memory.base, another_nfa_config);
                    dll_push_back(dfa_state_model_first, dfa_state_model_last, copied);
                    
                    Automaton_State *new_dfa_state = fa_insert_state(&result_dfa, arena);
                    another_nfa_config->dfa_equivalent = new_dfa_state;
                    copied->dfa_equivalent = new_dfa_state;
                    
                    queued_equivalent = another_nfa_config;
                    
                    for (DFN_Work_Node *node = another_nfa_config->first;
                         node;
                         node = node->next) {
                        if (node->state->flags & AutomatonFlag_Accepting) {
                            new_dfa_state->flags |= AutomatonFlag_Accepting;
                            result_dfa.end_state = new_dfa_state;
                            break;
                        }
                    }
                }
                
                assert_true(queued_equivalent != null);
                assert_true(dequeued_from_work->dfa_equivalent != null);
                assert_true(queued_equivalent->dfa_equivalent != null);
                
                fa_add_transition(&result_dfa, arena, dequeued_from_work->dfa_equivalent,
                                  queued_equivalent->dfa_equivalent, nfa->alphabet.str[character_index],
                                  false);
            }
        }
    }
    
    temp_mem_end(conversion_memory);
    return(result_dfa);
}

typedef struct Hopcroft_Partition_DFA_Node Hopcroft_Partition_DFA_Node;
struct Hopcroft_Partition_DFA_Node {
    Automaton_State *dfa_state;
    Hopcroft_Partition_DFA_Node *next;
};

// NOTE(christian): this list contains a set of DFA states that are
// equivalent. Two DFA states are equivalent when they produce the
// same behavior on any input string.
// Rules:
// - Two states in the same set must for every character in alphabet
// transitions to states that are themselves a member of a sigle set of
// partition
// - any single set must contain dfa states that are either an accepting state or not an
// accepting state.
typedef struct Hopcroft_Partition_Node Hopcroft_Partition_Node;
struct Hopcroft_Partition_Node {
    Hopcroft_Partition_DFA_Node *first;
    Hopcroft_Partition_DFA_Node *last;
    Hopcroft_Partition_Node *next;
    Hopcroft_Partition_Node *prev;
    
    Automaton_State *associated_dfa_state;
};

typedef struct Hopcroft_Partition_Transition_Node Hopcroft_Partition_Transition_Node;
struct Hopcroft_Partition_Transition_Node {
    Hopcroft_Partition_Node *transition_to;
    String_U8 edge_label;
    Hopcroft_Partition_Transition_Node *next;
};

typedef struct Hopcroft_Partition_Transition Hopcroft_Partition_Transition;
struct Hopcroft_Partition_Transition {
    Hopcroft_Partition_Node *transition_from;
    Hopcroft_Partition_Transition_Node *first;
    Hopcroft_Partition_Transition_Node *last;
    Hopcroft_Partition_Transition *next_in_hash;
};

typedef struct {
    Hopcroft_Partition_Transition *transition[32];
} Hopcroft_Transition;

function void
hc_add_transition(Hopcroft_Transition *transition_data, Memory_Arena *arena,
                  Hopcroft_Partition_Node *from, Hopcroft_Partition_Node *to,
                  String_U8 edge_label) {
    assert_true(from != null);
    assert_true(to != null);
    
    // NOTE(christian): outstanding hash function
    u64 hash = (u64)from % array_count(transition_data->transition);
    Hopcroft_Partition_Transition *transitions = transition_data->transition[hash];
    while (transitions && (transitions->transition_from != from)) {
        transitions = transitions->next_in_hash;
    }
    
    if (!transitions) {
        transitions = arena_push_struct(arena, Hopcroft_Partition_Transition);
        transitions->transition_from = from;
        transitions->first = transitions->last = null;
        transitions->next_in_hash = transition_data->transition[hash];
        transition_data->transition[hash] = transitions;
    }
    
    Hopcroft_Partition_Transition_Node *transition_to = arena_push_struct(arena, Hopcroft_Partition_Transition_Node);
    transition_to->transition_to = to;
    transition_to->edge_label = edge_label;
    transition_to->next = null;
    sll_push_back(transitions->first, transitions->last, transition_to);
}

function Hopcroft_Partition_Transition *
hc_get_transitions_for_partition_group(Hopcroft_Transition *transition_data,
                                       Hopcroft_Partition_Node *from) {
    u64 hash = (u64)from % array_count(transition_data->transition);
    Hopcroft_Partition_Transition *transitions = transition_data->transition[hash];
    while (transitions && (transitions->transition_from != from)) {
        transitions = transitions->next_in_hash;
    }
    
    return(transitions);
}

function String_U8
hc_acquire_alphabet_in_partition_group(Finite_Automaton *associated_automaton,
                                       Hopcroft_Partition_Node *from,
                                       Memory_Arena *arena) {
    String_U8 result = { 0 };
    b32 acquire_memory = true;
    result.str = arena->memory + arena->stack_ptr;
    
    for (Hopcroft_Partition_DFA_Node *node = from->first;
         node;
         node = node->next) {
        Automaton_State_Transition *transitions = fa_transitions_for_state(associated_automaton, node->dfa_state);
        if (transitions) {
            for (Automaton_State_Transition_Node *transition_to = transitions->first;
                 transition_to;
                 transition_to = transition_to->next) {
                if (!str8_contains_char(result, transition_to->edge_label)) {
                    if (acquire_memory) {
                        arena_push_struct(arena, u8);
                        acquire_memory = false;
                    }
                    
                    result.str[result.char_count++] = transition_to->edge_label;
                    acquire_memory = ((result.char_count % 8) == 0);
                }
            }
        }
    }
    
    return (result);
}

function Hopcroft_Partition_Node *
hc_copy_partitions(Memory_Arena *arena, Hopcroft_Partition_Node *partition) {
    Hopcroft_Partition_Node *result = arena_push_struct_zero(arena, Hopcroft_Partition_Node);
    for (Hopcroft_Partition_DFA_Node *dfa_node = partition->first;
         dfa_node;
         dfa_node = dfa_node->next) {
        Hopcroft_Partition_DFA_Node *copied = arena_push_struct(arena, Hopcroft_Partition_DFA_Node);
        copied->dfa_state = dfa_node->dfa_state;
        copied->next = null;
        
        sll_push_back(result->first, result->last, copied);
    }
    return(result);
}

function Hopcroft_Partition_Node *
hc_compute_image(Memory_Arena *arena, Finite_Automaton *dfa,
                 Hopcroft_Partition_Node *transitions_to, u8 character) {
    assert_true(dfa->type == Automaton_Deterministic);
    Hopcroft_Partition_Node *result = arena_push_struct_zero(arena, Hopcroft_Partition_Node);
    
    for (Automaton_State *dfa_state = dfa->first_state;
         dfa_state;
         dfa_state = dfa_state->next) {
        Hopcroft_Partition_DFA_Node *accepted_state = null;
        Automaton_State_Transition *transition_list = fa_transitions_for_state(dfa, dfa_state);
        if (transition_list) {
            for (Automaton_State_Transition_Node *transition_to = transition_list->first;
                 transition_to && !accepted_state;
                 transition_to = transition_to->next) {
                if (!transition_to->is_epsilon_transition &&
                    (transition_to->edge_label == character)) {
                    for (Hopcroft_Partition_DFA_Node *test_node = transitions_to->first;
                         test_node;
                         test_node = test_node->next) {
                        if (test_node->dfa_state == transition_to->transition_to) {
                            accepted_state = arena_push_struct(arena, Hopcroft_Partition_DFA_Node);
                            accepted_state->dfa_state = dfa_state;
                            accepted_state->next = null;
                            break;
                        }
                    }
                }
            }
        }
        
        if (accepted_state) {
            sll_push_back(result->first, result->last, accepted_state);
        }
    }
    
    return(result);
}

function Finite_Automaton
dfa_minimize(Memory_Arena *arena, Finite_Automaton *dfa) {
    Finite_Automaton dfa_minimized = { 0 };
    dfa_minimized.type = Automaton_Deterministic;
    dfa_minimized.alphabet = str8_copy(arena, dfa->alphabet);
    
    Temporary_Memory minimization_memory = temp_mem_begin(arena_get_scratch(&arena, 1));
    
    // NOTE(christian): Worklist in Book
    Hopcroft_Partition_Node *partition_queue_first = null;
    Hopcroft_Partition_Node *partition_queue_last = null;
    
    // NOTE(christian): each set in this set of sets becomes a state in the minimal dfa.
    // NOTE(christian): Partition in Book
    u64 minimized_dfa_model_count = 0;
    Hopcroft_Partition_Node *minimized_dfa_model_first = null;
    Hopcroft_Partition_Node *minimized_dfa_model_last = null;
    
    {
        Hopcroft_Partition_Node *queue_accepting = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
        Hopcroft_Partition_Node *queue_non_accepting = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
        for (Automaton_State *dfa_state = dfa->first_state;
             dfa_state;
             dfa_state = dfa_state->next) {
            Hopcroft_Partition_DFA_Node *new_node = arena_push_struct(minimization_memory.base, Hopcroft_Partition_DFA_Node);
            new_node->dfa_state = dfa_state;
            new_node->next = null;
            if (dfa_state->flags & AutomatonFlag_Accepting) {
                sll_push_back(queue_accepting->first, queue_accepting->last, new_node);
            } else {
                sll_push_back(queue_non_accepting->first, queue_non_accepting->last, new_node);
            }
        }
        
        dll_push_back(partition_queue_first, partition_queue_last, queue_accepting);
        dll_push_back(partition_queue_first, partition_queue_last, queue_non_accepting);
        
        //~
        queue_accepting = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
        queue_non_accepting = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
        for (Automaton_State *dfa_state = dfa->first_state;
             dfa_state;
             dfa_state = dfa_state->next) {
            Hopcroft_Partition_DFA_Node *new_node = arena_push_struct(minimization_memory.base, Hopcroft_Partition_DFA_Node);
            new_node->dfa_state = dfa_state;
            new_node->next = null;
            if (dfa_state->flags & AutomatonFlag_Accepting) {
                sll_push_back(queue_accepting->first, queue_accepting->last, new_node);
            } else {
                sll_push_back(queue_non_accepting->first, queue_non_accepting->last, new_node);
            }
        }
        
        minimized_dfa_model_count += 2;
        dll_push_back(minimized_dfa_model_first, minimized_dfa_model_last, queue_accepting);
        dll_push_back(minimized_dfa_model_first, minimized_dfa_model_last, queue_non_accepting);
    }
    
    while (partition_queue_first) {
        Hopcroft_Partition_Node *dequeued_from_queue = partition_queue_first;
        dll_remove(partition_queue_first, partition_queue_last, dequeued_from_queue);
        for (u64 character_index = 0;
             character_index < dfa->alphabet.char_count;
             ++character_index) {
            u8 character = dfa->alphabet.str[character_index];
            // NOTE(christian): image: dfa states that can reach a state in dequeued_from_queue with respect
            // to character
            Hopcroft_Partition_Node *image = hc_compute_image(minimization_memory.base, dfa, dequeued_from_queue, character);
            
            u64 set_in_partition_with_state_in_image_count = 0;
            Hopcroft_Partition_Node **set_in_partition_with_state_in_image = arena_push_array(minimization_memory.base, Hopcroft_Partition_Node *, minimized_dfa_model_count);
            
            for (Hopcroft_Partition_Node *node_in_model = minimized_dfa_model_first;
                 node_in_model;
                 node_in_model = node_in_model->next) {
                b32 accept_node = false;
                for (Hopcroft_Partition_DFA_Node *dfa_node_in_model = node_in_model->first;
                     dfa_node_in_model && !accept_node;
                     dfa_node_in_model = dfa_node_in_model->next) {
                    for (Hopcroft_Partition_DFA_Node *dfa_node_in_image = image->first;
                         dfa_node_in_image;
                         dfa_node_in_image = dfa_node_in_image->next) {
                        if (dfa_node_in_image->dfa_state == dfa_node_in_model->dfa_state) {
                            accept_node = true;
                            break;
                        }
                    }
                }
                
                if (accept_node) {
                    assert_true(set_in_partition_with_state_in_image_count < minimized_dfa_model_count);
                    set_in_partition_with_state_in_image[set_in_partition_with_state_in_image_count++] = node_in_model;
                }
            }
            
            for (u64 partition_index = 0;
                 partition_index < set_in_partition_with_state_in_image_count;
                 ++partition_index) {
                Hopcroft_Partition_Node *partition = set_in_partition_with_state_in_image[partition_index];
                
                u64 intersect_count = 0;
                Hopcroft_Partition_Node *partiton_intersect_image = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
                u64 difference_count = 0;
                Hopcroft_Partition_Node *partiton_difference_intersect = arena_push_struct_zero(minimization_memory.base, Hopcroft_Partition_Node);
                
                for (Hopcroft_Partition_DFA_Node *partition_dfa = partition->first;
                     partition_dfa;
                     partition_dfa = partition_dfa->next) {
                    b32 in_intersection = false;
                    
                    for (Hopcroft_Partition_DFA_Node *dfa_node_in_image = image->first;
                         dfa_node_in_image;
                         dfa_node_in_image = dfa_node_in_image->next) {
                        if (partition_dfa->dfa_state == dfa_node_in_image->dfa_state) {
                            in_intersection = true;
                            break;
                        }
                    }
                    
                    if (in_intersection) {
                        Hopcroft_Partition_DFA_Node *intersected = arena_push_struct(minimization_memory.base, Hopcroft_Partition_DFA_Node);
                        intersected->dfa_state = partition_dfa->dfa_state;
                        intersected->next = null;
                        sll_push_back(partiton_intersect_image->first, partiton_intersect_image->last, intersected);
                        ++intersect_count;
                    }
                }
                
                for (Hopcroft_Partition_DFA_Node *partition_dfa = partition->first;
                     partition_dfa;
                     partition_dfa = partition_dfa->next) {
                    b32 not_in_intersect = true;
                    for (Hopcroft_Partition_DFA_Node *dfa_node_in_intersect = partiton_intersect_image->first;
                         dfa_node_in_intersect;
                         dfa_node_in_intersect = dfa_node_in_intersect->next) {
                        if (partition_dfa->dfa_state == dfa_node_in_intersect->dfa_state) {
                            not_in_intersect = false;
                            break;
                        }
                    }
                    
                    if (not_in_intersect) {
                        Hopcroft_Partition_DFA_Node *difference = arena_push_struct(minimization_memory.base, Hopcroft_Partition_DFA_Node);
                        difference->dfa_state = partition_dfa->dfa_state;
                        difference->next = null;
                        sll_push_back(partiton_difference_intersect->first, partiton_difference_intersect->last, difference);
                        ++difference_count;
                    }
                }
                
                if (difference_count) {
                    assert_true(minimized_dfa_model_count > 0);
                    minimized_dfa_model_count -= 1;
                    
                    dll_remove(minimized_dfa_model_first, minimized_dfa_model_last, partition);
                    dll_push_back(minimized_dfa_model_first, minimized_dfa_model_last, partiton_intersect_image);
                    dll_push_back(minimized_dfa_model_first, minimized_dfa_model_last, partiton_difference_intersect);
                    minimized_dfa_model_count += 2;
                    
                    Hopcroft_Partition_Node *work_equivalent = null;
                    for (Hopcroft_Partition_Node *work_node = partition_queue_first;
                         work_node;
                         work_node = work_node->next) {
                        Hopcroft_Partition_DFA_Node *outer_node = work_node->first;
                        while (outer_node) {
                            b32 has_element = false;
                            for (Hopcroft_Partition_DFA_Node *inner_node = partition->first;
                                 inner_node;
                                 inner_node = inner_node->next) {
                                if (outer_node->dfa_state == inner_node->dfa_state) {
                                    has_element = true;
                                    break;
                                }
                            }
                            
                            if (!has_element) {
                                break;
                            }
                            
                            outer_node = outer_node->next;
                        }
                        
                        if (outer_node == null) {
                            work_equivalent = work_node;
                            break;
                        }
                    }
                    
                    if (work_equivalent) {
                        assert_true(work_equivalent != null);
                        dll_remove(partition_queue_first, partition_queue_last, work_equivalent);
                        
                        Hopcroft_Partition_Node *copied = hc_copy_partitions(minimization_memory.base, partiton_intersect_image);
                        dll_push_back(partition_queue_first, partition_queue_last, copied);
                        
                        copied = hc_copy_partitions(minimization_memory.base, partiton_difference_intersect);
                        dll_push_back(partition_queue_first, partition_queue_last, copied);
                    } else if (intersect_count <= difference_count) {
                        Hopcroft_Partition_Node *copied = hc_copy_partitions(minimization_memory.base, partiton_intersect_image);
                        dll_push_back(partition_queue_first, partition_queue_last, copied);
                    } else {
                        Hopcroft_Partition_Node *copied = hc_copy_partitions(minimization_memory.base, partiton_difference_intersect);
                        dll_push_back(partition_queue_first, partition_queue_last, copied);
                    }
                    
                    Hopcroft_Partition_DFA_Node *outer_node = dequeued_from_queue->first;
                    while (outer_node) {
                        b32 has_element = false;
                        for (Hopcroft_Partition_DFA_Node *inner_node = partition->first;
                             inner_node;
                             inner_node = inner_node->next) {
                            if (outer_node->dfa_state == inner_node->dfa_state) {
                                has_element = true;
                                break;
                            }
                        }
                        
                        if (!has_element) {
                            break;
                        }
                        
                        outer_node = outer_node->next;
                    }
                    
                    // NOTE(christian): is equal
                    if (outer_node == null) {
                        break;
                    }
                }
            }
        }
    }
    
    for (Hopcroft_Partition_Node *dfa_state_representative0 = minimized_dfa_model_first;
         dfa_state_representative0;
         dfa_state_representative0 = dfa_state_representative0->next) {
        dfa_state_representative0->associated_dfa_state = fa_insert_state(&dfa_minimized, arena);
        
        // NOTE(christian): technically, we do not need a loop and just take the first entry. But whatever.
        for (Hopcroft_Partition_DFA_Node *dfa_state = dfa_state_representative0->first;
             dfa_state;
             dfa_state = dfa_state->next) {
            if (dfa_state->dfa_state->flags & AutomatonFlag_Accepting) {
                dfa_minimized.end_state = dfa_state_representative0->associated_dfa_state;
                dfa_state_representative0->associated_dfa_state->flags |= AutomatonFlag_Accepting;
            } else if (dfa_state->dfa_state->flags & AutomatonFlag_Inital) {
                dfa_minimized.start_state = dfa_state_representative0->associated_dfa_state;
                dfa_state_representative0->associated_dfa_state->flags |= AutomatonFlag_Inital;
            }
            
            break;
        }
    }
    
    //Hopcroft_Transition intermediary_transitions = { 0 };
    for (Hopcroft_Partition_Node *dfa_state_representative0 = minimized_dfa_model_first;
         dfa_state_representative0;
         dfa_state_representative0 = dfa_state_representative0->next) {
        assert_true(dfa_state_representative0->associated_dfa_state != null);
        
        for (Hopcroft_Partition_DFA_Node *possible_source_transition = dfa_state_representative0->first;
             possible_source_transition;
             possible_source_transition = possible_source_transition->next) {
            Automaton_State_Transition *transitions = fa_transitions_for_state(dfa, possible_source_transition->dfa_state);
            
            if (transitions) {
                Hopcroft_Partition_Node *transition_to_partition = null;
                for (Automaton_State_Transition_Node *transition_to = transitions->first;
                     transition_to && !transition_to_partition;
                     transition_to = transition_to->next) {
                    //u8 character = transition_to->edge_label;
                    
                    // NOTE(christian): it could transition to itself...
                    for (Hopcroft_Partition_Node *dfa_state_representative1 = minimized_dfa_model_first;
                         dfa_state_representative1 && !transition_to_partition;
                         dfa_state_representative1 = dfa_state_representative1->next) {
                        for (Hopcroft_Partition_DFA_Node *possible_dest_transition = dfa_state_representative1->first;
                             possible_dest_transition;
                             possible_dest_transition = possible_dest_transition->next) {
                            if (transition_to->transition_to == possible_dest_transition->dfa_state) {
                                transition_to_partition = dfa_state_representative1;
                                break;
                            }
                        }
                    }
                }
                
                if (transition_to_partition) {
                    assert_true(transition_to_partition->associated_dfa_state != null);
                    fa_add_transition2(&dfa_minimized, arena,
                                       dfa_state_representative0->associated_dfa_state,
                                       transition_to_partition->associated_dfa_state,
                                       hc_acquire_alphabet_in_partition_group(dfa, dfa_state_representative0,
                                                                              arena));
                    break;
                }
            }
        }
    }
    
    temp_mem_end(minimization_memory);
    return(dfa_minimized);
}

function Finite_Automaton
dfa_from_regex(Memory_Arena *arena, String_Const_U8 regex) {
    Finite_Automaton result_dfa;
    
    Memory_Arena *scratch = arena_get_scratch(&arena, 1);
    Temporary_Memory temp = temp_mem_begin(scratch);
    Finite_Automaton nfa = nfa_from_regex(scratch, regex);
    Finite_Automaton dfa = dfa_from_nfa(scratch, &nfa); // temporary.
    result_dfa = dfa_minimize(arena, &dfa);
    temp_mem_end(temp);
    return (result_dfa);
}

int
main(void) {
    // TODO(christian): flaws to fix. nfa_from_regex crashes / fails when we input this
    // our dfa minimization.
    //String_Const_U8 test_regex = str8("fei|gol");
    String_Const_U8 test_regex = str8("a(b|c)*");
    Memory_Arena *main_arena = arena_reserve(mb(512llu));
    Finite_Automaton dfa = dfa_from_regex(main_arena, test_regex);
    nfa_print_states_and_transitions2(&dfa);
    return(0);
}