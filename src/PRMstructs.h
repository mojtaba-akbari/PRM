#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba , The Structures // ***
// Use Stack Programming To Design The Whole PRM //
// Stack Is Faster Than BFP Helper Calls For Allocating Data //
// Here The Structure Is Between 512 Byte Allocation , So I Would Prefer Develop It As Stack //

enum PRM_STATE_ENUM {
    UNLOADED,
    STARTUP,
    LOADED,
    BROKEN,
    TOO_MANY_ROLES,
    NON_OF_GENERAL_ROLE
};

struct prm_state {
    enum PRM_STATE_ENUM prm_state;
};

enum PROCESS_RELATION_ACTION_ENUM{
    ACCEPT,
    REJECT,
    REDIRECT,
    DEBUG,
    RETURN
};

struct process_relation {
    char process[MAX_RELATION_PROCESSNAME];
    char parent[MAX_RELATION_PROCESSNAME];
    char grandparent[MAX_RELATION_PROCESSNAME];
    enum PROCESS_RELATION_ACTION_ENUM action;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_NUMBER_OF_RELATION);
    __type(key, u32);
    __type(value, struct process_relation);
} prm_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PRM_STATE);
    __type(key, __u32);
    __type(value, struct prm_state);
} prm_state_map SEC(".maps");

// Macro to generate function to insert an element into the map
#define DEFINE_LOAD_RELATION_FUNCTION(i)  \
    static int insert_chunk_##i(void) {   \
        __u32 key = i;                      \
        struct process_relation relation = {RELATION_##i}; \
        bpf_printk("Inserted into map: %s -> %s -> %s -> %d\n", relation.process, relation.parent, relation.grandparent, relation.action); \
        bpf_map_update_elem(&prm_map, &key, &relation, BPF_ANY); \
        return 0;                          \
    }

#define GENERATE_LOAD_FUNCTIONS()      \
    DEFINE_LOAD_RELATION_FUNCTION(0);    \
    DEFINE_LOAD_RELATION_FUNCTION(1);    \
    DEFINE_LOAD_RELATION_FUNCTION(2);    \
    DEFINE_LOAD_RELATION_FUNCTION(3);    \
    DEFINE_LOAD_RELATION_FUNCTION(4);    \
    DEFINE_LOAD_RELATION_FUNCTION(5);    \
    DEFINE_LOAD_RELATION_FUNCTION(6);    \
    DEFINE_LOAD_RELATION_FUNCTION(7);    \
    DEFINE_LOAD_RELATION_FUNCTION(8);    \
    DEFINE_LOAD_RELATION_FUNCTION(9);    \
    DEFINE_LOAD_RELATION_FUNCTION(10);   \
    DEFINE_LOAD_RELATION_FUNCTION(11);   \
    DEFINE_LOAD_RELATION_FUNCTION(12);   \
    DEFINE_LOAD_RELATION_FUNCTION(13);   \
    DEFINE_LOAD_RELATION_FUNCTION(14);   \
    DEFINE_LOAD_RELATION_FUNCTION(15);   \
    DEFINE_LOAD_RELATION_FUNCTION(16);   \
    DEFINE_LOAD_RELATION_FUNCTION(17);   \
    DEFINE_LOAD_RELATION_FUNCTION(18);   \
    DEFINE_LOAD_RELATION_FUNCTION(19);   \
    DEFINE_LOAD_RELATION_FUNCTION(20);   \
    DEFINE_LOAD_RELATION_FUNCTION(21);   \
    DEFINE_LOAD_RELATION_FUNCTION(22);   \
    DEFINE_LOAD_RELATION_FUNCTION(23);   \
    DEFINE_LOAD_RELATION_FUNCTION(24);   \
    DEFINE_LOAD_RELATION_FUNCTION(25);   \
    DEFINE_LOAD_RELATION_FUNCTION(26);   \
    DEFINE_LOAD_RELATION_FUNCTION(27);   \
    DEFINE_LOAD_RELATION_FUNCTION(28);   \
    DEFINE_LOAD_RELATION_FUNCTION(29);   \
    DEFINE_LOAD_RELATION_FUNCTION(30);   \
    DEFINE_LOAD_RELATION_FUNCTION(31);   \
    DEFINE_LOAD_RELATION_FUNCTION(32);   \
    DEFINE_LOAD_RELATION_FUNCTION(33);   \
    DEFINE_LOAD_RELATION_FUNCTION(34);   \
    DEFINE_LOAD_RELATION_FUNCTION(35);   \
    DEFINE_LOAD_RELATION_FUNCTION(36);   \
    DEFINE_LOAD_RELATION_FUNCTION(37);   \
    DEFINE_LOAD_RELATION_FUNCTION(38);   \
    DEFINE_LOAD_RELATION_FUNCTION(39);   \
    DEFINE_LOAD_RELATION_FUNCTION(40);   \
    DEFINE_LOAD_RELATION_FUNCTION(41);   \
    DEFINE_LOAD_RELATION_FUNCTION(42);   \
    DEFINE_LOAD_RELATION_FUNCTION(43);   \
    DEFINE_LOAD_RELATION_FUNCTION(44);   \
    DEFINE_LOAD_RELATION_FUNCTION(45);   \
    DEFINE_LOAD_RELATION_FUNCTION(46);   \
    DEFINE_LOAD_RELATION_FUNCTION(47);   \
    DEFINE_LOAD_RELATION_FUNCTION(48);   \
    DEFINE_LOAD_RELATION_FUNCTION(49);   \

#define CALL_RELATION_FUNCTIONS()      \
    insert_chunk_0();    \
    insert_chunk_1();    \
    insert_chunk_2();    \
    insert_chunk_3();    \
    insert_chunk_4();    \
    insert_chunk_5();    \
    insert_chunk_6();    \
    insert_chunk_7();    \
    insert_chunk_8();    \
    insert_chunk_9();    \
    insert_chunk_10();   \
    insert_chunk_11();    \
    insert_chunk_12();    \
    insert_chunk_13();    \
    insert_chunk_14();    \
    insert_chunk_15();    \
    insert_chunk_16();    \
    insert_chunk_17();    \
    insert_chunk_18();    \
    insert_chunk_19();    \
    insert_chunk_20();    \
    insert_chunk_21();   \
    insert_chunk_22();    \
    insert_chunk_23();    \
    insert_chunk_24();    \
    insert_chunk_25();    \
    insert_chunk_26();    \
    insert_chunk_27();    \
    insert_chunk_28();    \
    insert_chunk_29();    \
    insert_chunk_30();    \
    insert_chunk_31();    \
    insert_chunk_32();   \
    insert_chunk_33();    \
    insert_chunk_34();    \
    insert_chunk_35();    \
    insert_chunk_36();    \
    insert_chunk_37();    \
    insert_chunk_38();    \
    insert_chunk_39();    \
    insert_chunk_40();    \
    insert_chunk_41();    \
    insert_chunk_42();    \
    insert_chunk_43();   \
    insert_chunk_44();    \
    insert_chunk_45();    \
    insert_chunk_46();    \
    insert_chunk_47();   \
    insert_chunk_48();    \
    insert_chunk_49();    \

#if defined(GENERATE_LOAD_FUNCTIONS)
    GENERATE_LOAD_FUNCTIONS()
    #define _GENERATED_ 1
#endif

static int GENERATE_LOAD_FUNCTIONS_STATIC_FUNCTION(){
    #if defined(_GENERATED_) && _GENERATED_ == 1
        CALL_RELATION_FUNCTIONS()
    #endif

    return 0;
}

static void Load_PRM(){
    bpf_printk("Preparing PRM...");
    __u32 _index_=0;
    struct prm_state currect_state={STARTUP};
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);

    GENERATE_LOAD_FUNCTIONS_STATIC_FUNCTION();

    // Change State
    currect_state.prm_state=LOADED;
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
}

#endif