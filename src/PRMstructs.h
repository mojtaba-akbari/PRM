#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba :) , The Structures // ***
// Use Stack Programming To Design The Whole PRM //
// Stack Is Faster Than BFP Helper Calls For Allocating Data //
// Here The Structure Is Between 512 Byte Allocation , So I Would Prefer Develop It As Stack //

static volatile __u8 map_loaded = 0;

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
    int redirectIndex;
    bool protectZone;
};

const struct process_relation relation_data[MAX_NUMBER_OF_RELATION] SEC(".rodata") = {
    {RELATION_0},
    {RELATION_1},
    {RELATION_2},
    {RELATION_3},
    {RELATION_4},
    {RELATION_5},
    {RELATION_6},
    {RELATION_7},
    {RELATION_8},
    {RELATION_9},
    {RELATION_10},
    {RELATION_11},
    {RELATION_12},
    {RELATION_13},
    {RELATION_14},
    {RELATION_15},
    {RELATION_16},
    {RELATION_17},
    {RELATION_18},
    {RELATION_19},
    {RELATION_20},
    {RELATION_21},
    {RELATION_22},
    {RELATION_23},
    {RELATION_24},
    {RELATION_25},
    {RELATION_26},
    {RELATION_27},
    {RELATION_28},
    {RELATION_29},
    {RELATION_30},
    {RELATION_31},
    {RELATION_32},
    {RELATION_33},
    {RELATION_34},
    {RELATION_35},
    {RELATION_36},
    {RELATION_37},
    {RELATION_38},
    {RELATION_39},
    {RELATION_40},
    {RELATION_41},
    {RELATION_42},
    {RELATION_43},
    {RELATION_44},
    {RELATION_45},
    {RELATION_46},
    {RELATION_47},
    {RELATION_48},
    {RELATION_49},
    {RELATION_50},
    {RELATION_51},
    {RELATION_52},
    {RELATION_53},
    {RELATION_54},
    {RELATION_55},
    {RELATION_56},
    {RELATION_57},
    {RELATION_58},
    {RELATION_59},
    {RELATION_60},
    {RELATION_61},
    {RELATION_62},
    {RELATION_63},
    {RELATION_64},
    {RELATION_65},
    {RELATION_66},
    {RELATION_67},
    {RELATION_68},
    {RELATION_69},
    {RELATION_70},
    {RELATION_71},
    {RELATION_72},
    {RELATION_73},
    {RELATION_74},
    {RELATION_75},
    {RELATION_76},
    {RELATION_77},
    {RELATION_78},
    {RELATION_79}
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

#define DEFINE_LOAD_RELATION_FUNCTION(i)  \
    static int insert_chunk_##i(void) {   \
        __u32 key = i;                      \
        struct process_relation relation = {RELATION_##i}; \
        bpf_printk("Inserted into map: %s -> %s -> %s -> %d -> %d -> %d\n", relation.process, relation.parent, relation.grandparent, relation.action, relation.redirectIndex, relation.protectZone); \
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
    DEFINE_LOAD_RELATION_FUNCTION(50);   \
    DEFINE_LOAD_RELATION_FUNCTION(51);   \
    DEFINE_LOAD_RELATION_FUNCTION(52);   \
    DEFINE_LOAD_RELATION_FUNCTION(53);   \
    DEFINE_LOAD_RELATION_FUNCTION(54);   \
    DEFINE_LOAD_RELATION_FUNCTION(55);   \
    DEFINE_LOAD_RELATION_FUNCTION(56);   \
    DEFINE_LOAD_RELATION_FUNCTION(57);   \
    DEFINE_LOAD_RELATION_FUNCTION(58);   \
    DEFINE_LOAD_RELATION_FUNCTION(59);   \
    DEFINE_LOAD_RELATION_FUNCTION(60);   \
    DEFINE_LOAD_RELATION_FUNCTION(61);   \
    DEFINE_LOAD_RELATION_FUNCTION(62);   \
    DEFINE_LOAD_RELATION_FUNCTION(63);   \
    DEFINE_LOAD_RELATION_FUNCTION(64);   \
    DEFINE_LOAD_RELATION_FUNCTION(65);   \
    DEFINE_LOAD_RELATION_FUNCTION(66);   \
    DEFINE_LOAD_RELATION_FUNCTION(67);   \
    DEFINE_LOAD_RELATION_FUNCTION(68);   \
    DEFINE_LOAD_RELATION_FUNCTION(69);   \
    DEFINE_LOAD_RELATION_FUNCTION(70);   \
    DEFINE_LOAD_RELATION_FUNCTION(71);   \
    DEFINE_LOAD_RELATION_FUNCTION(72);   \
    DEFINE_LOAD_RELATION_FUNCTION(73);   \
    DEFINE_LOAD_RELATION_FUNCTION(74);   \
    DEFINE_LOAD_RELATION_FUNCTION(75);   \
    DEFINE_LOAD_RELATION_FUNCTION(76);   \
    DEFINE_LOAD_RELATION_FUNCTION(77);   \
    DEFINE_LOAD_RELATION_FUNCTION(78);   \
    DEFINE_LOAD_RELATION_FUNCTION(79);   \

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
    insert_chunk_50();    \
    insert_chunk_51();   \
    insert_chunk_52();    \
    insert_chunk_53();    \
    insert_chunk_54();    \
    insert_chunk_55();    \
    insert_chunk_56();    \
    insert_chunk_57();    \
    insert_chunk_58();    \
    insert_chunk_59();    \
    insert_chunk_60();    \
    insert_chunk_61();    \
    insert_chunk_62();   \
    insert_chunk_63();    \
    insert_chunk_64();    \
    insert_chunk_65();    \
    insert_chunk_66();    \
    insert_chunk_67();    \
    insert_chunk_68();    \
    insert_chunk_69();    \
    insert_chunk_70();    \
    insert_chunk_71();    \
    insert_chunk_72();    \
    insert_chunk_73();   \
    insert_chunk_74();    \
    insert_chunk_75();    \
    insert_chunk_76();    \
    insert_chunk_77();   \
    insert_chunk_78();    \
    insert_chunk_79();    \

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

static void init_relation_map() {
    __u32 _safeCounter_=0;
    #pragma unroll
    for (int i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;
        bpf_map_update_elem(&prm_map, &_safeCounter_, &relation_data[_safeCounter_], BPF_ANY);
    }
}

static void Load_PRM(){
    bpf_printk("Preparing PRM...");
    __u32 _index_=0;
    struct prm_state currect_state={STARTUP};
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);

    //GENERATE_LOAD_FUNCTIONS_STATIC_FUNCTION();
    init_relation_map();

    // Change State
    currect_state.prm_state=LOADED;
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
}

#endif