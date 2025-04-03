#include "../include/conf/PRM.h"
#include "../include/PRMStructs.h"

static void init_relation_map() {
    bpf_printk("Preparing PRM Relation Map...");
    __u32 _safeCounter_=0;

    for (int i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;
        struct process_relation processTmpx = relation_data[_safeCounter_];
        if(processTmpx.process[0]=='\0' || processTmpx.parent[0]=='\0' || processTmpx.grandparent[0]=='\0'){
            ASSERT_RUNTIME(0 , bpf_printk("Role#%d Have been found fully EMPTY",_safeCounter_));
            memset(processTmpx.process,0,sizeof(MAX_RELATION_PROCESSNAME));
            memset(processTmpx.parent,0,sizeof(MAX_RELATION_PROCESSNAME));
            memset(processTmpx.grandparent,0,sizeof(MAX_RELATION_PROCESSNAME));
            processTmpx.action = NONE_ACTION;
            processTmpx.hookType = NONE_CELL;
            processTmpx.redirectIndex = 0;
            processTmpx.protectZone=0;
        }
        else{
            ASSERT_RUNTIME(strlen(processTmpx.process,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong process name",_safeCounter_));
            ASSERT_RUNTIME(strlen(processTmpx.parent,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong parent name",_safeCounter_));
            ASSERT_RUNTIME(strlen(processTmpx.grandparent,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong grand name",_safeCounter_));

            ASSERT_RUNTIME((processTmpx.action>=0) && (processTmpx.action<=5) , bpf_printk("Role#%d wrong action",_safeCounter_));
            ASSERT_RUNTIME((processTmpx.hookType>=0) && (processTmpx.hookType<=27) , bpf_printk("Role#%d wrong hook type",_safeCounter_));
            ASSERT_RUNTIME((processTmpx.redirectIndex>=0) && (processTmpx.redirectIndex<=MAX_NUMBER_OF_RELATION-1) , bpf_printk("Role#%d wrong redirect index",_safeCounter_));
            ASSERT_RUNTIME((processTmpx.protectZone==0 || processTmpx.protectZone==1) , bpf_printk("Role#%d wrong protect zone flag index",_safeCounter_));
        }
        
        bpf_printk("Role Number #%d {(process=%s),(parent=%s),(grand=%s),(hookType=%d),(action=%d),(redirectIndex=%d),(protectZone=%d)} Loaded Up",_safeCounter_,processTmpx.process,
                        processTmpx.parent,processTmpx.grandparent,processTmpx.hookType,processTmpx.action,processTmpx.redirectIndex,processTmpx.protectZone);

        bpf_map_update_elem(&prm_map, &_safeCounter_, &processTmpx, BPF_ANY);
    }
}

static void Load_PRM(){
    bpf_printk("******Preparing PRM******");
    __u32 _index_=0;
    struct prm_state currect_state={STARTUP};
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);

    init_relation_map();

    currect_state.prm_state=LOADED;
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
}