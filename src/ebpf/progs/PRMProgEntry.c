#include "../include/PRMProgEntry.h"
#include "PRMProgHelper.c"

/*
 * PRM PROG Module System
 * ──────────────────────
 * Each module is a self-contained file in progs/modules/.
 * To add a new PROG:
 *   1. Create progs/modules/prog_yourName.c (copy prog_test.c as template)
 *   2. Include it below
 *   3. Assign a slot in conf/PRMProg.h: #define PROG_N yourName
 *   4. Add a RETURN rule in conf/PRM.h pointing to slot N
 *   5. Rebuild (make ebpf)
 *
 * To disable a PROG:
 *   - Comment out its #define in conf/PRMProg.h (set to EMPTY_PROG)
 *   - No other changes needed
 *
 * Module contract:
 *   - Define: static __u32 name_prog(struct hooks_context_t *hook_ctx)
 *   - Define: static __u32 name_fingerprint(struct hooks_context_t *hook_ctx)
 *   - Call: __PROG_REGISTER__(name, HOOK_TYPE, name_prog, name_fingerprint)
 *   - Use FLAG_FOR_HASH() in both _prog (on accept path) and _fingerprint
 *   - Return: RET_ACCEPT, RET_REJECT, or RET_ACCEPT_FORCEFULLY
 */

// ─── Module includes ───────────────────────────────────────────────────────
#include "modules/prog_test.c"
#include "modules/prog_signalKillTracer.c"
#include "modules/prog_denyWriteOutside.c"
#include "modules/prog_denySocketEndHost.c"
#include "modules/prog_bprmSecurityCheck.c"
#include "modules/prog_memoryProtect.c"
#include "modules/prog_denyIncomeSocket.c"
#include "modules/prog_denyFileOpen.c"
#include "modules/prog_denyLoadModule.c"
#include "modules/prog_credPrepareCheck.c"
#include "modules/prog_capableCheck.c"
#include "modules/prog_taskFixSetUIDCheck.c"

// ─── Install all registered PROGs into the dispatch table ──────────────────
__INSTALL_PROGS__
