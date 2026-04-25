#pragma once
/*
 * obfstr.h — compile-time string obfuscation.
 *
 * Source files mark sensitive literals with OBFSTR("literal").
 * tools/gen_obf.py (run by Makefile before compilation) scans all .c files,
 * replaces OBFSTR("...") with _obf_get(N), and emits src/obf_table.c with
 * XOR-encrypted byte arrays keyed by a per-build random byte.
 *
 * At runtime, ObfInit() decodes the table once; _obf_get(N) returns the
 * decoded string pointer.  All encoded byte arrays live in .rodata with no
 * readable plaintext.
 */
#include "ntdefs.h"

typedef struct {
    const unsigned char *data;   /* XOR-encoded bytes (including null terminator) */
    int                  len;    /* total encoded bytes (strlen+1) */
} ObfEntry;

/* Implemented in generated src/obf_table.c */
void        ObfInit(void);
const char *_obf_get(int idx);
void        _obf_fill_w(int idx, WCHAR *out, int cap);

/*
 * OBFSTR("literal") — replaced by gen_obf.py with _obf_get(N).
 * WOBFSTR("literal", buf, cap) — replaced by gen_obf.py with _obf_fill_w(N, buf, cap).
 * Fallback definitions below are used only in IDEs / non-generated builds.
 */
#ifndef OBFSTR
#define OBFSTR(s) (s)
#endif

#ifndef WOBFSTR
static __inline void _wobfstr_fb(const char *s, WCHAR *buf, int cap) {
    int i = 0;
    while (s[i] && i < cap - 1) { buf[i] = (WCHAR)(unsigned char)s[i]; i++; }
    buf[i] = 0;
}
#define WOBFSTR(s, buf, cap) _wobfstr_fb((s), (buf), (cap))
#endif
