#include <target/util.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* vformat(const char* fmt, va_list ap) {
  char buf[256];
  vsnprintf(buf, 255, fmt, ap);
  buf[255] = 0;
  return strdup(buf);
}

char* format(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char* r = vformat(fmt, ap);
  va_end(ap);
  return r;
}

void error(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char* r = vformat(fmt, ap);
  va_end(ap);
  fprintf(stderr, "%s\n", r);
  exit(1);
}

static int g_indent;

void inc_indent() {
  g_indent++;
}

void dec_indent() {
  g_indent--;
}

void emit_line(const char* fmt, ...) {
  if (fmt[0]) {
    for (int i = 0; i < g_indent; i++)
      putchar(' ');
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
  }
  putchar('\n');
}

static const char* DEFAULT_REG_NAMES[7] = {
  "a", "b", "c", "d", "bp", "sp", "pc"
};

const char** reg_names = DEFAULT_REG_NAMES;

const char* value_str(Value* v) {
  if (v->type == REG) {
    return reg_names[v->reg];
  } else if (v->type == IMM) {
    return format("%d", v->imm);
  } else {
    error("invalid value");
  }
}

const char* src_str(Inst* inst) {
  return value_str(&inst->src);
}

Op normalize_cond(Op op, bool flip) {
  if (op >= 16)
    op -= 8;
  if (flip) {
    static const Op TBL[] = {
      JNE, JEQ, JGE, JLE, JGT, JLT, JMP
    };
    op = TBL[op-JEQ];
  }
  return (Op)op;
}

const char* cmp_str(Inst* inst, const char* true_str) {
  int op = normalize_cond(inst->op, 0);
  const char* op_str;
  switch (op) {
    case JEQ:
      op_str = "=="; break;
    case JNE:
      op_str = "!="; break;
    case JLT:
      op_str = "<"; break;
    case JGT:
      op_str = ">"; break;
    case JLE:
      op_str = "<="; break;
    case JGE:
      op_str = ">="; break;
    case JMP:
      return true_str;
    default:
      error("oops");
  }
  return format("%s %s %s", reg_names[inst->dst.reg], op_str, src_str(inst));
}

static int g_emit_cnt;
static bool g_emit_started;

int emit_cnt() {
  return g_emit_cnt;
}

void emit_reset() {
  g_emit_cnt = 0;
  g_emit_started = false;
}

void emit_start() {
  g_emit_started = true;
}

void emit_1(int a) {
  g_emit_cnt++;
  if (g_emit_started)
    putchar(a);
}

void emit_2(int a, int b) {
  emit_1(a);
  emit_1(b);
}

void emit_3(int a, int b, int c) {
  emit_1(a);
  emit_1(b);
  emit_1(c);
}

void emit_4(int a, int b, int c, int d) {
  emit_1(a);
  emit_1(b);
  emit_1(c);
  emit_1(d);
}

void emit_5(int a, int b, int c, int d, int e) {
  emit_1(a);
  emit_1(b);
  emit_1(c);
  emit_1(d);
  emit_1(e);
}

void emit_6(int a, int b, int c, int d, int e, int f) {
  emit_1(a);
  emit_1(b);
  emit_1(c);
  emit_1(d);
  emit_1(e);
  emit_1(f);
}

void emit_le(uint32_t a) {
  emit_1(a % 256);
  a /= 256;
  emit_1(a % 256);
  a /= 256;
  emit_1(a % 256);
  a /= 256;
  emit_1(a);
}

void emit_diff(uint32_t a, uint32_t b) {
  uint32_t v = a - b;
  emit_1(v % 256);
  v /= 256;
  emit_1(v % 256);
  v /= 256;
  emit_1(v % 256);
  emit_1(a >= b ? 0 : 0xff);
}

int CHUNKED_FUNC_SIZE = 512;

int emit_chunked_main_loop(Inst* inst,
                           void (*emit_func_prologue)(int func_id),
                           void (*emit_func_epilogue)(void),
                           void (*emit_pc_change)(int pc),
                           void (*emit_inst)(Inst* inst)) {
  int prev_pc = -1;
  int prev_func_id = -1;
  for (; inst; inst = inst->next) {
    int func_id = inst->pc / CHUNKED_FUNC_SIZE;
    if (prev_pc != inst->pc) {
      if (prev_func_id != func_id) {
        if (prev_func_id != -1) {
          emit_func_epilogue();
        }
        emit_func_prologue(func_id);
      }

      emit_pc_change(inst->pc);
    }
    prev_pc = inst->pc;
    prev_func_id = func_id;

    emit_inst(inst);
  }
  emit_func_epilogue();
  return prev_func_id + 1;
}

#define PACK2(x) ((x) % 256), ((x) / 256)
#define PACK4(x) ((x) % 256), ((x) / 256 % 256), ((x) / 65536), 0

void emit_elf_header(uint16_t machine, uint32_t filesz) {
  const char ehdr[52] = {
    // e_ident
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    PACK2(2),  // e_type
    PACK2(machine),  // e_machine
    PACK4(1),  // e_version
    PACK4(ELF_TEXT_START + ELF_HEADER_SIZE),  // e_entry
    PACK4(52),  // e_phoff
    PACK4(0),  // e_shoff
    PACK4(0),  // e_flags
    PACK2(52),  // e_ehsize
    PACK2(32),  // e_phentsize
    PACK2(1),  // e_phnum
    PACK2(40),  // e_shentsize
    PACK2(0),  // e_shnum
    PACK2(0),  // e_shstrndx
  };
  const char phdr[32] = {
    PACK4(1),  // p_type
    PACK4(0),  // p_offset
    PACK4(ELF_TEXT_START),  // p_vaddr
    PACK4(ELF_TEXT_START),  // p_paddr
    PACK4(filesz + ELF_HEADER_SIZE),  // p_filesz
    PACK4(filesz + ELF_HEADER_SIZE),  // p_memsz
    PACK4(5),  // p_flags
    PACK4(0x1000),  // p_align
  };
  fwrite(ehdr, 52, 1, stdout);
  fwrite(phdr, 32, 1, stdout);
}

int emit_pe_header(uint16_t machine, uint32_t imagesz, uint16_t nsec) {
  // DOS Header
  char *doshdr = calloc(1, sizeof(char) * 0x40);
  doshdr[0x00] = 0x4d; doshdr[0x01] = 0x5a; // "MZ"
  doshdr[0x3c] = 0x40; // e_lfanew = 0x0040

  // PE Header
  char *nthdr = calloc(1, sizeof(char) * 0x108);
  nthdr[0x00] = 0x50; nthdr[0x01] = 0x45; // "PE"

  // File Header
  nthdr[0x04] = machine % 256;
  nthdr[0x05] = machine / 256; // Machine
  nthdr[0x06] = nsec % 256;
  nthdr[0x07] = nsec / 256; // NumberOfSection
  nthdr[0x14] = 0xf0; nthdr[0x15] = 0x00; // SizeOfOptionalHeader
  nthdr[0x16] = 0x02; nthdr[0x17] = 0x21; // Characteristics

  // Optional Header
  nthdr[0x18] = 0x0b; nthdr[0x19] = 0x02; // PE+
  nthdr[0x28] = PE_TEXT_START % 256;
  nthdr[0x29] = PE_TEXT_START / 256 % 256;
  nthdr[0x2a] = PE_TEXT_START / 65536;
  nthdr[0x2b] = 0x00; // AddressOfEntryPoint
  nthdr[0x30] = 0x00; nthdr[0x31] = 0x00;
  nthdr[0x32] = 0x40; nthdr[0x33] = 0x00;
  nthdr[0x34] = 0x00; nthdr[0x35] = 0x00;
  nthdr[0x36] = 0x00; nthdr[0x37] = 0x00; // ImageBase
  nthdr[0x38] = 0x00; nthdr[0x39] = 0x10;
  nthdr[0x3a] = 0x00; nthdr[0x3b] = 0x00; // SectionAlignment
  nthdr[0x3c] = 0x00; nthdr[0x3d] = 0x02;
  nthdr[0x3e] = 0x00; nthdr[0x3f] = 0x00; // FileAlignment
  nthdr[0x50] = imagesz % 256;
  nthdr[0x51] = imagesz / 256 % 256;
  nthdr[0x52] = imagesz / 65536;
  nthdr[0x53] = 0x00; // SizeOfImage
  nthdr[0x54] = PE_HEADER_SIZE % 256;
  nthdr[0x55] = PE_HEADER_SIZE / 256 % 256;
  nthdr[0x56] = PE_HEADER_SIZE / 65536;
  nthdr[0x57] = 0x00; // SizeOfHeaders

  fwrite(doshdr, 0x40, 1, stdout);
  fwrite(nthdr, 0x108, 1, stdout);

  return 0x40 + 0x108;
}

int emit_pe_sechdr(Sec* sec) {
  char *sechdr = calloc(1, sizeof(char) * 0x28);
  strcpy(sechdr, sec->name);
  sechdr[0x08] = sec->vsize % 256;
  sechdr[0x09] = sec->vsize / 256 % 256;
  sechdr[0x0a] = sec->vsize / 65536 % 256;
  sechdr[0x0b] = sec->vsize / 16777216 % 256; // VirtualSize
  sechdr[0x0c] = sec->vaddr % 256;
  sechdr[0x0d] = sec->vaddr / 256 % 256;
  sechdr[0x0e] = sec->vaddr / 65536 % 256;
  sechdr[0x0f] = sec->vaddr / 16777216 % 256; // VirtualAddress
  sechdr[0x10] = sec->rsize % 256;
  sechdr[0x11] = sec->rsize / 256 % 256;
  sechdr[0x12] = sec->rsize / 65536 % 256;
  sechdr[0x13] = sec->rsize / 16777216 % 256; // SizeOfRawData
  sechdr[0x14] = sec->raddr % 256;
  sechdr[0x15] = sec->raddr / 256 % 256;;
  sechdr[0x16] = sec->raddr / 65536 % 256;
  sechdr[0x17] = sec->raddr / 16777216 % 256; // PointerToRawData
  sechdr[0x24] = sec->chars % 256;
  sechdr[0x25] = sec->chars / 256 % 256;;
  sechdr[0x26] = sec->chars / 65536 % 256;
  sechdr[0x27] = sec->chars / 16777216 % 256; // Characteristics

  fwrite(sechdr, 0x28, 1, stdout);

  return 0x28;
}
