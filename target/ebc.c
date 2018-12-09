#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ir/ir.h>
#include <target/util.h>

#define MAGIC_MZ                            0x5a4d

#define IMAGE_FILE_RELOCS_STRIPPED          0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002
#define IMAGE_FILE_32BIT_MACHINE            0x0100
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400
#define IMAGE_FILE_SYSTEM                   0x1000
#define IMAGE_FILE_DLL                      0x2000

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define MAGIC_PE                            0x00004550

#define IMAGE_SIZEOF_SHORT_NAME             8

#define IMAGE_SCN_CNT_CODE                  0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000

#define SIZE_OF_OPTIONAL_HEADER             240
#define ADDRESS_OF_ENTRYPOINT               0x1000
#define IMAGE_BASE                          0x400000
#define SECTION_ALIGNMENT                   0x1000
#define FILE_ALIGNMENT                      0x0200
#define SIZE_OF_HEADERS                     0x0200

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint64_t ULONGLONG;

typedef struct _IMAGE_DOS_HEADER {
  WORD    e_magic;
  WORD    e_cblp;
  WORD    e_cp;
  WORD    e_crlc;
  WORD    e_cparhdr;
  WORD    e_minalloc;
  WORD    e_maxalloc;
  WORD    e_ss;
  WORD    e_sp;
  WORD    e_csum;
  WORD    e_ip;
  WORD    e_cs;
  WORD    e_lfarlc;
  WORD    e_ovno;
  WORD    e_res[4];
  WORD    e_oemid;
  WORD    e_oeminfo;
  WORD    e_res2[10];
  LONG    e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  WORD    Machine;
  WORD    NumberOfSections;
  DWORD   TimeDateStamp;
  DWORD   PointerToSymbolTable;
  DWORD   NumberOfSymbols;
  WORD    SizeOfOptionalHeader;
  WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD   VirtualAddress;
  DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD      Magic;
  BYTE      MajorLinkerVersion;
  BYTE      MinorLinkerVersion;
  DWORD     SizeOfCode;
  DWORD     SizeOfInitializedData;
  DWORD     SizeOfUninitializedData;
  DWORD     AddressOfEntryPoint;
  DWORD     BaseOfCode;

  ULONGLONG ImageBase;
  DWORD     SectionAlignment;
  DWORD     FileAlignment;
  WORD      MajorOperatingSystemVersion;
  WORD      MinorOperatingSystemVersion;
  WORD      MajorImageVersion;
  WORD      MinorImageVersion;
  WORD      MajorSubsystemVersion;
  WORD      MinorSubsystemVersion;
  DWORD     Win32VersionValue;
  DWORD     SizeOfImage;
  DWORD     SizeOfHeaders;
  DWORD     CheckSum;
  WORD      Subsystem;
  WORD      DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD     LoaderFlags;
  DWORD     NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY
            DataDirecroty[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _PE32_IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER   OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE        Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD   PhysicalAddress;
    DWORD   VirtualSize;
  } Misc;
  DWORD       VirtualAddress;
  DWORD       SizeOfRawData;
  DWORD       PointerToRawData;
  DWORD       PointerToRelocations;
  DWORD       PointerToLinenumbers;
  WORD        NumberOfRelocations;
  WORD        NumberOfLinenumbers;
  DWORD       Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

int size_of_image;
int text_vaddr, text_vsize, text_raddr, text_rsize;
int rodata_vaddr, rodata_vsize, rodata_raddr, rodata_rsize;

static int emit_aligned(int addr, int align) {
  return ((addr / align) + 1) * align;
}

static void emit_pe_header() {
  IMAGE_DOS_HEADER* doshdr = calloc(1, sizeof(IMAGE_DOS_HEADER));
  doshdr->e_magic = MAGIC_MZ;
  doshdr->e_lfanew = 0x40;

  IMAGE_NT_HEADERS* nthdr = calloc(1, sizeof(IMAGE_NT_HEADERS));
  nthdr->Signature = MAGIC_PE;

  IMAGE_FILE_HEADER* fhdr = &nthdr->FileHeader;
  fhdr->Machine = 0x0ebc;
  fhdr->NumberOfSections = 2; // .text + .rodata
  fhdr->SizeOfOptionalHeader = SIZE_OF_OPTIONAL_HEADER;
  fhdr->Characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
  fhdr->Characteristics |= IMAGE_FILE_32BIT_MACHINE;
  fhdr->Characteristics |= IMAGE_FILE_DLL;

  IMAGE_OPTIONAL_HEADER* opthdr = &nthdr->OptionalHeader;
  opthdr->Magic = 0x20b; // PE+
  opthdr->AddressOfEntryPoint = ADDRESS_OF_ENTRYPOINT;
  opthdr->ImageBase = IMAGE_BASE;
  opthdr->SectionAlignment = SECTION_ALIGNMENT;
  opthdr->FileAlignment = FILE_ALIGNMENT;
  opthdr->SizeOfImage = size_of_image;
  opthdr->SizeOfHeaders = SIZE_OF_HEADERS;

  IMAGE_SECTION_HEADER* sechdr;
  // .text
  IMAGE_SECTION_HEADER* text_sechdr;
  text_sechdr = calloc(1, sizeof(IMAGE_SECTION_HEADER));
  sechdr = text_sechdr;
  strcpy((char *)sechdr->Name, ".text");
  sechdr->PointerToRawData = text_raddr;
  sechdr->SizeOfRawData = text_rsize;
  sechdr->VirtualAddress = text_vaddr;
  sechdr->Misc.VirtualSize = text_vsize;
  sechdr->Characteristics |= IMAGE_SCN_CNT_CODE;
  sechdr->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
  sechdr->Characteristics |= IMAGE_SCN_MEM_READ;
  // .rodata
  IMAGE_SECTION_HEADER* rodata_sechdr;
  rodata_sechdr = calloc(1, sizeof(IMAGE_SECTION_HEADER));
  sechdr = rodata_sechdr;
  strcpy((char *)sechdr->Name, ".rodata");
  sechdr->PointerToRawData = rodata_raddr;
  sechdr->SizeOfRawData = rodata_rsize;
  sechdr->VirtualAddress = rodata_vaddr;
  sechdr->Misc.VirtualSize = rodata_vsize;
  sechdr->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
  sechdr->Characteristics |= IMAGE_SCN_MEM_READ;

  fwrite(doshdr, sizeof(IMAGE_DOS_HEADER), 1, stdout);
  fwrite(nthdr, sizeof(IMAGE_NT_HEADERS), 1, stdout);
  fwrite(text_sechdr, sizeof(IMAGE_SECTION_HEADER), 1, stdout);
  fwrite(rodata_sechdr, sizeof(IMAGE_SECTION_HEADER), 1, stdout);

  // padding
  int hdr_size = 0;
  hdr_size += sizeof(IMAGE_DOS_HEADER);
  hdr_size += sizeof(IMAGE_NT_HEADERS);
  hdr_size += sizeof(IMAGE_SECTION_HEADER);
  hdr_size += sizeof(IMAGE_SECTION_HEADER);
  char *padding = calloc(SIZE_OF_HEADERS - hdr_size, sizeof(char));
  fwrite(padding, sizeof(char) * (SIZE_OF_HEADERS - hdr_size), 1, stdout);
}

static int EBCREG[] = {
  1, // A - R1
  2, // B - R2
  3, // C - R3
  4, // D - R4
  5, // BP - R5
  6, // SP - R6
  7, // R7 - free register
  0, // R0 - stack pointer
};

#define R0 ((Reg)7)
#define R1 A
#define R2 B
#define R3 C
#define R4 D
#define R5 BP
#define R6 SP
#define R7 ((Reg)6)

static void emit_le32(uint32_t a) {
  emit_le(a);
}

static void emit_ebc_mov_reg(Reg dst, Reg src) {
  // MOVqq R_1, R_2
  emit_2(0x28, (EBCREG[src] << 4) + EBCREG[dst]);
}

static void emit_ebc_mov_imm(Reg dst, int src) {
  // MOVIdd R_1, IMM32
  emit_2(0xb7, 0x20 + EBCREG[dst]);
  emit_le32(src);
}

static void emit_ebc_mov(Reg dst, Value* src) {
  if (src->type == REG) {
    emit_ebc_mov_reg(dst, src->reg);
  } else {
    emit_ebc_mov_imm(dst, src->imm);
  }
}

static void emit_ebc_cmp(Inst* inst, int cmp) {
  emit_ebc_mov(R7, &inst->src);
  emit_2(cmp, (EBCREG[R7] << 4) + EBCREG[inst->dst.reg]);
}

static void emit_ebc_jcc(Inst* inst, int cmp, int op, int* pc2addr) {
  if (op) {
    emit_ebc_cmp(inst, cmp);
    if (inst->op == JLT || inst->op == JGT)
      emit_2(0x6c, EBCREG[inst->dst.reg]); // POP inst->dst.reg
  }

  if (inst->jmp.type == REG) {
    emit_2(0x6b, EBCREG[inst->jmp.reg]); // PUSH inst->jmp.reg
    emit_4(0x77, 0x10 + EBCREG[R7], 0x04, 0x00); // MOVIww R7, 4
    emit_2(0x0f, (EBCREG[R7] << 4) + EBCREG[inst->jmp.reg]); // MULU inst->jmp.reg, R7
    // MOVREL R7, rodata
    emit_2(0xb9, EBCREG[R7]);
    emit_le32(rodata_vaddr - (text_vaddr + emit_cnt() + 4));
    emit_2(0x0c, (EBCREG[inst->jmp.reg] << 4) + EBCREG[R7]); // ADD R7, inst->jmp.reg
    // MOVww R7, @R7
    emit_2(0x1e, 0x80 + (EBCREG[R7] << 4) + EBCREG[R7]);
    // MOVdw inst->jmp.reg, @R0(0, +16)
    emit_4(0x5f, 0x80 + (EBCREG[R0] << 4) +EBCREG[inst->jmp.reg], 0x10, 0x00);
    emit_2(0x0c, (EBCREG[inst->jmp.reg] << 4) + EBCREG[R7]); // ADD R7, inst->jmp.reg
    emit_2(0x6c, EBCREG[inst->jmp.reg]); // POP inst->jmp.reg
    emit_2(0x01, op + EBCREG[R7]); // JMP32 R7
  } else {
    // MOVdw R7, @R0(0, +8)
    emit_4(0x5f, 0x80 + (EBCREG[R0] << 4) + EBCREG[R7], 0x08, 0x00);
    emit_2(0x6b, EBCREG[R1]); // PUSH R1
    emit_ebc_mov_imm(R1, pc2addr[inst->jmp.imm]);
    emit_2(0x0c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD R7, R1
    emit_2(0x6c, EBCREG[R1]); // POP R1
    emit_2(0x01, op + EBCREG[R7]); // JMP32 R7
  }
}

static void emit_ebc_arith_reg(Reg dst, int op, Reg src) {
  emit_ebc_mov_reg(R7, src);
  emit_2(op, (EBCREG[R7] << 4) + EBCREG[dst]);
  emit_ebc_mov_imm(R7, 0xffffff);
  emit_2(0x14, (EBCREG[R7] << 4) + EBCREG[dst]); // AND
}

static void emit_ebc_arith_imm(Reg dst, int op, int imm) {
  emit_ebc_mov_imm(R7, imm);
  emit_2(op, (EBCREG[R7] << 4) + EBCREG[dst]);
  emit_ebc_mov_imm(R7, 0xffffff);
  emit_2(0x14, (EBCREG[R7] << 4) + EBCREG[dst]); // AND
}

static void emit_ebc_arith(Inst* inst, int op) {
  if (inst->src.type == REG) {
    emit_ebc_arith_reg(inst->dst.reg, op, inst->src.reg);
  } else {
    emit_ebc_arith_imm(inst->dst.reg, op, inst->src.imm);
  }
}

static void emit_ebc_setcc(Inst* inst, int cmp, int op) {
  emit_ebc_cmp(inst, cmp);
  emit_2(op, 0x04); // JMP8cc .L1
  emit_ebc_mov_imm(inst->dst.reg, 0x01);
  emit_2(0x02, 0x04); // JMP8 .L2
  emit_ebc_mov_imm(inst->dst.reg, 0x00);
  emit_2(0x02, 0x00); // JMP8 .L2
}

static void init_state_ebc(Data* data) {
  // XXX: PUSH text_vaddr
  emit_2(0x2a, (0x01 << 4) + EBCREG[R7]); // STORE R7, IP
  emit_2(0x6b, EBCREG[R7]); // PUSH R7

  emit_ebc_mov_imm(R7, 0x00);
  emit_2(0x6b, EBCREG[R7]); // PUSH Buffer
  emit_4(0x60, 0x07, 0x08, 0x00); // MOVqw R7, R0 (0, +8);
  emit_4(0x72, 0xf7, 0x41, 0x10); // MOVnw R7, @R7 (.SystemTable)
  emit_4(0x72, 0xf7, 0x89, 0x21); // MOVnw R7, @R7 (.BootServices)
  emit_4(0x77, 0x31, 0x02, 0x00); // MOVI R1, 0x0002
  emit_6(0xb7, 0x32, 0x08, 0x00, 0x00, 0x04); // MOVI R2, 0x04000000
  emit_ebc_mov_reg(R3, R0); // MOV R3, R0
  emit_2(0x35, 0x03); // PUSHn32 R3
  emit_2(0x35, 0x02); // PUSHn32 R2
  emit_2(0x35, 0x01); // PUSHn32 R1
  emit_6(0x83, 0x2f, 0x85, 0x01, 0x00, 0x10); // CALL32EXa @R7 (.AllocatePool)
  emit_4(0x60, 0x00, 0x03, 0x10); // MOVqw R0, R0 (+3, 0)

  for (int mp = 0; data; data = data->next, mp++) {
    if (data->v) {
      emit_ebc_mov_reg(R7, R0);
      emit_ebc_mov_imm(R1, 0x0004);
      emit_ebc_mov_imm(R2, mp);
      emit_2(0x4e, 0x21); // MUL R1, R2
      emit_2(0x4c, 0x17); // ADD R7, R1
      // MOVI @R7, data->v
      emit_2(0xb7, 0x3f);
      emit_le32(data->v);
    }
  }

  emit_ebc_mov_imm(A, 0);
  emit_ebc_mov_imm(B, 0);
  emit_ebc_mov_imm(C, 0);
  emit_ebc_mov_imm(D, 0);
  emit_ebc_mov_imm(BP, 0);
  emit_ebc_mov_imm(SP, 0);
}

static void ebc_emit_inst(Inst* inst, int* pc2addr) {
  switch (inst->op) {
    case MOV:
      emit_ebc_mov(inst->dst.reg, &inst->src);
      break;

    case ADD:
      emit_ebc_arith(inst, 0x0c);
      break;

    case SUB:
      emit_ebc_arith(inst, 0x0d);
      break;

    case LOAD:
      // MOV R7, R0; Buffer
      emit_ebc_mov_reg(R7, R0);
      emit_2(0x6b, EBCREG[R1]); // PUSH R1
      emit_2(0x6b, EBCREG[R2]); // PUSH R2
      emit_ebc_mov(R1, &inst->src);
      emit_ebc_mov_imm(R2, 0x04); // MOVIdd R2, 0x04
      emit_2(0x4e, (EBCREG[R2] << 4) + EBCREG[R1]); // MUL64 R1, R2
      emit_2(0x4c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD64 R7, R1
      emit_2(0x6c, EBCREG[R2]); // POP R2
      emit_2(0x6c, EBCREG[R1]); // POP R1
      // MOVdd inst->dst.reg, @R7
      emit_2(0x23, 0x80 + (EBCREG[R7] << 4) + EBCREG[inst->dst.reg]);
      break;

    case STORE:
      // MOV R7, R0; Buffer
      emit_ebc_mov_reg(R7, R0);
      emit_2(0x6b, EBCREG[R1]); // PUSH R1
      emit_2(0x6b, EBCREG[R2]); // PUSH R2
      emit_ebc_mov(R1, &inst->src);
      emit_ebc_mov_imm(R2, 0x04); // MOVIdd R2, 0x04
      emit_2(0x4e, (EBCREG[R2] << 4) + EBCREG[R1]); // MUL64 R1, R2
      emit_2(0x4c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD64 R7, R1
      emit_2(0x6c, EBCREG[R2]); // POP R2
      emit_2(0x6c, EBCREG[R1]); // POP R1
      // MOVdd @R7, inst->dst.reg
      emit_2(0x23, (EBCREG[inst->dst.reg] << 4) + 0x08 + EBCREG[R7]);
      break;

    case PUTC:
      emit_2(0x6b, EBCREG[R1]); // PUSH R1
      emit_2(0x6b, EBCREG[R2]); // PUSH R2
      emit_ebc_mov(R7, &inst->src);
      emit_ebc_mov_imm(R2, 0x0000);
      emit_2(0x6b, EBCREG[R2]); // PUSH R2; String
      emit_ebc_mov_reg(R2, R0);
      // MOVww @R2, R7
      emit_2(0x1e, (EBCREG[R7] << 4) + 0x08 + EBCREG[R2]);
      // MOVIww @R2(+2, 0), 0xffff
      emit_2(0x77, 0x50 + 0x08 + EBCREG[R2]);
      emit_2(0x02, 0x00);
      emit_2(0xff, 0xff);
      emit_4(0x60, 0x07, 0x28, 0x00); // MOVqw R7, R0 (0, +40)
      emit_4(0x72, 0xf1, 0x41, 0x10); // MOVn R1, @R7(.SystemTable)
      emit_4(0x72, 0x91, 0x85, 0x21); // MOVn R1, @R1(.ConOut)
      emit_2(0x35, 0x02); // PUSHn R2
      emit_2(0x35, 0x01); // PUSHn R1
      emit_6(0x83, 0x29, 0x01, 0x00, 0x00, 0x10); // CALLEX @R1(.OutputString)
      emit_4(0x60, 0x00, 0x02, 0x10); // MOV R0, R0(+2, 0)
      emit_2(0x6c, EBCREG[R2]); // POP R2; String
      emit_2(0x6c, EBCREG[R2]); // POP R2
      emit_2(0x6c, EBCREG[R1]); // POP R1
      break;

    case GETC:
      emit_2(0x6b, EBCREG[R1]); // PUSH R1
      emit_2(0x6b, EBCREG[R2]); // PUSH R2
      emit_ebc_mov_imm(R2, 0x0000);
      emit_2(0x6b, EBCREG[R2]); // PUSH R2; Key
      emit_ebc_mov_reg(R2, R0);
      emit_4(0x60, 0x07, 0x28, 0x00); // MOVqw R7, R0 (0, +40)
      emit_4(0x72, 0xf1, 0x41, 0x10); // MOVn R1, @R7(.SystemTable)
      emit_4(0x72, 0x91, 0x63, 0x10); // MOVn R1, @R1(.ConIn)
      emit_2(0x35, 0x02); // PUSHn R2
      emit_2(0x35, 0x01); // PUSHn R1
      emit_6(0x83, 0x29, 0x01, 0x00, 0x00, 0x10); // CALLEX @R1(.ReadKeyStroke)
      emit_4(0x60, 0x00, 0x02, 0x10); // MOV R0, R0(+2, 0)
      emit_4(0x60, 0xa7, 0x04, 0x00); // MOV R7, @R2(0, +2)
      emit_2(0x6c, EBCREG[R2]); // POP R2; Key
      emit_2(0x6c, EBCREG[R2]); // POP R2
      emit_2(0x6c, EBCREG[R1]); // POP R1
      emit_ebc_mov_reg(inst->dst.reg, R7);
      break;

    case EXIT:
      emit_2(0x6c, EBCREG[R7]); // POP Buffer
      emit_2(0x6c, EBCREG[R7]); // POP text_vaddr
      emit_2(0x04, 0x00); // RET
      break;

    case DUMP:
      break;

    case EQ:
      emit_ebc_setcc(inst, 0x05, 0x82);
      break;

    case NE:
      emit_ebc_setcc(inst, 0x05, 0xc2);
      break;

    case LT:
      // dst < src; dst + 1 <= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0c, 0x01); // INC inst->dst.reg
      emit_ebc_setcc(inst, 0x08, 0x82);
      emit_2(0x6c, EBCREG[inst->dst.reg]); // POP inst->dst.reg
      break;

    case GT:
      // dst > src; dst - 1 >= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0d, 0x01); // DEC inst->dst.reg
      emit_ebc_setcc(inst, 0x09, 0x82);
      emit_2(0x6c, EBCREG[inst->dst.reg]); // POP inst->dst.reg
      break;

    case LE:
      emit_ebc_setcc(inst, 0x08, 0x82);
      break;

    case GE:
      emit_ebc_setcc(inst, 0x09, 0x82);
      break;

    case JEQ:
      emit_ebc_jcc(inst, 0x05, 0xc0, pc2addr);
      break;

    case JNE:
      emit_ebc_jcc(inst, 0x05, 0x80, pc2addr);
      break;

    case JLT:
      // dst < src; dst + 1 <= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0c, 0x01); // INC inst->dst.reg
      emit_ebc_jcc(inst, 0x08, 0xc0, pc2addr);
      break;

    case JGT:
      // dst > src; dst - 1 >= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0d, 0x01); // DEC inst->dst.reg
      emit_ebc_jcc(inst, 0x09, 0xc0, pc2addr);
      break;

    case JLE:
      emit_ebc_jcc(inst, 0x08, 0xc0, pc2addr);
      break;

    case JGE:
      emit_ebc_jcc(inst, 0x09, 0xc0, pc2addr);
      break;

    case JMP:
      emit_ebc_jcc(inst, 0x00, 0x00, pc2addr);
      break;

    default:
      error("oops");
  }
}

void target_ebc(Module* module) {
  // g_emit_cnt: get size of init code
  emit_reset();
  init_state_ebc(module->data);

  // pc_cnt: get program counter count
  int pc_cnt = 0;
  for (Inst* inst = module->text; inst; inst = inst->next) {
    pc_cnt++;
  }

  // pc2addr: table from pc to addr
  int* pc2addr = calloc(pc_cnt, sizeof(int));
  int prev_pc = -1;
  for (Inst* inst = module->text; inst; inst = inst->next) {
    if (prev_pc != inst->pc) {
      pc2addr[inst->pc] = emit_cnt();
    }
    prev_pc = inst->pc;
    ebc_emit_inst(inst, pc2addr);
  }

  int mp_cnt = 0;
  mp_cnt += 4; // CHAR16[2] String
  mp_cnt += 4; // struct { UINT16 ScanCode; CHAR16 UnicodeChar } Key

  text_vaddr = emit_aligned(SIZE_OF_HEADERS, SECTION_ALIGNMENT);
  text_vsize = emit_cnt();
  text_raddr = emit_aligned(SIZE_OF_HEADERS, FILE_ALIGNMENT) - FILE_ALIGNMENT;
  text_rsize = emit_aligned(text_vsize, FILE_ALIGNMENT);

  rodata_vaddr = emit_aligned(text_vaddr + text_vsize, SECTION_ALIGNMENT);
  rodata_vsize = pc_cnt * 4;
  rodata_raddr = emit_aligned(text_raddr + text_rsize, FILE_ALIGNMENT) - FILE_ALIGNMENT;;
  rodata_rsize = emit_aligned(rodata_vsize, FILE_ALIGNMENT);

  size_of_image = emit_aligned(rodata_vaddr + rodata_vsize - text_vaddr, SECTION_ALIGNMENT);

  // generate PE header
  emit_pe_header();

  // generate actual code
  emit_reset();
  emit_start();
  init_state_ebc(module->data);

  for (Inst* inst = module->text; inst; inst = inst->next) {
    ebc_emit_inst(inst, pc2addr);
  }
  // padding
  for (int i = 0; i < text_rsize - text_vsize; i++) {
    emit_1(0x00);
  }

  for (int i = 0; i < pc_cnt; i++) {
    emit_le32(pc2addr[i]);
  }
  // padding
  for (int i = 0; i < rodata_rsize - rodata_vsize; i++) {
    emit_1(0x00);
  }
}
