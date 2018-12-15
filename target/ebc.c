#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ir/ir.h>
#include <target/util.h>

Sec text, rodata;

static int aligned(int addr, int align) {
  return ((addr / align) + 1) * align;
}

static void emit_headers(int imagesz) {
  int hdrsz = 0;
  hdrsz += emit_pe_header(0x0ebc, imagesz, 2);
  hdrsz += emit_pe_sechdr(&text);
  hdrsz += emit_pe_sechdr(&rodata);

  char *padding = calloc(PE_HEADER_SIZE - hdrsz, sizeof(char));

  fwrite(padding, PE_HEADER_SIZE - hdrsz, 1, stdout);
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

static void emit_ebc_cmp(Inst* inst, int cmp) {
  emit_ebc_mov(R7, &inst->src);
  emit_2(cmp, (EBCREG[R7] << 4) + EBCREG[inst->dst.reg]);
}

static void emit_ebc_setcc(Inst* inst, int cmp, int op) {
  emit_ebc_cmp(inst, cmp);
  if (inst->op == LT || inst->op == GT) {
    emit_2(0x6c, EBCREG[inst->dst.reg]); // POP64 inst->dst.reg
  }
  emit_2(op, 0x04); // JMP8cc .L1
  emit_ebc_mov_imm(inst->dst.reg, 0x01);
  emit_2(0x02, 0x04); // JMP8 .L2
  emit_ebc_mov_imm(inst->dst.reg, 0x00);
  emit_2(0x02, 0x00); // JMP8 .L2
}

static void emit_ebc_jcc(Inst* inst, int cmp, int op, int* pc2addr) {
  if (op) {
    emit_ebc_cmp(inst, cmp);
    if (inst->op == JLT || inst->op == JGT) {
      emit_2(0x6c, EBCREG[inst->dst.reg]); // POP64 inst->dst.reg
    }
  }

  emit_2(0x6b, EBCREG[R1]); // PUSH64 R1
  if (inst->jmp.type == REG) {
    emit_ebc_mov_reg(R7, inst->jmp.reg);
    emit_2(0x6b, EBCREG[R2]); // PUSH64 R2
    // MOVREL R1, rodata
    emit_2(0xb9, EBCREG[R1]);
    emit_le32(rodata.vaddr - (text.vaddr + emit_cnt() + 4));
    emit_ebc_mov_imm(R2, 0x04);
    emit_2(0x4e, (EBCREG[R2] << 4) + EBCREG[R7]); // MUL64 R7, R2
    emit_2(0x4c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD64 R7, R1
    emit_2(0x1e, 0x80 + (EBCREG[R7] << 4) + EBCREG[R7]); // MOVww R7, @R7
    emit_2(0x6c, EBCREG[R2]); // POP64 R2
  } else {
    emit_ebc_mov_imm(R7, pc2addr[inst->jmp.imm]);
  }
  // MOVdw R1, @R0(0, +18)
  emit_4(0x5f, 0x80 + (EBCREG[R0] << 4) + EBCREG[R1], 0x10, 0x00);
  emit_2(0x4c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD64 R7, R1
  emit_2(0x6c, EBCREG[R1]); // POP64 R1
  emit_2(0x01, op + EBCREG[R7]); // JMP32 R7
}

static void init_state_ebc(Data* data) {
  // XXX: PUSH text_vaddr
  emit_2(0x2a, (0x01 << 4) + EBCREG[R7]); // STORE R7, IP
  emit_2(0x6b, EBCREG[R7]); // PUSH64 R7

  emit_ebc_mov_imm(R7, 0x00);
  emit_2(0x6b, EBCREG[R7]); // PUSH64 Buffer
  emit_4(0x60, 0x07, 0x10, 0x00); // MOVqw R7, R0 (0, +16);
  emit_4(0x72, 0xf7, 0x41, 0x10); // MOVnw R7, @R7 (.SystemTable)
  emit_4(0x72, 0xf7, 0x89, 0x21); // MOVnw R7, @R7 (.BootServices)
  emit_4(0x77, 0x31, 0x02, 0x00); // MOVI R1, 0x0002
  emit_6(0xb7, 0x32, 0x00, 0x00, 0x00, 0x04); // MOVI R2, 0x04000000
  emit_ebc_mov_reg(R3, R0); // MOV R3, R0 XXX: void **Buffer is R3
  emit_2(0x35, 0x03); // PUSHn32 R3
  emit_2(0x35, 0x02); // PUSHn32 R2
  emit_2(0x35, 0x01); // PUSHn32 R1
  emit_6(0x83, 0x2f, 0x85, 0x01, 0x00, 0x10); // CALL32EXa @R7 (.AllocatePool)
  emit_4(0x60, 0x00, 0x03, 0x10); // MOVqw R0, R0 (+3, 0)

  for (int mp = 0; data; data = data->next, mp++) {
    if (data->v) {
      emit_2(0x20, 0x87); // MOVqw R7, @R0
      emit_ebc_mov_imm(R1, 0x04);
      emit_ebc_mov_imm(R2, mp);
      emit_2(0x4e, 0x21); // MUL64 R1, R2
      emit_2(0x4c, 0x17); // ADD64 R7, R1
      // MOVIqw @R7, data->v
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
    case STORE:
      emit_2(0x28, 0x80 + (EBCREG[R0] << 4) + EBCREG[R7]); // MOVqq R7, @R0
      emit_2(0x6b, EBCREG[R1]); // PUSH64 R1
      emit_2(0x6b, EBCREG[R2]); // PUSH64 R2
      emit_ebc_mov(R1, &inst->src);
      emit_ebc_mov_imm(R2, 0x04); // MOVIdd R2, 0x04
      emit_2(0x4e, (EBCREG[R2] << 4) + EBCREG[R1]); // MUL64 R1, R2
      emit_2(0x4c, (EBCREG[R1] << 4) + EBCREG[R7]); // ADD64 R7, R1
      emit_2(0x6c, EBCREG[R2]); // POP64 R2
      emit_2(0x6c, EBCREG[R1]); // POP64 R1
      if (inst->op == LOAD) {
        // MOVdd inst->dst.reg, @R7
        emit_2(0x23, 0x80 + (EBCREG[R7] << 4) + EBCREG[inst->dst.reg]);
      } else if (inst->op == STORE) {
        // MOVdd @R7, inst->dst.reg
        emit_2(0x23, (EBCREG[inst->dst.reg] << 4) + 0x08 + EBCREG[R7]);
      }
      break;


    case PUTC:
      emit_2(0x6b, EBCREG[R1]); // PUSH64 R1
      emit_2(0x6b, EBCREG[R2]); // PUSH64 R2
      emit_ebc_mov(R7, &inst->src);
      emit_ebc_mov_imm(R2, 0x0000);
      emit_2(0x6b, EBCREG[R2]); // PUSH64 R2; String
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
      emit_2(0x6c, EBCREG[R2]); // POP64 R2; String
      emit_2(0x6c, EBCREG[R2]); // POP64 R2
      emit_2(0x6c, EBCREG[R1]); // POP64 R1
      break;

    case GETC:
      emit_2(0x6b, EBCREG[R1]); // PUSH64 R1
      emit_2(0x6b, EBCREG[R2]); // PUSH64 R2
      emit_ebc_mov_imm(R2, 0x0000);
      emit_2(0x6b, EBCREG[R2]); // PUSH64 R2; Key
      emit_ebc_mov_reg(R2, R0);
      emit_4(0x60, 0x07, 0x28, 0x00); // MOVqw R7, R0 (0, +40)
      emit_4(0x72, 0xf1, 0x41, 0x10); // MOVn R1, @R7(.SystemTable)
      emit_4(0x72, 0x91, 0x63, 0x10); // MOVn R1, @R1(.ConIn)
      emit_2(0x35, 0x02); // PUSHn R2
      emit_2(0x35, 0x01); // PUSHn R1
      emit_6(0x83, 0x29, 0x01, 0x00, 0x00, 0x10); // CALLEX @R1(.ReadKeyStroke)
      emit_4(0x60, 0x00, 0x02, 0x10); // MOV R0, R0(+2, 0)
      emit_4(0x60, 0xa7, 0x04, 0x00); // MOV R7, @R2(0, +2)
      emit_2(0x6c, EBCREG[R2]); // POP64 R2; Key
      emit_2(0x6c, EBCREG[R2]); // POP64 R2
      emit_2(0x6c, EBCREG[R1]); // POP64 R1
      emit_ebc_mov_reg(inst->dst.reg, R7);
      break;

    case EXIT:
      emit_2(0x6c, EBCREG[R7]); // POP64 Buffer
      emit_2(0x6c, EBCREG[R7]); // POP64 text_vaddr
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
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH64 inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0c, 0x01); // INC inst->dst.reg
      emit_ebc_setcc(inst, 0x08, 0x82);
      break;

    case GT:
      // dst > src; dst - 1 >= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH64 inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0d, 0x01); // DEC inst->dst.reg
      emit_ebc_setcc(inst, 0x09, 0x82);
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
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH64 inst->dst.reg
      emit_ebc_arith_imm(inst->dst.reg, 0x0c, 0x01); // INC inst->dst.reg
      emit_ebc_jcc(inst, 0x08, 0xc0, pc2addr);
      break;

    case JGT:
      // dst > src; dst - 1 >= src
      emit_2(0x6b, EBCREG[inst->dst.reg]); // PUSH64 inst->dst.reg
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

  strcpy(text.name, ".text");
  text.vaddr = aligned(PE_HEADER_SIZE, PE_SEC_ALIGN);
  text.vsize = emit_cnt();
  text.raddr = aligned(PE_HEADER_SIZE, PE_FILE_ALIGN) - PE_FILE_ALIGN;
  text.rsize = aligned(text.vsize, PE_FILE_ALIGN);
  text.chars = 0x60000020; // r-x exec

  strcpy(rodata.name, ".rodata");
  rodata.vaddr = aligned(text.vaddr + text.vsize, PE_SEC_ALIGN);
  rodata.vsize = pc_cnt * 4;
  rodata.raddr = aligned(text.raddr + text.rsize, PE_FILE_ALIGN)
                                                    - PE_FILE_ALIGN;
  rodata.rsize = aligned(rodata.vsize, PE_FILE_ALIGN);
  rodata.chars = 0x40000040; // r-- inited

  int imagesz = aligned(rodata.vaddr + rodata.vsize - text.vaddr, PE_SEC_ALIGN);

  // generate PE header
  emit_headers(imagesz);

  // generate actual code
  emit_reset();
  emit_start();
  init_state_ebc(module->data);

  for (Inst* inst = module->text; inst; inst = inst->next) {
    ebc_emit_inst(inst, pc2addr);
  }
  // padding
  for (int i = 0; i < (int)(text.rsize - text.vsize); i++) {
    emit_1(0x00);
  }

  for (int i = 0; i < pc_cnt; i++) {
    emit_le32(pc2addr[i]);
  }
  // padding
  for (int i = 0; i < (int)(rodata.rsize - rodata.vsize); i++) {
    emit_1(0x00);
  }
}
