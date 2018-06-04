#include <ir/ir.h>
#include <target/util.h>

static void wat_init_state(void) {
  emit_line("(module");
  inc_indent();
  emit_line("(func $getchar (import \"imports\" \"getchar\") (result i32))");
  emit_line("(func $putchar (import \"imports\" \"putchar\") (param i32))");

  for (int i = 0; i < 7; i++) {
    emit_line("(global $%s (mut i32) (i32.const 0))", reg_names[i]);
  }
  emit_line("(memory $mem 256)");
}

static void wat_emit_func_prologue(int func_id) {
  emit_line("");
  emit_line("(func $func%d", func_id);
  inc_indent();

  /* TODO: Rewrite */
  emit_line("while (%d <= pc && pc < %d) {",
            func_id * CHUNKED_FUNC_SIZE, (func_id + 1) * CHUNKED_FUNC_SIZE);
  inc_indent();
  emit_line("switch (pc) {");
  emit_line("case -1:  /* dummy */");
  inc_indent();
}

static void wat_emit_func_epilogue(void) {
  dec_indent();
  emit_line(")");
  emit_line("(set_global $pc (i32.add (get_global $pc) (i32.const 1)))");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
}

static void wat_emit_pc_change(int pc) {
  /* TODO: Rewrite */
  emit_line("break;");
  emit_line("");
  dec_indent();
  emit_line("case %d:", pc);
  inc_indent();
}

static char* wat_cmp_str(Inst* inst) {
  int op = normalize_cond(inst->op, 0);
  switch (op) {
    case JEQ:
      return "eq";
    case JNE:
      return "ne";
    case JLT:
      return "lt_u";
    case JGT:
      return "gt_u";
    case JLE:
      return "le_u";
    case JGE:
      return "ge_u";
    default:
      error("oops");
  }
}

static void wat_emit_inst(Inst* inst) {
  switch (inst->op) {
  case MOV:
    if (inst->src.type == REG) {
      emit_line("(set_global $%s (get_global $%s))",
                 reg_names[inst->dst.reg], src_str(inst));
    } else {
      emit_line("(set_global $%s (i32.const %s))",
                 reg_names[inst->dst.reg], src_str(inst));
    }
    break;

  case ADD:
    if (inst->src.type == REG) {
      emit_line("(set_global $%s (i32.add (get_global $%s) (get_global $%s)))",
                 reg_names[inst->dst.reg],
		 reg_names[inst->dst.reg], src_str(inst));
    } else {
      emit_line("(set_global $%s (i32.add (get_global $%s) (i32.const %s)))",
                 reg_names[inst->dst.reg],
		 reg_names[inst->dst.reg], src_str(inst));
    }
    break;

  case SUB:
    if (inst->src.type == REG) {
      emit_line("(set_global $%s (i32.sub (get_global $%s) (get_global $%s)))",
                 reg_names[inst->dst.reg],
		 reg_names[inst->dst.reg], src_str(inst));
    } else {
      emit_line("(set_global $%s (i32.sub (get_global $%s) (i32.const %s)))",
                 reg_names[inst->dst.reg],
		 reg_names[inst->dst.reg], src_str(inst));
    }
    break;

  case LOAD:
    if (inst->src.type == REG) {
      emit_line("(set_global $%s (i32.load8_s (get_global $%s)))",
                 reg_names[inst->dst.reg], src_str(inst));
    } else {
      emit_line("(set_global $%s (i32.load8_s (i32.const %s)))",
                 reg_names[inst->dst.reg], src_str(inst));
    }
    break;

  case STORE:
    if (inst->src.type == REG) {
      emit_line("(i32.store8 (get_global $%s) (get_global $%s))",
                 src_str(inst), reg_names[inst->dst.reg]);
    } else {
      emit_line("(i32.store8 (i32.const %s) (get_global $%s))",
                 src_str(inst), reg_names[inst->dst.reg]);
    }
    break;

  case PUTC:
    if (inst->src.type == REG) {
      emit_line("(get_global $%s) (call $putchar)", src_str(inst));
    } else {
      emit_line("(i32.const %s) (call $putchar)", src_str(inst));
    }
    break;

  case GETC:
    emit_line("(set_global $%s (call $getchar))", reg_names[inst->dst.reg]);
    break;

  case EXIT:
    /* TODO: Fix */
    emit_line("exit(0);");
    break;

  case DUMP:
    break;

  case EQ:
  case NE:
  case LT:
  case GT:
  case LE:
  case GE:
    if (inst->src.type == REG) {
      emit_line("(set_global $%s (i32.%s (get_global $%s) (get_global $%s)))",
                 reg_names[inst->dst.reg], wat_cmp_str(inst),
		 reg_names[inst->dst.reg], src_str(inst));
    } else {
      emit_line("(set_global $%s (i32.%s (get_global $%s) (i32.const %s)))",
                 reg_names[inst->dst.reg], wat_cmp_str(inst),
		 reg_names[inst->dst.reg], src_str(inst));
    }
    break;

  case JEQ:
  case JNE:
  case JLT:
  case JGT:
  case JLE:
  case JGE:
  case JMP:
    if (inst->src.type == REG) {
      emit_line("(if (i32.%s (get_global $%s) (get_global $%s))",
                 wat_cmp_str(inst), reg_names[inst->dst.reg], src_str(inst));
      inc_indent();
      emit_line("(then");
      inc_indent();
      emit_line("(set_global $pc (i32.sub (get_global $%s) (i32.const 1))",
                 value_str(&inst->jmp));
      dec_indent();
      emit_line(")");
      dec_indent();
      emit_line(")");
    } else {
      emit_line("(if (i32.%s (get_global $%s) (i32.const %s))",
                 wat_cmp_str(inst), reg_names[inst->dst.reg], src_str(inst));
      inc_indent();
      emit_line("(then");
      inc_indent();
      emit_line("(set_global $pc (i32.sub (i32.const %s) (i32.const 1))",
                 value_str(&inst->jmp));
      dec_indent();
      emit_line(")");
      dec_indent();
      emit_line(")");
    }
    break;

  default:
    error("oops");
  }
}

void target_wat(Module* module) {
  wat_init_state();

  int num_funcs = emit_chunked_main_loop(module->text,
                                         wat_emit_func_prologue,
                                         wat_emit_func_epilogue,
                                         wat_emit_pc_change,
                                         wat_emit_inst);

  emit_line("(func (export \"main\")");
  inc_indent();

  Data* data = module->data;
  for (int mp = 0; data; data = data->next, mp++) {
    if (data->v) {
      emit_line("(i32.store (i32.const %d) (i32.const %d))", mp, data->v);
    }
  }

  /* TODO: Rewrite */
  emit_line("");
  emit_line("while (1) {");
  inc_indent();
  emit_line("switch (pc / %d | 0) {", CHUNKED_FUNC_SIZE);
  for (int i = 0; i < num_funcs; i++) {
    emit_line("case %d:", i);
    emit_line(" func%d();", i);
    emit_line(" break;");
  }
  emit_line("}");
  dec_indent();
  emit_line("}");

  emit_line("return 1;");
  dec_indent();
  emit_line("}");
}
