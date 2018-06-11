#include <ir/ir.h>
#include <target/util.h>

static void wat_init_state(void) {
  emit_line("const wast = `");
  emit_line("(module");
  inc_indent();
  emit_line("(func $getchar (import \"imports\" \"getchar\") (result i32))");
  emit_line("(func $putchar (import \"imports\" \"putchar\") (param i32))");
  emit_line("(func $exit (import \"imports\" \"exit\") (param i32))");

  for (int i = 0; i < 7; i++) {
    emit_line("(global $%s (mut i32) (i32.const 0))", reg_names[i]);
  }
  emit_line("(memory $mem 256)");
  emit_line("(func $dummy (unreachable))");
}


static void wat_emit_func_prologue(int func_id) {
  emit_line("");
  emit_line("(func $func%d", func_id);
  inc_indent();

  emit_line("(loop");
  inc_indent();
  emit_line("(br_if 1 (i32.eq (i32.and (i32.lt_u (i32.const %d) (get_global $pc)) (i32.ge_u (get_global $pc) (i32.const %d))) (i32.const 1)))",
            func_id * CHUNKED_FUNC_SIZE, (func_id + 1) * CHUNKED_FUNC_SIZE);
  for (int i = 0; i < CHUNKED_FUNC_SIZE + 1; i++) {
    emit_line("(block");
    inc_indent();
  }
  emit_line("(get_global $pc)");
  emit_line("(br_table");
  inc_indent();
  for (int i = 0; i < CHUNKED_FUNC_SIZE + 1; i++) {
    emit_line("%d", i);
  }
  dec_indent();
  emit_line(")");
}

static void wat_emit_func_epilogue(int pc, int func_id) {
  for (; pc < (func_id + 1) * CHUNKED_FUNC_SIZE; pc++) {
    emit_line("(call $dummy)");
    emit_line("(br %d)", (func_id + 1) * CHUNKED_FUNC_SIZE - pc - 1);
    dec_indent();
    emit_line(")");
  }
  emit_line("(set_global $pc (i32.add (get_global $pc) (i32.const 1)))");
  emit_line("(br 0)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
}

static void wat_emit_pc_change(int pc, int func_id) {
  emit_line("(br %d)", (func_id + 1) * CHUNKED_FUNC_SIZE - pc + 1);
  dec_indent();
  emit_line(")");
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
    emit_line("(i32.const 0) (call $exit)");
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

  case JMP:
    if (inst->jmp.type == REG) {
      emit_line("(set_global $pc (i32.sub (get_global $%s) (i32.const 1)))",
                 value_str(&inst->jmp));
    } else {
      emit_line("(set_global $pc (i32.sub (i32.const %d) (i32.const 1)))",
                 inst->jmp);
    }
    break;

  default:
    error("oops");
  }
}

static int wat_emit_chunked_main_loop(Inst* inst,
                            void (*emit_func_prologue)(int func_id),
                            void (*emit_func_epilogue)(int pc, int func_id),
                            void (*emit_pc_change)(int pc, int func_id),
                            void (*emit_inst)(Inst* inst)) {
  int prev_pc = -1;
  int prev_func_id = -1;
  for (; inst; inst = inst->next) {
    int func_id = inst->pc / CHUNKED_FUNC_SIZE;
    if (prev_pc != inst->pc) {
      if (prev_func_id != func_id) {
        if (prev_func_id != -1) {
          emit_pc_change(inst->pc, func_id - 1);
          emit_func_epilogue(inst->pc, func_id - 1);
        }
        emit_func_prologue(func_id);
      }
      emit_pc_change(inst->pc, func_id);
    }
    prev_pc = inst->pc;
    prev_func_id = func_id;

    emit_inst(inst);
    if (!inst->next) {
      emit_pc_change(inst->pc - 1, func_id);
      emit_func_epilogue(inst->pc - 1, func_id);
    }
  }
  return prev_func_id + 1;
}

static void wat_emit_funcs_br_table(int depth, int num_funcs) {
  emit_line("(block");
  inc_indent();
  if (depth < num_funcs) {
    wat_emit_funcs_br_table(depth+1, num_funcs);
  } else {
    emit_line("(i32.div_u (get_global $pc) (i32.const %d))",
                                            CHUNKED_FUNC_SIZE);
    emit_line("(br_table");
    inc_indent();
    for (int i = 0; i < num_funcs+1; i++) {
      emit_line("%d", i);
    }
    dec_indent();
    emit_line(")");
  }
  emit_line("(call $func%d)", num_funcs-depth-1);
  emit_line("(br %d)", depth+1);
  dec_indent();
  emit_line(")");
}

void target_wat(Module* module) {
  wat_init_state();

  int num_funcs = wat_emit_chunked_main_loop(module->text,
                                            wat_emit_func_prologue,
                                            wat_emit_func_epilogue,
                                            wat_emit_pc_change,
                                            wat_emit_inst);

  emit_line("(func (export \"main\")");
  inc_indent();
  inc_indent();

  Data* data = module->data;
  for (int mp = 0; data; data = data->next, mp++) {
    if (data->v) {
      emit_line("(i32.store (i32.const %d) (i32.const %d))", mp, data->v);
    }
  }

  emit_line("");
  emit_line("(loop");
  inc_indent();
  emit_line("(br_if 1 (i32.eq (i32.and (i32.lt_u (i32.const 0) (get_global $pc)) (i32.ge_u (get_global $pc) (i32.const 5))) (i32.const 1)))");
  emit_line("(block");
  inc_indent();
  wat_emit_funcs_br_table(0, num_funcs);
  emit_line("(call $dummy)");
  emit_line("(br 0)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
  emit_line("(i32.const 1) (call $exit)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line("`;");
  emit_line("");
  emit_line("const wast2wasm = require('wast2wasm');");
  emit_line("const readlineSync = require('readline-sync');");
  emit_line("");
  emit_line("let buf = '';");
  emit_line("function getchar() {");
  emit_line(" if (input === '')");
  emit_line("  input = input + readlineSync.question() + '\\n';");
  emit_line(" const result = input.charCodeAt(0);");
  emit_line(" input = input.substring(1);");
  emit_line(" return result;");
  emit_line("}");
  emit_line("function putchar(c) {");
  emit_line(" process.stdout.write(String.fromCharCode(c & 255));");
  emit_line("}");
  emit_line("function exit(status) {");
  emit_line(" process.exit(status);");
  emit_line("}");
  emit_line("function main() {");
  emit_line(" wast2wasm(wast, true).then(wasm => {");
  emit_line("  const buffer = wasm.buffer;");
  emit_line("  WebAssembly.instantiate(buffer, {");
  emit_line("   imports: {");
  emit_line("    getchar,");
  emit_line("    putchar,");
  emit_line("    exit,");
  emit_line("   },");
  emit_line("  }).then(instance => {");
  emit_line("   const result = instance.instance.exports.main();");
  emit_line("  });");
  emit_line(" });");
  emit_line("}");
  emit_line("");
  emit_line("main();");
}