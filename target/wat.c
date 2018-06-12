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
  emit_line("(memory $mem 32767 32767)");
}


static void wat_emit_func_prologue(int func_id) {
  emit_line("");
  emit_line("(func $func%d", func_id);
  inc_indent();

  emit_line("(loop");
  inc_indent();
  emit_line("(br_if 1 (i32.eq (i32.and (i32.lt_u (i32.const %d) (get_global $pc)) (i32.ge_u (get_global $pc) (i32.const %d))) (i32.const 1)))",
            func_id * CHUNKED_FUNC_SIZE, (func_id + 1) * CHUNKED_FUNC_SIZE);
  emit_line("(if (i32.eq (get_global $pc) (i32.const -1))");
  inc_indent();
  emit_line("(then");
  inc_indent();
}

static void wat_emit_func_epilogue(void) {
  emit_line("(set_global $pc (i32.add (get_global $pc) (i32.const 1)))");
  emit_line("(br 2)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
}

static void wat_emit_pc_change(int pc) {
  emit_line("(set_global $pc (i32.add (get_global $pc) (i32.const 1)))");
  emit_line("(br 2)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
  emit_line("(if (i32.eq (get_global $pc) (i32.const %d))", pc);
  inc_indent();
  emit_line("(then");
  inc_indent();
}

static const char* wat_value_str(Value* v) {
  if (v->type == REG) {
    return format("(get_global $%s)", reg_names[v->reg]);
  } else if (v->type == IMM) {
    return format("(i32.const %d)", v->imm);
  } else {
    error("invalid value");
  }
}

static const char* wat_src_str(Inst* inst) {
  return wat_value_str(&inst->src);
}

static const char* wat_cmp_str(Inst* inst) {
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
    emit_line("(set_global $%s %s)",
            reg_names[inst->dst.reg], wat_src_str(inst));
    break;

  case ADD:
    emit_line("(set_global $%s (i32.add (get_global $%s) %s))",
            reg_names[inst->dst.reg],
            reg_names[inst->dst.reg], wat_src_str(inst));
    break;

  case SUB:
    emit_line("(set_global $%s (i32.sub (get_global $%s) %s))",
            reg_names[inst->dst.reg],
            reg_names[inst->dst.reg], wat_src_str(inst));
    break;

  case LOAD:
    emit_line("(set_global $%s (i32.load (i32.mul %s (i32.const 4))))",
            reg_names[inst->dst.reg], wat_src_str(inst));
    break;

  case STORE:
    emit_line("(i32.store (i32.mul %s (i32.const 4)) (get_global $%s))",
            wat_src_str(inst), reg_names[inst->dst.reg]);
    break;

  case PUTC:
    emit_line("%s (call $putchar)", wat_src_str(inst));
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
    emit_line("(set_global $%s (i32.%s (get_global $%s) $%s))",
            reg_names[inst->dst.reg], wat_cmp_str(inst),
	    reg_names[inst->dst.reg], wat_src_str(inst));
    break;

  case JEQ:
  case JNE:
  case JLT:
  case JGT:
  case JLE:
  case JGE:
    emit_line("(if (i32.%s (get_global $%s) %s)",
            wat_cmp_str(inst), reg_names[inst->dst.reg], wat_src_str(inst));
    inc_indent();
    emit_line("(then");
    inc_indent();
    emit_line("(set_global $pc (i32.sub (get_global $%s) (i32.const 1)))",
                 wat_value_str(&inst->jmp));
    dec_indent();
    emit_line(")");
    dec_indent();
    emit_line(")");
    break;

  case JMP:
    emit_line("(set_global $pc (i32.sub %s (i32.const 1)))",
            wat_value_str(&inst->jmp));
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

  emit_line("(loop");
  inc_indent();

  for (int i = 0; i < num_funcs; i++) {
    emit_line("(if (i32.eq (i32.div_u (get_global $pc) (i32.const %d)) (i32.const %d))", CHUNKED_FUNC_SIZE, i);
    inc_indent();
    emit_line("(then (call $func%d))", i);
    dec_indent();
    emit_line(")");
  }

  emit_line("(br 0)");
  dec_indent();
  emit_line(")");
  emit_line("(i32.const 1) (call $exit)");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line(")");
  dec_indent();
  emit_line("`;");
  emit_line("");
  emit_line("const wast2wasm = require('wast2wasm');");
  emit_line("");
  emit_line("var input = null;");
  emit_line("var ip = 0;");
  emit_line("function getchar() {");
  emit_line(" if (input === null)");
  emit_line("  input = require('fs').readFileSync('/dev/stdin');");
  emit_line(" return input[ip++] | 0;");
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
