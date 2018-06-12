#include <ir/ir.h>
#include <target/util.h>

static void rs_init_state(void) {
  emit_line("use std::io::Read;");
  emit_line("use std::process;");

  emit_line("");
  emit_line("#[allow(dead_code)]");
  emit_line("");

  emit_line("struct State {");
  inc_indent();
  for (int i = 0; i < 7; i++) {
    emit_line("%s: i32,", reg_names[i]);
  }
  emit_line("mem: Vec<i32>,");
  dec_indent();
  emit_line("}");

  emit_line("");
  emit_line("#[allow(dead_code)]");
  emit_line("fn getchar() -> u8 {");
  inc_indent();
  emit_line("let ch = match std::io::stdin().bytes().next().and_then(|result| result.ok()).map(|byte| byte as u8) {");
  inc_indent();
  emit_line("None => process::exit(1),");
  emit_line("Some(ch) => ch,");
  dec_indent();
  emit_line("};");
  emit_line("ch");
  dec_indent();
  emit_line("}");

  emit_line("");
  emit_line("#[allow(dead_code)]");
  emit_line("fn putchar(ch: u8) {");
  inc_indent();
  emit_line("print!(\"{}\", ch as char);");
  dec_indent();
  emit_line("}");
}

static void rs_emit_func_prologue(int func_id) {
  emit_line("");
  emit_line("fn func%d(mut state: State) -> State {", func_id);
  inc_indent();
  emit_line("while %d <= state.pc && state.pc < %d {",
            func_id * CHUNKED_FUNC_SIZE, (func_id + 1) * CHUNKED_FUNC_SIZE);
  inc_indent();
  emit_line("match state.pc {");
  inc_indent();
  emit_line("-1 => {");
  inc_indent();
}

static void rs_emit_func_epilogue(void) {
  dec_indent();
  emit_line("},");
  emit_line("_ => {");
  inc_indent();
  emit_line("process::exit(1);");
  dec_indent();
  emit_line("},");
  dec_indent();
  emit_line("}");
  dec_indent();
  emit_line("state.pc += 1;");
  emit_line("}");
  emit_line("state");
  dec_indent();
  emit_line("}");
}

static void rs_emit_pc_change(int pc) {
  dec_indent();
  emit_line("},");
  emit_line("%d => {", pc);
  inc_indent();
}

static const char* rs_value_str(Value* v) {
  if (v->type == REG) {
    return format("state.%s", reg_names[v->reg]);
  } else if (v->type == IMM) {
    return format("%d", v->imm);
  } else {
    error("invalid value");
  }
}

static const char* rs_src_str(Inst* inst) {
  return rs_value_str(&inst->src);
}

static void rs_emit_inst(Inst* inst) {
  switch (inst->op) {
  case MOV:
    emit_line("state.%s = %s;", reg_names[inst->dst.reg], rs_src_str(inst));
    break;

  case ADD:
    emit_line("state.%s = (state.%s + %s) & " UINT_MAX_STR ";",
              reg_names[inst->dst.reg],
              reg_names[inst->dst.reg], rs_src_str(inst));
    break;

  case SUB:
    emit_line("state.%s = (state.%s - state.%s) & " UINT_MAX_STR ";",
              reg_names[inst->dst.reg],
              reg_names[inst->dst.reg], rs_src_str(inst));
    break;

  case LOAD:
    emit_line("state.%s = state.mem[%s];",
              reg_names[inst->dst.reg], rs_src_str(inst));
    break;

  case STORE:
    emit_line("state.mem[%s] = state.%s;", rs_src_str(inst),
              reg_names[inst->dst.reg]);
    break;

  case PUTC:
    emit_line("putchar(%s as u8);", rs_src_str(inst));
    break;

  case GETC:
    emit_line("state.%s = getchar() as i32;", reg_names[inst->dst.reg]);
    break;

  case EXIT:
    emit_line("process::exit(0);");
    break;

  case DUMP:
    break;

  case EQ:
  case NE:
  case LT:
  case GT:
  case LE:
  case GE:
    emit_line("state.%s = (%s) as i32;",
              reg_names[inst->dst.reg], cmp_str(inst, "1"));
    break;

  case JEQ:
  case JNE:
  case JLT:
  case JGT:
  case JLE:
  case JGE:
    emit_line("if %s { state.pc = %s - 1; }",
              cmp_str(inst, "1"), rs_value_str(&inst->jmp));
    break;

  case JMP:
    emit_line("state.pc = %s - 1;", rs_value_str(&inst->jmp));
    break;

  default:
    error("oops");
  }
}

void target_rs(Module* module) {
  rs_init_state();

  int num_funcs = emit_chunked_main_loop(module->text,
                                         rs_emit_func_prologue,
                                         rs_emit_func_epilogue,
                                         rs_emit_pc_change,
                                         rs_emit_inst);

  emit_line("");
  emit_line("fn main() {");
  inc_indent();

  emit_line("let mut state = State {");
  inc_indent();
  for (int i = 0; i < 7; i++) {
    emit_line("%s: 0,", reg_names[i]);
  }
  emit_line("mem: vec![0; 1<<24],");
  dec_indent();
  emit_line("};");

  Data* data = module->data;
  for (int mp = 0; data; data = data->next, mp++) {
    if (data->v) {
      emit_line("state.mem[%d] = %d;", mp, data->v);
    }
  }

  emit_line("");
  emit_line("loop {");
  inc_indent();
  emit_line("match state.pc / %d | 0 {", CHUNKED_FUNC_SIZE);
  for (int i = 0; i < num_funcs; i++) {
    emit_line("%d => state = func%d(state),", i, i);
  }
  emit_line("_ => process::exit(1),");
  emit_line("}");
  dec_indent();
  emit_line("}");

  dec_indent();
  emit_line("}");
}
