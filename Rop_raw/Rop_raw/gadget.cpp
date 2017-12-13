#include "gadget.hpp"

Gadget::Gadget(uc_mode uc_mode_, uc_arch uc_arch_) :
m_size(0),emu(uc_mode_,uc_arch_) {
}


Gadget::~Gadget(void) {
  /* Avoid memory leaks */
  for(std::list<Instruction*>::iterator it = m_instructions.begin();
      it != m_instructions.end(); ++it)
          delete *it;
}

std::string Gadget::get_disassembly(void) const {
  return m_disassembly;
}

unsigned int Gadget::get_size(void) const {
  return m_size;
}

void Gadget::add_instructions(std::list<Instruction> &instrs, unsigned long long va_section)
{
  for(std::list<Instruction>::const_iterator it = instrs.begin(); it != instrs.end(); ++it) {
      /* 
        * If we haven't any offset yet, it means this instruction is the first one added
        * thus, the offset of the gadget
        * 
        * XXX: Yeah I'm aware that passing the va_section is a bit weird
        */
      if(m_offsets.size() == 0) {
          m_offsets.push_back(it->get_offset());
          m_va_sections.push_back(va_section);
      }
        
      Instruction *instr_copy = new (std::nothrow) Instruction(*it);
      if (instr_copy == NULL) {
        printf("Cannot allocate instr_copy");
        return;
      }

      /* We build our gadget instruction per instruction */
      m_instructions.push_back(instr_copy);

      /* Don't forget to increment the size */
      m_size += it->get_size();

      /* Build the disassembly instruction per instruction */
      m_disassembly += it->get_disassembly() + " ; ";
  }
}

unsigned long long Gadget::get_first_offset(void) const {
  return m_instructions.front()->get_offset();
}

unsigned long long Gadget::get_first_va_section(void) const {
  return m_va_sections.front();
}

unsigned long long Gadget::get_first_absolute_address(void) const {
  return get_first_offset() + get_first_va_section();
}

size_t Gadget::get_nb(void) const {
  return m_offsets.size();
}

void Gadget::add_new_one(unsigned long long offset, unsigned long long va_section) {
  m_offsets.push_back(offset);
  m_va_sections.push_back(va_section);
}

std::list<Instruction*> Gadget::get_instructions(void) {
  std::list<Instruction*> instrs(m_instructions);
  /* We don't want the ending instruction in the list */
  instrs.pop_back();

  return instrs;
}

Instruction* Gadget::get_ending_instruction(void) {
  return m_instructions.back();
}

//TODO: refactor. separate this function.
//TODO: make independent on arch. which type use?
void Gadget::analize() {
  if (!emu.Init_unicorn())
    return;
  std::string test = "\x5B\x5D\xC3";
  uc_err result = emu.Map_code(0x1000, test);//(get_first_offset(), get_disassembly());
  auto arch_description = emu.get_description();
  uint64_t stack = utils::get_random_page(arch_description);
  std::string stack_data = utils::random_str(arch_description.page_size);
  result = emu.Setup_stack(stack, arch_description.page_size, stack_data);
  std::map<uint32_t, uc_x86_reg> init_regs;
  for (auto const& current_reg : arch_description.common_regs_) {
    std::string random_data;
    if (current_reg.first == arch_description.instruction_pointer.begin()->first ||
      current_reg.first == arch_description.stack_pointer.begin()->first) {
      random_data = "";
      continue;
    }
    random_data = utils::random_str(arch_description.bits >> 3);
    uint64_t hex_value = std::stoll(utils::convert_string2ascii(random_data),0,16);
    result = emu.Setup_regist(current_reg.first, hex_value);
    init_regs[hex_value] = current_reg.first;
  }
  result = emu.Run(0x1000, test.size());//(get_first_offset(), get_size())

  for (auto const& current_reg : arch_description.common_regs_) {
    regs_condition[current_reg.first] = { "junk", "" };
    uint32_t val_emu = emu.Get_reg_value(current_reg.first);
    if (init_regs.find(val_emu) != init_regs.end()) {
      regs_condition[current_reg.first] = { "mov", std::to_string(init_regs[val_emu]) }; //TODO chanage to enum 
      continue;
    }
    int32_t offset = utils::gen_find(utils::convert_ascii2string(utils::covert_int2hex(val_emu),16), stack_data);
    if (offset != -1) {
      regs_condition[current_reg.first] = { "stack", std::to_string(offset) };
    }
   }

  if (regs_condition[arch_description.stack_pointer.begin()->first][0] == "junk") {
    mov = emu.Get_reg_value(arch_description.stack_pointer.begin()->first) - stack;
    regs_condition[arch_description.stack_pointer.begin()->first] = { "add", std::to_string(mov) };
  }
  is_analized = true;
}

std::map<std::string, z3::expr_vector> Gadget::start_map() {
  std::map<std::string, z3::expr_vector> result;
  result = z3_state;
  //TODO: if change iterator will it change the value?
  auto ptr_ip = result.find(get_arch_info().instruction_pointer.begin()->second);
  auto ptr_stack = z3_state.find("stack");
  ptr_ip->second = utils::z3_read_bits(ptr_stack->second, z3_context, 0,get_arch_info().bits);
  auto ptr_sp = result.find(get_arch_info().stack_pointer.begin()->second);
  ptr_sp->second[0] = ptr_sp->second[0] + (get_arch_info().bits >> 3);
  return result;
};
std::map<std::string, z3::expr_vector> Gadget::smt_map() {
  std::map<std::string, z3::expr_vector> result;
  return result;
};

void Gadget::map() {
  z3_state = utils::z3_new_state(z3_context, emu.get_description());
  start_map();
  smt_map(); // in wich calls build round. in wich calls map for real gadget
}

std::map<std::string, z3::expr_vector> Gadget::gadget_map() {
  std::map<std::string, z3::expr_vector> result;
  if (!is_analized)
    return result;
  //z3_state = utils::z3_new_state(z3_context, emu.get_description());
  //z3_state["constraints"].push_back(z3_state[emu.get_description().instruction_pointer.begin()->second] == address);
  int smth = 2;
  return result;
}

//def map(self, ins) :
//assert self.analysed
//outs = dict(ins)
//outs["constraints"] = list(ins["constraints"])
//outs["constraints"].append(ins[self.arch.ip] == self.address)
//
//for reg, action in self.regs.items() :
//if action[0] == "mov" :
//outs[reg] = ins[action[1]]
//elif action[0] == "stack" :
//outs[reg] = z3_read_bits(ins["stack"], action[1] * 8, self.arch.bits)
//elif action[0] == "add" :
//outs[reg] = ins[reg] + action[1]
//elif action[0] == "junk" :
//outs[reg] = random.randint(0, 2 * *self.arch.bits)
//
//if self.move >= 0 :
//outs["stack"] = z3_read_bits(ins["stack"], self.move * 8)
//
//return outs