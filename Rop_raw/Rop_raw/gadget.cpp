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
void Gadget::analize() { //TODO::set to x64 independent
  if (!emu.Init_unicorn())
    return;
  std::string test = "\x5B\x5D\xC3";
  uc_err result = emu.Map_code(0x1000, test);//(get_first_offset(), get_disassembly());
  uint64_t stack = utils::get_random_page(emu.description_);
  std::string stack_data = utils::random_str(emu.description_.page_size);
  result = emu.Setup_stack(stack, emu.description_.page_size, stack_data);
  std::vector<std::string> random_data;
  std::map<uint32_t, uc_x86_reg> init_regs;
  for (int i = 0; i < emu.description_.common_regs.size(); i++) {
    if (emu.description_.common_regs[i] == emu.description_.instruction_pointer ||
      emu.description_.common_regs[i] == emu.description_.stack_pointer) {
      random_data.push_back("");
      continue;
    }
    random_data.push_back(utils::random_str(emu.description_.bits >> 3));
    uint64_t hex_value = std::stoll(utils::convert_string2ascii(random_data[i]),0,16);
    result = emu.Setup_regist(emu.description_.common_regs[i], hex_value);
    uint32_t test_U = emu.Get_reg_value(UC_X86_REG_EAX);
    init_regs[hex_value] = emu.description_.common_regs[i];
  }
  result = emu.Run(0x1000, test.size());//(get_first_offset(), get_size()) //why ???
  for (int i = 0; i < emu.description_.common_regs.size(); i++) {
    uc_x86_reg current_reg = emu.description_.common_regs[i];
    regs_condition[current_reg] = { "junk", "" };
    uint32_t val_emu = emu.Get_reg_value(current_reg);
    if (init_regs.find(val_emu) != init_regs.end()) {
      regs_condition[current_reg] = { "mov", std::to_string(init_regs[val_emu]) }; //TODO chanage to enum 
      continue;
    }

    int32_t offset = utils::gen_find(utils::convert_ascii2string(utils::covert_int2hex(val_emu),16), stack_data);
    //for esp should be -1
    if (offset != -1) {
      regs_condition[current_reg] = { "stack", std::to_string(offset) };
    }
   }

  if (regs_condition[emu.description_.stack_pointer][0] == "junk") {
    mov = emu.Get_reg_value(emu.description_.stack_pointer) - stack;
    regs_condition[emu.description_.stack_pointer] = { "add", std::to_string(mov) };
  }
  is_analized = true;
}
