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

void Gadget::analize() {
  if (!emu.Init_unicorn())
    return;
  std::string test_ = "\xB9\x04\x00\x00\x00\x89\xCB";
  uc_err result = emu.Map_code(get_first_offset(), test_); //get_disassembly()
  uint64_t stack = utils::get_random_page(emu.description_);
  std::string stack_data = utils::random_str(emu.description_.page_size);
  result = emu.Setup_stack(stack, emu.description_.page_size, stack_data);
  std::vector<std::string> random_data;
  std::map<uint64_t, uc_x86_reg> registr_value;
  for (int i = 0; i < emu.description_.common_regs.size(); i++) {
    if (emu.description_.common_regs[i] == emu.description_.instruction_pointer ||
      emu.description_.common_regs[i] == emu.description_.stack_pointer) {
      random_data.push_back("");
      continue;
    }
    random_data.push_back(utils::random_str(emu.description_.bits >> 3));
    std::stringstream result_str;
    result_str << std::setw(2) << std::setfill('0') << std::hex << std::uppercase;
    std::copy(random_data[i].begin(), random_data[i].end(), std::ostream_iterator<unsigned int>(result_str, ""));
    uint64_t hex_value;
    result_str >> hex_value;
    result = emu.Setup_regist(emu.description_.common_regs[i], hex_value);
    registr_value[hex_value] = emu.description_.common_regs[i];
  }
  result = emu.Run(get_first_offset(), get_size()); //TODO ???
  int smth = 4;
  //setting value condition to mov reg,reg // or setting reg (stack< int) push/pop??
  //for reg in self.arch.regs:
  //self.regs[reg] = ("junk", )
  //  val = emu[reg]
  //  if init_regs.get(val, None) :
  //    self.regs[reg] = ("mov", init_regs[val])
  //    continue
  //    offset = gen_find(self.arch.pack(val), stack_data)
  //    if offset != -1 :
  //      self.regs[reg] = ("stack", offset)

  //      if self.regs[sp][0] == "junk" :
  //        self.move = emu[self.arch.stack_pointer] - stack
  //        self.regs[sp] = ("add", self.move)

  //        self.analysed = True
}
