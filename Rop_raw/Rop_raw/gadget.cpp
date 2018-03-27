#include "gadget.hpp"

Gadget::Gadget(uc_mode uc_mode_, uc_arch uc_arch_) :
m_size(0),cpu_description(cpu_info::CPU_description(uc_mode_, uc_arch_)) {
}

Gadget::Gadget(const cpu_info::CPU_description& cpu_description_) :
m_size(0), cpu_description(cpu_description_) {
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
      m_code += it->get_opcodes();
  }
}

std::string Gadget::get_code(void) const {
  return m_code;
};

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

void Gadget::print_condition() {
  /*int counter_load = 0;
  int counter_store = 0;
  int counter_call = 0;
  int counter_syscall = 0;
  int counter_adjust = 0;
  int non_changed = 0;
  std::vector<std::string> load;
  std::vector<std::string> store;
  std::vector<std::string> adjust;
  for (auto reg : regs_condition) {
    if (reg.second[0] == "mov") {
      if (reg.second[1] != cpu_description.common_regs_.at(reg.first)) {
        counter_load += 1;
        load.push_back(cpu_description.common_regs_.at(reg.first));
      } else {
        non_changed += 1;
      }
    } else if (reg.second[0] == "add" || reg.second[0] == "stack") {
      counter_store += 1;
      store.push_back(cpu_description.common_regs_.at(reg.first));
    } else if (reg.second[0] == "junk") {
      adjust.push_back(cpu_description.common_regs_.at(reg.first));
    }
  }
  std::cout << "\n******GADGET INSTRUCTION INFO******\n";
  std::cout << "***NON CHANGED Registers \n*** Total Count: \n" << non_changed << std::endl;
  std::cout << "***LOAD***\n";
  std::cout << "  Total count: " << counter_load << std::endl;
  std::cout << "  Registers: ";
  for (auto reg : load) {
    std::cout << reg << ",";
  }
  std::cout << "\n***STORE***\n";
  std::cout << "  Total count: " << counter_store << std::endl;
  std::cout << "  Registers: ";
  for (auto reg : store) {
    std::cout << reg << ",";
  }
  std::cout << "\n***CALL***\n";
  std::cout << "  Total count: " << 0 << std::endl;
  std::cout << "***Syscall***\n";
  std::cout << "  Total count: " << 0 << std::endl;
  std::cout << "***Adjust***\n";
  std::cout << "  Total count: " << counter_adjust << std::endl;
  std::cout << "  Registers: ";
  for (auto reg : adjust) {
    std::cout << reg << ",";
  }
  std::cout << std::endl;*/
}

//bool Gadget::analize() {
//  sequence_helper::AnalizeMngr analize_mngr(cpu_description);
//  if (analize_mngr.Is_initialized()) {
//    std::string tmp_code(TEST_CODE);
//    regs_condition = analize_mngr.GetAnalizedState(tmp_code,TEST_VALUE,&mov);
//    is_analized = true;
//    return true;
//  }
//  return false;
//}

//sequence_helper::SMTGadgetDescription Gadget::map(sequence_helper::SMTGadgetDescription input_state, z3::context& z3_context) {
//  sequence_helper::AnalizeMngr analize_mngr(cpu_description);
//  return analize_mngr.GetMappedState(input_state, regs_condition, z3_context, mov, TEST_VALUE);
//};

