#include "gadget.hpp"

Gadget::Gadget(uc_mode uc_mode_, uc_arch uc_arch_) :
m_size(0),emu(uc_mode_,uc_arch_) {
}

Gadget::Gadget(const cpu_info::CPU_description& cpu_description) :
m_size(0), emu(cpu_description) {
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
  int counter_load = 0;
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
      if (reg.second[1] != emu.get_description().common_regs_.at(reg.first)) {
        counter_load += 1;
        load.push_back(emu.get_description().common_regs_.at(reg.first));
      } else {
        non_changed += 1;
      }
    } else if (reg.second[0] == "add" || reg.second[0] == "stack") {
      counter_store += 1;
      store.push_back(emu.get_description().common_regs_.at(reg.first));
    } else if (reg.second[0] == "junk") {
      adjust.push_back(emu.get_description().common_regs_.at(reg.first));
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
  std::cout << std::endl;
}
//TODO: refactor. separate this function.
//TODO: make independent on arch. which type use?
bool Gadget::analize() {
  if (!emu.Init_unicorn())
    return false;
  std::string test(TEST_CODE);
  std::string value_dis = get_code();//TODO: get opcodes not disassemble. Send correct values to RUN
  uc_err result = emu.Map_code(TEST_VALUE, TEST_CODE);//TEST (get_first_offset(), get_code());
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
  int size_dissasembly = value_dis.size();
  int size_byte = get_size();
  result = emu.Run(TEST_VALUE, test.size());//(get_first_offset(), get_size())

  for (auto const& current_reg : arch_description.common_regs_) {
    regs_condition[current_reg.first] = { "junk", "" };
    uint32_t val_emu = emu.Get_reg_value(current_reg.first);
    if (init_regs.find(val_emu) != init_regs.end()) {
      regs_condition[current_reg.first] = { "mov", arch_description.common_regs_.at(uc_x86_reg(init_regs[val_emu])) };
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
  return true;
}

std::map<std::string, z3::expr_vector> Gadget::map(std::map<std::string, z3::expr_vector> input_state, z3::context& z3_context) {
  std::map<std::string, z3::expr_vector> out_state;
  if (!is_analized)
    return out_state;
  out_state = utils::z3_new_state(z3_context, emu.get_description());
  auto ptr_ip_out = out_state.find(emu.get_description().instruction_pointer.begin()->second);
  auto ptr_stack_out = out_state.find(emu.get_description().stack_pointer.begin()->second);
  auto ptr_constr_out = out_state.find("constraints"); 
  auto ptr_ip_input = input_state.find(emu.get_description().instruction_pointer.begin()->second);

  //TEST: get_first_offset() or maybe here get_first_absolute_address(void)
  //We can compare bitvector only by extracting its value.

  auto is_ip_equal_address = ptr_ip_input->second[0].extract(
    utils::get_bit_vector_size(ptr_ip_input->second[0], z3_context) - 1, 0) == TEST_VALUE;
  ptr_constr_out->second.push_back(is_ip_equal_address);

  for (auto & reg : regs_condition) {
    auto ptr_reg_out = out_state.find(emu.get_description().common_regs_.at(reg.first));
	  if (reg.second[0]== "mov") {  
      //auto ptr_reg_in = input_state.find(reg.second[1]);
      //ptr_reg = ptr_reg_in;
      ptr_reg_out->second = input_state.at(emu.get_description().common_regs_.at(reg.first));
    } else if (reg.second[0] == "stack") { //EIP,EBX, EBP stack mode
      //TODO::here add
      ptr_reg_out->second = utils::z3_read_bits(input_state.at("stack"), z3_context, 
        std::stoi(reg.second[1]) * 8, emu.get_description().bits);
    } else if (reg.second[0] == "add") { //EIP mode
      auto value = input_state.at(emu.get_description().common_regs_.at(reg.first));
      z3::expr_vector tmp_vector(z3_context);
      tmp_vector.push_back(value[0] + std::stoi(reg.second[1]));
      ptr_reg_out->second = tmp_vector;
    } else if (reg.second[0] == "junk") {
      z3::expr_vector tmp_vector(z3_context);
      tmp_vector.push_back(z3_context.int_val(utils::random_int(0, 2 * emu.get_description().bits)));
      ptr_reg_out->second = tmp_vector;
    }
  }

  if (mov >= 0) {
    ptr_stack_out->second = utils::z3_read_bits(input_state.at("stack"), z3_context, mov * 8);
  }
  //Works here fine
  int test = out_state.at("constraints").size();

  return out_state;
};

