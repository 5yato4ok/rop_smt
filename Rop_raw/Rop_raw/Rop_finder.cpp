#include "Rop_finder.h"
#define BEA_ENGINE_STATIC

namespace findrop_helper {

Rop_finder::Rop_finder(std::fstream& input, uint32_t m_depth_) : 
m_depth(m_depth_), cpu_info(UC_MODE_V9, UC_ARCH_X86) {
  if (init(input)) {
    initialized_ = true;
  }
};


std::multiset<Gadget*, Gadget::Sort> Rop_finder::find_rop() {
  std::multiset<Gadget*, Gadget::Sort> gadgets_found;
  /* Walk the executable sections */
  for (std::vector<Section*>::iterator it_sec = executable_sections.begin(); it_sec != executable_sections.end(); ++it_sec) {
    std::cout << "in " << (*it_sec)->get_name() << std::endl;
    unsigned long long va_section = (*it_sec)->get_vaddr();

    std::multiset<Gadget*> gadgets = find_gadget_in_memory((const char*)(*it_sec)->get_section_buffer(),
      (*it_sec)->get_size(), va_section, m_depth);
    std::cout << gadgets.size() << " found." << std::endl << std::endl;

    /*
    XXX:
    If at&t syntax is enabled, BeaEngine doesn't seem to handle the prefix:
    \xf0\x00\x00 => addb %al, (%eax) ; -- and in intel -- lock add byte [eax], al ; ret  ;

    It will introduce differences between the number of unique gadgets found!
    */

    /* Mergin'! */
    for (std::multiset<Gadget*>::iterator it_g = gadgets.begin(); it_g != gadgets.end(); ++it_g)
      gadgets_found.insert(*it_g);
  }
  return gadgets_found;
}

bool Rop_finder::init(std::fstream& input_file) {
  uc_mode mode_ = exe_info.extract_information_from_binary(input_file);
  executable_sections = exe_info.get_executables_section(input_file);
  cpu_info = cpu_info::CPU_description(mode_, UC_ARCH_X86); //TODO:change in future;
  found_gadgets = find_rop();
  if (!cpu_info.is_initialized() || executable_sections.empty() ||found_gadgets.empty()) {
    printf("ERROR while extracting info");
    return false;
  }
  return true;
}

void Rop_finder::init_disasm_struct(DISASM& d) {
  d = { 0 };
  // those options are mostly display option for the disassembler engine 
  //d.Options = m_opts;
  d.Archi = cpu_info.bits;
}

std::multiset<Gadget*> Rop_finder::find_all_gadget_from_ret(const char* data, unsigned long long vaddr,
  const DISASM& ending_instr_disasm, unsigned int len_ending_instr) {
  std::multiset<Gadget*> gadgets;
  DISASM dis;
  init_disasm_struct(dis);
  /*
  We go back, trying to create the longuest gadget possible with the longuest instructions
  "On INTEL processors, (in IA-32 or intel 64 modes), instruction never exceeds 15 bytes." -- beaengine.org
  */
  dis.EIP = (UIntPtr)(ending_instr_disasm.EIP - m_depth * 15); // /!\ Warning to pointer arith
  dis.VirtualAddr = ending_instr_disasm.VirtualAddr - m_depth * 15;

  /* going back yeah, but not too much :)) */
  if (dis.EIP < (UIntPtr)data) {
    dis.EIP = (UIntPtr)data;
    dis.VirtualAddr = vaddr;
  }

  while (dis.EIP < ending_instr_disasm.EIP) {
    std::list<Instruction> list_of_instr;

    /* save where we were in memory */
    UIntPtr saved_eip = dis.EIP;
    UInt64 saved_vaddr = dis.VirtualAddr;
    bool is_a_valid_gadget = false;

    /* now we'll try to find suitable sequence */
    for (unsigned int nb_ins = 0; nb_ins < m_depth; nb_ins++) {
      int len_instr = Disasm(&dis);

      /* if the instruction isn't valid, let's try the process one byte after */
      if (len_instr == UNKNOWN_OPCODE || is_valid_instruction(dis) == false)
        break;
      std::string opcodes_string((char*)dis.EIP, len_instr);
      list_of_instr.push_back(Instruction(
        std::string(dis.CompleteInstr), std::string(dis.Instruction.Mnemonic),opcodes_string,
        dis.EIP - (UIntPtr)data, len_instr));

      dis.EIP += len_instr;
      dis.VirtualAddr += len_instr;

      /* if the address of the latest instruction found points on the ending one, we have a winner */
      if (dis.EIP == ending_instr_disasm.EIP) {
        is_a_valid_gadget = true;
        /* NB: I reach the ending instruction without depth instruction */
        break;
      }

      /* if we point after the ending one, it's not a valid sequence */
      if (dis.EIP > ending_instr_disasm.EIP)
        break;
    }

    if (is_a_valid_gadget) {
      /* we have a valid gadget, time to build it ; add the instructions found & finally add the ending instruction */
      std::string opcodes_string((char*)dis.EIP, len_ending_instr);
      /* Don't forget to include the ending instruction in the chain of instruction */
      list_of_instr.push_back(Instruction(
        std::string(ending_instr_disasm.CompleteInstr),
        std::string(ending_instr_disasm.Instruction.Mnemonic),opcodes_string,
        ending_instr_disasm.EIP - (UIntPtr)data,len_ending_instr ));

      Gadget *gadget = new (std::nothrow) Gadget(cpu_info);
      if (gadget == NULL)
        printf("Cannot allocate gadget");

      /* Now we populate our gadget with the instructions previously found.. */
      gadget->add_instructions(list_of_instr, vaddr);
      gadgets.insert(gadget);
    }

    /* goto the next byte */
    dis.EIP = saved_eip + 1;
    dis.VirtualAddr = saved_vaddr + 1;

  }
  return gadgets;
}

bool Rop_finder::is_valid_ending_instruction_nasm(DISASM& ending_instr_d) {
  Int32 branch_type = ending_instr_d.Instruction.BranchType;
  UInt64 addr_value = ending_instr_d.Instruction.AddrValue;
  char *mnemonic = ending_instr_d.Instruction.Mnemonic; 
  char *completeInstr = ending_instr_d.CompleteInstr;

  bool is_good_branch_type = (
    /* We accept all the ret type instructions (except retf/iret) */
    (branch_type == RetType && strncmp(mnemonic, "retf", 4) != 0 && strncmp(mnemonic, "iretd", 4) != 0) ||

    /* call reg32 / call [reg32] */
    (branch_type == CallType && addr_value == 0) ||

    /* jmp reg32 / jmp [reg32] */
    (branch_type == JmpType && addr_value == 0) ||

    /* int 0x80 & int 0x2e */
    (strncmp(completeInstr, "int 0x80", 8) == 0 || strncmp(completeInstr, "int 0x2e", 8) == 0 
    || strncmp(completeInstr, "syscall", 7) == 0)
    );

  return (is_good_branch_type &&
    /* Yeah, entrance isn't allowed to the jmp far/call far */
    strstr(completeInstr, "far") == NULL);
}

bool Rop_finder::is_valid_ending_instruction_att(DISASM& ending_instr_d) {
  Int32 branch_type = ending_instr_d.Instruction.BranchType;
  UInt64 addr_value = ending_instr_d.Instruction.AddrValue;
  //TODO: change to string
  char *mnemonic = ending_instr_d.Instruction.Mnemonic, *completeInstr = ending_instr_d.CompleteInstr;

  bool is_good_branch_type = (
    /* We accept all the ret type instructions (except retf/iret) */
    (branch_type == RetType && strncmp(mnemonic, "lret", 4) != 0 && strncmp(mnemonic, "retf", 4) != 0 
    && strncmp(mnemonic, "iret", 4) != 0) ||

    /* call reg32 / call [reg32] */
    (branch_type == CallType && addr_value == 0) ||

    /* jmp reg32 / jmp [reg32] */
    (branch_type == JmpType && addr_value == 0) ||

    /* int 0x80 & int 0x2e */
    (strncmp(completeInstr, "intb $0x80", 10) == 0 || strncmp(completeInstr, "intb $0x2e", 10) == 0 
    || strncmp(completeInstr, "syscall", 7) == 0)
    );

  return (
    is_good_branch_type &&

    /* Yeah, entrance isn't allowed to the jmp far/call far */
    (strncmp(completeInstr, "lcall", 5) != 0 && strncmp(completeInstr, "ljmp", 4) != 0)
    );
}

bool Rop_finder::is_valid_ending_instruction(DISASM& ending_instr_d) {
  bool isAllowed = false;
  /*
  Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
  Btw, this is not the only case!
  */
  if (ending_instr_d.CompleteInstr[0] != 0) {
    if (NasmSyntax) //m_opts
      isAllowed = is_valid_ending_instruction_nasm(ending_instr_d);
    else
      isAllowed = is_valid_ending_instruction_att(ending_instr_d);
  }
  return isAllowed;
}

bool Rop_finder::is_valid_instruction(DISASM& ending_instr_d) {
  Int32 branch_type = ending_instr_d.Instruction.BranchType;
  return (
    /*
    Work Around, BeaEngine in x64 mode disassemble "\xDE\xDB" as an instruction without disassembly
    Btw, this is not the only case!
    */
    ending_instr_d.CompleteInstr[0] != 0 &&
    branch_type != RetType &&
    branch_type != JmpType &&
    branch_type != CallType &&
    branch_type != JE &&
    branch_type != JB &&
    branch_type != JC &&
    branch_type != JO &&
    branch_type != JA &&
    branch_type != JS &&
    branch_type != JP &&
    branch_type != JL &&
    branch_type != JG &&
    branch_type != JNE &&
    branch_type != JNB &&
    branch_type != JNC &&
    branch_type != JNO &&
    branch_type != JECXZ &&
    branch_type != JNA &&
    branch_type != JNS &&
    branch_type != JNP &&
    branch_type != JNL &&
    branch_type != JNG &&
    branch_type != JNB &&
    strstr(ending_instr_d.CompleteInstr, "far") == NULL
    );
}

std::multiset<Gadget*, Gadget::Sort> Rop_finder::get_test_result(std::string test_code) {
  std::multiset<Gadget*, Gadget::Sort> gadgets_found;
  unsigned long long va_section = 0x1000;

  std::multiset<Gadget*> gadgets = find_gadget_in_memory(test_code.c_str(),
    test_code.size(), va_section, m_depth);
  std::cout << gadgets.size() << " found." << std::endl << std::endl;
  for (std::multiset<Gadget*>::iterator it_g = gadgets.begin(); it_g != gadgets.end(); ++it_g)
    if ((*it_g)->get_code() != "\xC3")
      gadgets_found.insert(*it_g);
  return gadgets_found;
}

std::multiset<Gadget*> Rop_finder::find_gadget_in_memory(const char* data, 
  unsigned long long size, unsigned long long vaddr, uint32_t m_depth_) {
  m_depth = m_depth_;
  std::multiset<Gadget*> merged_gadgets;
  DISASM dis;
  init_disasm_struct(dis);

  for (unsigned long long offset = 0; offset < size; ++offset) {
    dis.EIP = (UIntPtr)(data + offset);
    dis.VirtualAddr = SafeAddU64(vaddr, offset);
    dis.SecurityBlock = (UInt32)(size - offset + 1);

    int len = Disasm(&dis);

    /* I guess we're done ! */
    if (len == OUT_OF_BLOCK)
      break;

    /* OK this one is an unknow opcode, goto the next one */
    if (len == UNKNOWN_OPCODE)
      continue;

    if (is_valid_ending_instruction(dis)) {
      DISASM ret_instr;
      std::string opcodes_string((char*)(data + offset), len);
      /* Okay I found a RET ; now I can build the gadget */
      ret_instr = dis;

      /* Do not forget to add the ending instruction only -- we give to the user all gadget with < depth instruction */
      std::list<Instruction> only_ending_instr;

      only_ending_instr.push_back(Instruction(std::string(ret_instr.CompleteInstr),
        std::string(ret_instr.Instruction.Mnemonic), opcodes_string,offset, len ));

      Gadget *gadget_with_one_instr = new (std::nothrow) Gadget(cpu_info);
      if (gadget_with_one_instr == NULL)
        printf("Cannot allocate gadget_with_one_instr");

      /* the gadget will only have 1 ending instruction */
      gadget_with_one_instr->add_instructions(only_ending_instr, vaddr);
      merged_gadgets.insert(gadget_with_one_instr);

      /* if we want to see gadget with more instructions */
      if (m_depth > 0) {
        std::multiset<Gadget*> gadgets = find_all_gadget_from_ret(data, vaddr, ret_instr, len);
        for (std::multiset<Gadget*>::iterator it = gadgets.begin(); it != gadgets.end(); ++it)
          merged_gadgets.insert(*it);
      }
    }
  }
  return merged_gadgets;
}

const cpu_info::CPU_description& Rop_finder::get_arch_info() {
  return cpu_info;
}

} //namespace findrop_helper
