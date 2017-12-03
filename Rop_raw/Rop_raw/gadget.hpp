#ifndef GADGET_HPP
#define GADGET_HPP

#include <list>
#include <string>
#include <vector>
#include <map>
#include <iterator>
#include "instruction.hpp"
#include "Emulator.h"
#include "utils.h"
#include <z3++.h>
/*! \class Gadget
*
* A gadget is a sequence of instructions that ends by an ending instruction (ret/call/jmp)
* In order, to keep in memory only *unique* gadgets, each gadget holds a set of offset where you can find
* the same one.
*/

enum class action : int32_t {MOV, STACK};

//TODO: SMT -gadget make as child class
class Gadget { // as RealGadget in script
 public:
  Gadget(uc_mode uc_mode_, uc_arch uc_arch_);
  ~Gadget(void);
  /*!
  *  \brief Get the entire disassembly of your gadget
  *  \return the disassembly
  */
  std::string get_disassembly(void) const;

  /*!
  *  \brief Get the size of your gadget
  *  \return the size of the whole gadget
  */
  unsigned int get_size(void) const;

  /*!
  *  \brief Add a list of instructions to your gadget ; don't forget it's back pushed in the instruction list
  *   It means the first instruction inserted will be the address of the gadget
  *
  *  \param instrs: It is a list of Instruction to create our gadget (NB: the method copy in its memory those instructions for futur usage)
  *  \param va_section: It is the va section of the instructions ; a bit weird to pass it here yeah
  */
  void add_instructions(std::list<Instruction> &instrs, unsigned long long va_section);

  /*!
  *  \brief Get the size of your gadget
  *  \return the size of the whole gadget
  */
  std::list<Instruction*> get_instructions(void);

  /*!
  *  \brief Get the first offset of this gadget (first offset because a gadget instance stores other offset with the same disassembly in memory)
  *  \return the offset (relative to m_va_section)
  */
  unsigned long long get_first_offset(void) const;

  /*!
  *  \brief Get the first va section of this gadget (first offset because a gadget instance stores other offset with the same disassembly in memory)
  *  \return the va section
  */
  unsigned long long get_first_va_section(void) const;

  /*!
  *  \brief Get the first absolute address of this gadget
  *  \return the absolute address (computed like this: m_va_section + offset)
  */
  unsigned long long get_first_absolute_address(void) const;

  /*!
  *  \brief Get the number of other equivalent gadget
  *  \return the number of the same gadget in memory
  */
  size_t get_nb(void) const;

  /*!
  *  \brief Add the offset where you can find the same gadget
  *
  *  \param offset: the offset where you can find the same gadget
  */
  void add_new_one(unsigned long long offset, unsigned long long va_section);

  /*!
  *  \brief Get the ending instruction of this gadget
  *  \return a pointer on the ending instruction
  */
  Instruction* get_ending_instruction(void);

  /*!
  * \brief This structure can be used for sorting Gadgets instance
  * \return
  */
  struct Sort {
    bool operator()(const Gadget *g, const Gadget *d) const {
      return g->get_disassembly() < d->get_disassembly();
    }
  };
  cpu::CPU_description get_arch_info() { return emu.get_description(); };
  void analize();
  void map();
 private:
  std::map <uc_x86_reg, std::vector<std::string>> regs_condition;
  int mov = 0; //clean stack on N bytes
  ropperdis::Emulator emu;
  z3::context z3_context;
  int address;
  std::map<std::string, z3::expr_vector> z3_state;
  bool is_analized = false;
  std::string m_disassembly; /*!< the disassembly of the gadget*/
  unsigned int m_size; /*!< the size in byte of the gadget*/
  std::list<Instruction*> m_instructions; /*!< the list of the different instructions composing the gadget*/
  std::vector<unsigned long long> m_offsets; /*!< the vector which stores where you can find the same gadget ; those offsets are relative to m_va_section*/
  std::vector<unsigned long long> m_va_sections; /*!< the virtual address of the section where the instructions were found*/
  std::map<std::string, z3::expr_vector> start_map();
  std::map<std::string, z3::expr_vector> smt_map();
  std::map<std::string, z3::expr_vector> gadget_map();

};

#endif
