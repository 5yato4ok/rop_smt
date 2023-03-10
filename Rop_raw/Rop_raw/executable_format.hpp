#ifndef EXECUTABLE_FORMAT_H
#define EXECUTABLE_FORMAT_H

#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include "section.hpp"
#include "pe_struct.hpp"
#include "unicorn\unicorn.h"

class ExecutableFormat {
 public:
  enum E_ExecutableFormat {
    FORMAT_PE,
    FORMAT_ELF,
    FORMAT_UNKNOWN
 };
 
  explicit ExecutableFormat(void);
  std::string get_class_name(void);
  std::vector<Section*> get_executables_section(std::fstream & file);
  uc_mode extract_information_from_binary(std::fstream &file);
  template<class T>
  void init_properly_PELayout() {
    m_pPELayout = new (std::nothrow) PELayout<T>;
    if (m_pPELayout == NULL)
      printf("m_PELayout allocation failed");
  }
  PortableExecutableLayout* m_pPELayout;
};

#endif
