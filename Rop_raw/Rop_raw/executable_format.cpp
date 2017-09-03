#include "executable_format.hpp"
#include "pe_struct.hpp"

ExecutableFormat::ExecutableFormat(void)
{
}


//Just for demonstration
std::string ExecutableFormat::get_class_name(void) {
  return std::string("x86");
}

ExecutableFormat::E_CPU ExecutableFormat::extract_information_from_binary(std::fstream &file) {
    RP_IMAGE_DOS_HEADER imgDosHeader = {0};
    RP_IMAGE_NT_HEADERS32 imgNtHeaders32 = {0};
    E_CPU cpu = E_CPU::CPU_UNKNOWN;

    std::cout << "Loading PE information.." << std::endl;

    /* Remember where the caller was in the file */
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char*)&imgDosHeader, sizeof(RP_IMAGE_DOS_HEADER));

    file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
    /* 
     * Yeah, in fact, we don't know yet if it is a x86/x64 PE ; 
     * so just we grab the signature field, FILE_HEADER and the field Magic 
     */
    file.read((char*)&imgNtHeaders32, sizeof(unsigned int) + sizeof(RP_IMAGE_FILE_HEADER) + sizeof(unsigned int));
    
    if (imgNtHeaders32.Signature != RP_IMAGE_NT_SIGNATURE) {
      printf("This file doesn't seem to be a correct PE (bad IMAGE_NT_SIGNATURE)");
      return CPU_UNKNOWN;
    }

    switch(imgNtHeaders32.OptionalHeader.Magic)
    {
        case RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
            cpu = E_CPU::CPU_x86;
            /* Ok, now we can allocate the good version of the PE Layout */
            /* The 32bits version there! */
            init_properly_PELayout<x86Version>();
            break;
        }

        case RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
            cpu = E_CPU::CPU_x64;
            init_properly_PELayout<x64Version>();
            break;
        }

        default:
            printf("Cannot determine the CPU type");
            return CPU_UNKNOWN;
    }
    
    /* Now we can fill the structure */
    std::memcpy(&m_pPELayout->imgDosHeader, &imgDosHeader, m_pPELayout->get_image_dos_header_size());

    m_pPELayout->fill_nt_structures(file);

    file.seekg(off);
    return cpu;
}

std::vector<Section*> ExecutableFormat::get_executables_section(std::fstream & file) {
  std::vector<Section*> exec_sections;

  for (std::vector<RP_IMAGE_SECTION_HEADER*>::iterator it = m_pPELayout->imgSectionHeaders.begin();
    it != m_pPELayout->imgSectionHeaders.end();
    ++it) {
    if ((*it)->Characteristics & RP_IMAGE_SCN_MEM_EXECUTE) {
      Section *tmp = new (std::nothrow) Section(
        (*it)->get_name().c_str(),
        (*it)->PointerToRawData,
        /* in the PE, this field is a RVA, so we need to add it the image base to have a VA */
        m_pPELayout->get_image_base() + (*it)->VirtualAddress,
        (*it)->SizeOfRawData
      );

      if (tmp == NULL) {
        printf("Cannot allocate a section");
        break;
      }

      tmp->dump(file);

      tmp->set_props(Section::Executable);

      exec_sections.push_back(tmp);
    }
  }
  return exec_sections;
}
