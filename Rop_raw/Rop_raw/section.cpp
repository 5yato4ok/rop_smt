#include "section.hpp"
#include "safeint.hpp"

#include <cstring>

Section::Section(const char *name, const unsigned long long offset, const unsigned long long vaddr, const unsigned long long size)
: m_name(name), m_offset(offset), m_size(size), m_section(NULL), m_vaddr(vaddr)
{
}

Section::~Section(void) {
  if(m_section != NULL)
    delete [] m_section;
}

std::string Section::get_name(void) const {
  return m_name;
}

unsigned long long Section::get_size(void) const {
  return m_size;
}

unsigned char* Section::get_section_buffer(void) const {
  return m_section;
}

unsigned long long Section::get_offset(void) const {
  return m_offset;
}

std::list<unsigned long long> Section::search_in_memory(const unsigned char *val, const unsigned int size) {
  std::list<unsigned long long> val_found;

  for(unsigned long long offset = 0; offset < m_size; ++offset)
      if(std::memcmp(m_section + offset, val, size) == 0)
          val_found.push_back(offset);

  return val_found;
}

void Section::set_props(Properties props) {
    m_props = props;
}

std::streampos Section::get_file_size(std::fstream &file) {
  std::streampos backup = file.tellg();

  file.seekg(0, std::ios::beg);
  std::streampos fsize = file.tellg();

  file.seekg(0, std::ios::end);
  fsize = file.tellg() - fsize;

  file.seekg(backup);
  return fsize;
}

void Section::dump(std::fstream &file)
{
    /* NB: std::streampos performs unsigned check */
    unsigned long long fsize = get_file_size(file);
    if(SafeAddU64(m_offset, m_size) > fsize)
        printf("Your file seems to be wrong");

    std::streampos backup = file.tellg();

    file.seekg((unsigned int)m_offset, std::ios::beg);
    m_section = new (std::nothrow) unsigned char[(unsigned int)m_size];
    if(m_section == NULL)
        printf("Cannote allocate a section.");

    file.read((char*)m_section, (unsigned int)m_size);

    file.seekg(backup);
}

unsigned long long Section::get_vaddr(void) const
{
    return m_vaddr;
}
