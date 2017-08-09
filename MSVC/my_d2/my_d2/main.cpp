/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "main.hpp"
#include "program.hpp"
#include "toolbox.hpp"
#include "beaengine\beaengine.h"

#include <iostream>
#include <exception>
#include <cstdlib>
#include <cstring>

#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL

int main(int argc, char* argv[]) { 
	std::string program_path("calc.exe");
	CPU::E_CPU arch(CPU::CPU_UNKNOWN);
	arch = CPU::CPU_x86;
	//arch = CPU::CPU_x64;            
	Program p(program_path, arch);
	unsigned int disass_engine_display_option = 0;
  int num_gadget = 2;
	std::multiset<Gadget*, Gadget::Sort> all_gadgets = p.find_gadgets(num_gadget, disass_engine_display_option);
	std::cout << "A total of " << all_gadgets.size() << " gadgets found." << std::endl;
  bool unique = false;
	if(unique)	{
		std::map<std::string, Gadget*> unique_gadgets = only_unique_gadgets(all_gadgets);
		/* Now we walk the gadgets found and set the VA */
		for(std::map<std::string, Gadget*>::iterator it = unique_gadgets.begin(); it != unique_gadgets.end(); ++it)	{                
      //write to file here III
			/* Avoid mem leaks */
			delete it->second;
		}
		unique_gadgets.clear();
	}	else {
		for(std::multiset<Gadget*, Gadget::Sort>::iterator it = all_gadgets.begin(); it != all_gadgets.end(); ++it)	{
      //write to file here III
		}
	}
  bool find_hex = false;
	if(find_hex) { //try to find a pointer on a specific hex
		unsigned int size = 0;
    char test_hex[] = "0x90";
		unsigned char* hex_values = string_to_hex(test_hex, &size);
             
		if(hex_values == NULL)
			RAISE_EXCEPTION("Cannot allocate hex_values");

		p.search_and_display(hex_values, size);
		delete[] hex_values;
	}
  bool find_int = false;
	if(find_int)	{ //try to find a pointer on a specific integer value
    char test_value[] = "10";
		unsigned int val = std::strtoul(test_value, NULL, 16);
		p.search_and_display((const unsigned char*)&val, sizeof(unsigned int));
	}
  return 0;
}
