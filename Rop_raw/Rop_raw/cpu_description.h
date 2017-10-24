#define AMD64_BITS 64
#define instruction_pointer "rip"
#define stack_pointer "rsp"

#define address_mask 0x0000007fffffffff
#define page_mask 0x0000007ffffff000
#define page_size 0x1000

#define return_instructions "\xc3"
#define alignment 1

//TODO: add description for x86