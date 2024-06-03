#include <capstone/capstone.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

#define INT3 0xCC
const size_t PEEK_SIZE = 5;

// 64-bit static-nopie programs on x86-64. (little-endian)
// ptrace return value is "long", which is 8 bytes in 64-bit system.

// function prototypes
void load_program(char *program);  // load [program]
void print_disass_instr(uint64_t address, const uint8_t *code, size_t code_size);
void bytes_to_hex_string(char *bytes, const uint8_t *data, int size);
void load_text_section_from_elf(const char *path, uint8_t **textptr, uint64_t *n, uint64_t *sh_addr);
Elf64_Shdr get_section_hdr64(FILE *file_ptr, Elf64_Ehdr elf_hdr, Elf64_Off n);
// functions for debugger
void single_step();                                                // si
void continue_execution();                                         // cont
void set_breakpoint(uint64_t address);                             // break [addr]
void info_breakpoints();                                           // info break
void delete_breakpoint(int id);                                    // delete [id]
void info_register();                                              // info reg
void patch_memory(uint64_t address, uint64_t hex_value, int len);  // patch [hex address] [hex value] [len]

pid_t child_pid;
int child_status;
struct user_regs_struct regs;

uint8_t *textptr = NULL;       // allocated memory for text section
uint64_t text_size = 0;        // text section size
uint64_t text_start_addr = 0;  // text section start address in memory

unordered_map<uint64_t, char> breakpoints; // address, original data
map<uint64_t, int> breakpoints_id; // address, id
int breakpoint_count = 0;
uint64_t restore_breakpoint_address = 0;

unordered_set<int> syscall_enter_number;

void load_program(char *program) {
    child_pid = fork();
    if (child_pid == 0) {                           // child process
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {  // PTRACE_TRACEME: 要求 parent 追蹤自己
            perror("ptrace");
            exit(1);
        }
        execl(program, program, nullptr);
        perror("execl");
        exit(1);
    } else {  // parent process
        if (waitpid(child_pid, &child_status, 0) < 0) {
            perror("waitpid");
            exit(1);
        }
        ptrace(PTRACE_SETOPTIONS, child_pid, 0,
               PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);  // 當 chile 結束時，結束 parent
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        printf("** program '%s' loaded. entry point %p.\n", program, (void *)regs.rip);
    }
}

void bytes_to_hex_string(char *bytes, const uint8_t *data, int size) {
    for (int i = 0; i < size; i++) {
        // %2.2x : 2 characters, 0-padded, i * 3 : 3 characters per byte
        snprintf(&bytes[i * 3], 4, "%2.2x ", data[i]);
    }
}

void print_disass_instr(const uint8_t *code, size_t code_size, uint64_t address) {
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize capstone engine!\n");
        return;
    }

    size_t count = cs_disasm(handle, code, code_size, address, PEEK_SIZE, &insn);
    if (count <= 0) {
        printf("ERROR: Failed to disassemble given code!\n");
        cs_close(&handle);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        char bytes[128] = "";
        bytes_to_hex_string(bytes, insn[i].bytes, insn[i].size);
        // PRIx64 : 64-bit hexadecimal, %-32s : left-justified, 32 characters
        printf("\t%" PRIx64 ": %-32s%s\t  %s\n",
               insn[i].address,   // machine code 的地址
               bytes,             // machine code 的十六進制表示
               insn[i].mnemonic,  // machine code 的助記符 (instruction) ex: mov, add, sub
               insn[i].op_str);   // machine code 的操作數 (operand) ex: rax, rbx, 0x1234
    }
    cs_free(insn, count);
    if (count < PEEK_SIZE) printf("** the address is out of the range of the text section.\n");

    cs_close(&handle);
}

void single_step() {
    ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
    waitpid(child_pid, &child_status, 0);
}
void continue_execution() {
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    waitpid(child_pid, &child_status, 0);
}

void set_breakpoint(uint64_t address) {
    // already set breakpoint
    if (breakpoints.find(address) != breakpoints.end()) {
        printf("** breakpoint at 0x%lx already exists.\n", address);
        return;
    }

    uint64_t bp = ptrace(PTRACE_PEEKTEXT, child_pid, address, 0);
    char *bp_ptr = (char *)&bp;
    breakpoints[address] = bp_ptr[0];
    breakpoints_id[address] = breakpoint_count++;
    uint64_t data_int3 = (bp & 0xFFFFFFFFFFFFFF00) | INT3;
    // printf("data_int3: 0x%lx\n", data_int3);
    ptrace(PTRACE_POKETEXT, child_pid, address, data_int3);

    printf("** set a breakpoint at 0x%lx.\n", address);
}

void info_breakpoints() {
    printf("Num\tAddress\n");
    for (auto &breakpoint : breakpoints_id) {
        printf("%d\t0x%lx\n", breakpoint.second, breakpoint.first);
    }
}

void delete_breakpoint(int id) {
    for (auto &breakpoint : breakpoints) {
        if (breakpoints_id[breakpoint.first] == id) {
            // restore the original data
            uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, breakpoint.first, 0);
            // uint64_t index = regs.rip - text_start_addr;  // 目前指令在 text section 的 index
            // x86 arch: little-endian (低位元組在前) 0xcc -> 0xcc00000000000000
            // data[0] 是 0xcc，要換回原本的指令
            ((char *)&data)[0] = breakpoints[breakpoint.first];
            // printf("=== restore data: 0x%lx\n", data);
            // printf("breakpoint.first:  0x%lx\n", breakpoint.first);
            // printf("===== breakpoints[breakpoint.first]: %x\n", breakpoints[breakpoint.first]);
            ptrace(PTRACE_POKETEXT, child_pid, breakpoint.first, data);
            
            // remove the breakpoint (should remove id first, or breakpoint.first will be invalid)
            int x = breakpoints_id.erase(breakpoint.first);
            int y = breakpoints.erase(breakpoint.first);
            if (x == 0 || y == 0) {
                printf("ERROR: delete breakpoint %d failed.\n", id);
                return;
            }
            printf("** delete breakpoint %d.\n", id);

            if ((restore_breakpoint_address != 0) && (breakpoint.first == restore_breakpoint_address)) {
                printf("** restore bp at 0x%lx has been delete. no need to restore that bp\n",
                       restore_breakpoint_address);
                restore_breakpoint_address = 0;
            }

            return;
        }
    }
    printf("** breakpoint %d does not exist.\n", id);
}

void info_register() {
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

/*
Patch memory starts at the address with the value of len bytes.
The value will be integer value represented in hex and its length (in byte) is determined by the len,
which can be either 1, 2, 4, or 8.
*/
void patch_memory(uint64_t address, uint64_t patch_hex_value, int len) {
    // If patch on an instruction that has been set as a breakpoint,
    // the breakpoint should still exist, but the original instruction should be patched.
    uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, address, 0);
    // printf("=== data:        0x%lx\n", data);
    uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (8 * (8 - len));

    for (int i = 0; i < len; i++) {
        // printf("=== data[%d]: 0x%x\n", i, ((int8_t *)&data)[i] & 0xFF);
        if ((((int8_t *)&data)[i] & 0xFF) == 0xcc) {
            // printf("** the address is a breakpoint, skip it.\n");
            ((int8_t *)&mask)[i] = 0x00;
        }
    }
    // printf("=== mask:        0x%lx\n", mask);
    uint64_t data_masked = data & ~mask;
    // printf("=== data_masked: 0x%lx\n", data_masked);
    uint64_t data_patched = data_masked | (patch_hex_value & mask);
    // printf("=== data_patch : 0x%lx\n", data_patched);
    ptrace(PTRACE_POKETEXT, child_pid, address, data_patched);

    // but the original instruction should be patched
    for (int i = 0; i < len; i++) {
        textptr[address - text_start_addr + i] = (patch_hex_value >> (i * 8)) & 0xFF;
    }

    printf("** patch memory at address 0x%lx.\n", address);
}

void restore_breakpoint() {
    // 將原本的 breakpoint 恢復，下一次再執行到 breakpoint 時，才會停下來
    // printf("*** restore breakpoint at 0x%lx.\n", restore_breakpoint_address);
    uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, restore_breakpoint_address, 0);
    uint64_t data_int3 = (data & 0xFFFFFFFFFFFFFF00) | INT3;
    ptrace(PTRACE_POKETEXT, child_pid, restore_breakpoint_address, data_int3);
    restore_breakpoint_address = 0;
}

// The program execution should break at every system call instruction unless it hits a breakpoint.
// If it hits a breakpoint, output ** hit a breakpoint at [hex address].
// If it enters a syscall, output ** enter a syscall([nr]) at [hex address].
// If it leaves a syscall, output ** leave a syscall([nr]) = [ret] at [hex address].
void syscall() {
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    waitpid(child_pid, &child_status, 0);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0); // for automation testing (do not buffer the output)

    char command[256];
    
    if (argc > 1) {
        load_program(argv[1]);
        load_text_section_from_elf(argv[1], &textptr, &text_size, &text_start_addr);
        // regs.rip - text_start_addr : 目前指令在 text section 的 index
        print_disass_instr(&textptr[regs.rip - text_start_addr], text_size - (regs.rip - text_start_addr), regs.rip);
    } else {
        printf("(sdb) ");
        while (1) {
            scanf("%s", command);
            if (strcmp(command, "load") == 0) {
                char program[256];
                scanf("%s", program);
                load_program(program);
                load_text_section_from_elf(program, &textptr, &text_size, &text_start_addr);
                print_disass_instr(&textptr[regs.rip - text_start_addr], text_size - (regs.rip - text_start_addr),
                                   regs.rip);
                break;
            } else {
                printf("** please load a program first.\n");
            }
            printf("(sdb) ");
        }
    }

    while (1) {
        printf("(sdb) ");
        scanf("%s", command);

        vector<string> commands = {"info", "break", "delete", "patch", "exit", "si", "cont", "syscall"};
        if (find(commands.begin(), commands.end(), command) == commands.end()) {
            printf("** unknown command.\n");
            continue;
        }

        // instruction dont need to print_disass_instr
        if (strcmp(command, "info") == 0) {
            scanf("%s", command);
            if (strcmp(command, "reg") == 0) {  // info reg
                info_register();
            } else if (strcmp(command, "break") == 0) {  // info break
                if (breakpoints.size() > 0) {
                    info_breakpoints();
                } else {
                    printf("** no breakpoints.\n");
                }
            } else {
                printf("** unknown command.\n");
            }
            continue;
        } else if (strcmp(command, "break") == 0) {  // break [addr]
            uint64_t address;
            scanf("%lx", &address);
            set_breakpoint(address);
            continue;
        } else if (strcmp(command, "delete") == 0) {  // delete [id]
            int id;
            scanf("%d", &id);
            delete_breakpoint(id);
            continue;
        } else if (strcmp(command, "patch") == 0) {  // patch [hex address] [hex value] [len]
            uint64_t address;
            uint64_t hex_value;
            int len;
            scanf("%lx %lx %d", &address, &hex_value, &len);
            patch_memory(address, hex_value, len);
            continue;
        }

        else if (strcmp(command, "exit") == 0) {  // exit
            break;
        }

        // ------------------------------------------------------------------- //
        // instruction need to print_disass_instr and check if hit breakpoint  //

        int step = 0;                      // 已經執行完 breakpoint 指令代表
        if (strcmp(command, "si") == 0) {  // si
            if (restore_breakpoint_address != 0) {
                single_step();
                restore_breakpoint();
            } else {
                single_step();
            }
            step = 0;  // si 是到下一個指令，再檢查是否是 breakpoint，reg.rip 就是現在要檢查的指令
        } else if (strcmp(command, "cont") == 0) {  // cont
            if (restore_breakpoint_address != 0) {
                // 先走一步，執行 restored 的 instruction
                single_step();
                // 再 restore breakpoint
                restore_breakpoint();
            }
            continue_execution();
            step = 1;                                  // cont 是撞到 int3 後停下來，還沒執行完 int3 那行
        } else if (strcmp(command, "syscall") == 0) {  // syscall
            syscall();
            step = 1;
        }

        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        if (WIFSTOPPED(child_status)) {
            long data = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip - step, 0);

            if ((data & 0xFF) == INT3 && breakpoints.find(regs.rip - step) != breakpoints.end()){
                regs.rip -= step;
                printf("** hit a breakpoint at 0x%llx.\n", regs.rip);
                uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, 0);

                uint64_t index = regs.rip - text_start_addr;  // 目前指令在 text section 的 index
                // x86 arch: little-endian (低位元組在前) 0xcc -> 0xcc00000000000000
                // data[0] 是 0xcc，要換回原本的指令
                // printf("=== before original data: 0x%lx\n", data); // 0xebae589cc
                ((char *)&data)[0] = textptr[index];
                // printf("=== after original data: 0x%lx\n", data); // 0xebae58948

                ptrace(PTRACE_POKETEXT, child_pid, regs.rip, data);
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

                restore_breakpoint_address = regs.rip;
            }

            else if (WSTOPSIG(child_status) & 0x80) {
                regs.rip -= 2;  // syscall's instruction length is 2 bytes, so go back 2 bytes
                if (syscall_enter_number.find(regs.orig_rax) == syscall_enter_number.end()) {
                    printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip);
                    syscall_enter_number.insert(regs.orig_rax);
                } else {
                    printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip);
                    syscall_enter_number.erase(regs.orig_rax);
                }
            }
        }

        if (WIFEXITED(child_status)) {
            printf("** the target program terminated.\n");
            break;
        }

        print_disass_instr(&textptr[regs.rip - text_start_addr], text_size - (regs.rip - text_start_addr), regs.rip);
    }

    free(textptr);
    return 0;
}

Elf64_Shdr get_section_hdr64(FILE *file_ptr, Elf64_Ehdr elf_hdr, Elf64_Off n) {
    Elf64_Shdr section_hdr;
    fseeko(file_ptr, elf_hdr.e_shoff + n * elf_hdr.e_shentsize, SEEK_SET);
    fread(&section_hdr, sizeof(section_hdr), 1, file_ptr);
    return section_hdr;
}

void load_text_section_from_elf(const char *path, uint8_t **textptr, uint64_t *n, uint64_t *sh_addr) {
    FILE *file_ptr = fopen(path, "rb");

    unsigned char e_ident[EI_NIDENT];
    fread(e_ident, 1, EI_NIDENT, file_ptr);
    if (strncmp((char *)e_ident,
                "\x7f"
                "ELF",
                4) != 0) {
        printf("ELFMAGIC mismatch!\n");
        fclose(file_ptr);
        return;
    }

    if (e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr elf_hdr;
        memcpy(elf_hdr.e_ident, e_ident, EI_NIDENT);
        fread((char *)&elf_hdr + EI_NIDENT, sizeof(elf_hdr) - EI_NIDENT, 1, file_ptr);

        Elf64_Off shstrndx;
        if (elf_hdr.e_shstrndx == SHN_XINDEX) {
            shstrndx = get_section_hdr64(file_ptr, elf_hdr, 0).sh_link;
        } else {
            shstrndx = elf_hdr.e_shstrndx;
        }

        Elf64_Shdr section_hdr_string_tbl_hdr = get_section_hdr64(file_ptr, elf_hdr, shstrndx);
        char *const section_hdr_string_tbl = (char *)malloc(section_hdr_string_tbl_hdr.sh_size);
        fseeko(file_ptr, section_hdr_string_tbl_hdr.sh_offset, SEEK_SET);
        fread(section_hdr_string_tbl, 1, section_hdr_string_tbl_hdr.sh_size, file_ptr);

        Elf64_Off shnum;
        if (elf_hdr.e_shnum == SHN_UNDEF) {
            shnum = get_section_hdr64(file_ptr, elf_hdr, 0).sh_size;
        } else {
            shnum = elf_hdr.e_shnum;
        }

        for (Elf64_Off i = 0; i < shnum; i++) {
            Elf64_Shdr section_hdr = get_section_hdr64(file_ptr, elf_hdr, i);
            if (strcmp(".text", section_hdr_string_tbl + section_hdr.sh_name) == 0) {
                // 為 .text section 分配記憶體
                *textptr = (uint8_t *)malloc(section_hdr.sh_size);
                // 移動檔案指標到 .text section 的起始位址
                fseeko(file_ptr, section_hdr.sh_offset, SEEK_SET);
                // 讀取 .text section 的內容
                fread(*textptr, 1, section_hdr.sh_size, file_ptr);
                // 設定 .text section 的大小
                *n = section_hdr.sh_size;
                // 設定 .text section 的起始位址
                *sh_addr = section_hdr.sh_addr;
                break;
            }
        }
        free(section_hdr_string_tbl);
    }
    fclose(file_ptr);
}