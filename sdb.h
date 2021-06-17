#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <elf.h>

#define STATE_NONE 0
#define STATE_LOADED 1
#define STATE_RUNNING 2

using namespace std;

struct breakpoint 
{
    int id;
    unsigned long long addr;
    unsigned long code;
};
vector<string> reglist { "rax", "rbx", "rcx", "rdx",
                         "r8", "r9", "r10", "r11",
                         "r12", "r13", "r14", "r15",
                         "rdi", "rsi", "rbp", "rsp",
                         "rip", "flags" };

unsigned long entry_point(string filename);
unsigned long long s2ull(string s);
bool checkargs(int cmdlineLength, int n);
int checkstatus();
void ptrace_getregs();
unsigned long patch_code(unsigned long long addr, unsigned long code);
string get_bytes(unsigned char *bytes, int size);
void capstone_disasm(unsigned long long &addr, unsigned char *code);
void runcmd(string line);

void bp(unsigned long long addr);
void deletebp();
void disasm();
void dump();
void vmmap();
void list();
void load();
void start();
void run();
void si();
void cont();
void get(string reg);
void getregs();
void set(string reg, unsigned long long value);
void help();