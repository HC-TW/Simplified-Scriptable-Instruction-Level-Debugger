#include "sdb.h"

using namespace std;

int state = STATE_NONE;
string program;
pid_t child = 0;
struct user_regs_struct regs_struct = {};
map<string, unsigned long long *> regs;
int bpid = 0;
int meetbp = -1;
vector<struct breakpoint> breakpoints;

unsigned long entry_point(string filename)
{
    Elf64_Ehdr *elf64ehdr;
    elf64ehdr = new Elf64_Ehdr[1];
    ifstream file(filename);
    if (!file)
        return -1;
    file.seekg(0);
    file.read((char *)elf64ehdr, sizeof(Elf64_Ehdr));
    
    return elf64ehdr->e_entry;
}

unsigned long long s2ull(string s)
{
    if (s.find("0x") == 0)
        return stoull(s, 0, 16);
    else if (s.find("0") == 0)
        return stoull(s, 0, 8);
    else
        return stoull(s);
}

bool checkargs(int cmdlineLength, int n)
{
    if (cmdlineLength == n)
        return true;
    else
        cerr << "** syntax error." << endl;
    return false;
}

// Not SIGTRAP: -1
// meet breakpoint before: 0
// meet breakpoint now: 1
int checkstatus()
{
    int status;
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status))
    {
        if (WSTOPSIG(status) != SIGTRAP)
            return -1;

        if (meetbp != -1)
            return 0;

        ptrace_getregs();
        for (auto &&bp : breakpoints)
        {
            if (bp.addr == *regs["rip"] - 1)
            {
                unsigned long long tempaddr = bp.addr;
                meetbp = bp.id;
                cout << "** breakpoint @ ";
                capstone_disasm(tempaddr, (unsigned char *)&bp.code);
                patch_code(bp.addr, bp.code);
                (*regs["rip"])--;
                ptrace(PTRACE_SETREGS, child, 0, &regs_struct);
                return 1;
            }
        }
    }
    else if (WIFEXITED(status) || WIFSIGNALED(status))
    {
        if (WIFEXITED(status))
            cout << "** child process " << dec << child << " terminiated normally (code " << WEXITSTATUS(status) << ")" << endl;
        else
            cout << "** child process " << dec << child << " was terminiated by signal " << WTERMSIG(status) << endl;
        child = 0;
        state = STATE_LOADED;
    }
    return -1;
}

void ptrace_getregs()
{
    ptrace(PTRACE_GETREGS, child, NULL, &regs_struct);
    regs["rax"] = &regs_struct.rax;
    regs["rbx"] = &regs_struct.rbx;
    regs["rcx"] = &regs_struct.rcx;
    regs["rdx"] = &regs_struct.rdx;
    regs["r8"] = &regs_struct.r8;
    regs["r9"] = &regs_struct.r9;
    regs["r10"] = &regs_struct.r10;
    regs["r11"] = &regs_struct.r11;
    regs["r12"] = &regs_struct.r12;
    regs["r13"] = &regs_struct.r13;
    regs["r14"] = &regs_struct.r14;
    regs["r15"] = &regs_struct.r15;
    regs["rdi"] = &regs_struct.rdi;
    regs["rsi"] = &regs_struct.rsi;
    regs["rbp"] = &regs_struct.rbp;
    regs["rsp"] = &regs_struct.rsp;
    regs["rip"] = &regs_struct.rip;
    regs["flags"] = &regs_struct.eflags;
}

unsigned long patch_code(unsigned long long addr, unsigned long code)
{
    /* get original text */
    unsigned long ori_code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    /* patch code */
    if (ptrace(PTRACE_POKETEXT, child, addr, (ori_code & 0xffffffffffffff00) | (code & 0xff)) != 0)
        perror("** ptrace(POKETEXT)");
    return ori_code;
}

string get_bytes(unsigned char *bytes, int size)
{
    string s, byte;
    for (int i = 0; i < size; i++)
    {
        stringstream ss;
        ss << setfill('0') << setw(2) << hex << (int)bytes[i];
        ss >> byte;
        s += byte + " ";
    }
    s.pop_back();
    return s;
}

void capstone_disasm(unsigned long long &addr, unsigned char *code)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    count = cs_disasm(handle, code, 8, addr, 1, &insn);
    if (count > 0)
    {
        cout << right << setw(12) << hex << insn[0].address << ": "
             << left << setw(31) << get_bytes(insn[0].bytes, insn[0].size)
             << setw(7) << insn[0].mnemonic << insn[0].op_str << endl;

        addr += insn[0].size;
        cs_free(insn, count);
    }
    cs_close(&handle);
}

void bp(unsigned long long addr)
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    breakpoints.push_back((struct breakpoint){bpid++, addr, patch_code(addr, 0xcc)});
}

void deletebp(int bpid)
{
    for (auto it = breakpoints.begin(); it != breakpoints.end(); it++)
    {
        if ((*it).id == bpid)
        {
            patch_code((*it).addr, (*it).code);
            breakpoints.erase(it);
            cout << "** breakpoint " << dec << bpid << " deleted." << endl;
            return;
        }
    }
    cerr << "** breakpoint " << bpid << " doesn't exist." << endl;
}

void disasm(unsigned long long addr)
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }

    unsigned long code;
    for (int i = 0; i < 10; i++)
    {
        code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
        for (auto &&bp : breakpoints)
        {
            if (bp.addr == addr)
            {
                code = bp.code;
                break;
            }
        }
        capstone_disasm(addr, (unsigned char *)&code);
    }
}

void dump(unsigned long long addr)
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }

    for (int i = 0; i < 5; i++)
    {
        string s;
        cout << right << setw(12) << hex << addr << ": ";
        for (int i = 0; i < 2; i++)
        {
            unsigned long bytes = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
            cout << get_bytes((unsigned char *)&bytes, 8) + " ";
            s += string((char *)&bytes, 8);
            addr += 8;
        }
        cout << " |";
        for (int i = 0; i < 16; i++)
        {
            if (isprint(s[i]))
                cout << s[i];
            else
                cout << ".";
        }
        cout << "|" << endl;
    }
}

void vmmap()
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    ifstream file("/proc/" + to_string(child) + "/maps");
    string line;
    while (getline(file, line))
    {
        stringstream ss(line);
        vector<string> addr_parts;
        string address, temp, perms, inode, pathname;
        ss >> address >> perms >> inode >> inode >> inode >> pathname;

        ss.clear();
        ss.str(address);
        while (getline(ss, temp, '-'))
        {
            addr_parts.push_back(temp);
        }

        cout << right << setfill('0') << setw(16) << addr_parts[0] << "-" << setw(16) << addr_parts[1]
             << " " << perms.substr(0, 3) << " " << left << setfill(' ') << setw(9) << inode << pathname << endl;
    }
}

void list()
{
    for (auto &&bp : breakpoints)
    {
        cout << right << setw(3) << dec << bp.id << ":  " << hex << bp.addr << endl;
    }
}

void load()
{
    if (state != STATE_NONE)
    {
        cerr << "** The state must be not loaded." << endl;
        return;
    }

    if (entry_point(program) == (unsigned long)-1)
        return;
    
    cout << "** program '" << program << "' loaded. entry point 0x" << hex << entry_point(program) << endl;
    state = STATE_LOADED;
}

void start()
{
    if (state != STATE_LOADED)
    {
        cerr << "** The state must be loaded." << endl;
        return;
    }
    child = fork();
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            cerr << "** ptrace error" << endl;

        char *argv[2] = {NULL, NULL};
        argv[0] = &program[0];
        execv(argv[0], argv);
        cerr << "** execvp error" << endl;
    }
    else
    {
        int status;
        string s;
        if (waitpid(child, &status, 0) < 0)
            cerr << "** waitpid error." << endl;
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        cout << "** pid " << dec << child << endl;
        state = STATE_RUNNING;
    }
}

void run()
{
    if (state == STATE_RUNNING)
    {
        cerr << "** program " << program << " is already running." << endl;
        cont();
    }
    else if (state == STATE_LOADED)
    {
        start();
        cont();
    }
    else
    {
        cerr << "** The state must be loaded or running." << endl;
    }
}

void si()
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    // restore the breakpoint
    if (checkstatus() == 0)
    {
        for (auto &&bp : breakpoints)
        {
            if (bp.id == meetbp)
            {
                bp.code = patch_code(bp.addr, 0xcc);
                meetbp = -1;
                break;
            }
        }
    }
}

void cont()
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    // restore the breakpoint
    if (meetbp != -1)
    {
        si();
    }
    ptrace(PTRACE_CONT, child, 0, 0);
    checkstatus();
}

void set(string reg, unsigned long long value)
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    ptrace_getregs();
    if (!regs.count(reg))
    {
        cerr << "** The register doesn't exist." << endl;
        return;
    }
    *regs[reg] = value;
    ptrace(PTRACE_SETREGS, child, 0, &regs_struct);
}

void get(string reg)
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    ptrace_getregs();
    if (!regs.count(reg))
    {
        cerr << "** The register doesn't exist." << endl;
        return;
    }
    cout << reg << " = " << dec << *regs[reg] << " ("
         << "0x" << hex << *regs[reg] << ")" << endl;
}

void getregs()
{
    if (state != STATE_RUNNING)
    {
        cerr << "** The state must be running." << endl;
        return;
    }
    ptrace_getregs();
    int counter = 0;
    for (auto &&reg : reglist)
    {
        counter++;
        string upper_reg = reg;
        transform(reg.begin(), reg.end(), upper_reg.begin(), ::toupper);
        cout << left << setw(3) << upper_reg << " " << setw(18) << hex << *regs[reg];
        if (counter % 4 == 0)
            cout << endl;
    }
    if (counter % 4 != 0)
        cout << endl;
}

void help()
{
    cout << "- break {instruction-address}: add a break point\
             - cont: continue execution\
             - delete {break-point-id}: remove a break point\
             - disasm addr: disassemble instructions in a file or a memory region\
             - dump addr [length]: dump memory content\
             - exit: terminate the debugger\
             - get reg: get a single value from a register\
             - getregs: show registers\
             - help: show this message\
             - list: list break points\
             - load {path/to/a/program}: load a program\
             - run: run the program\
             - vmmap: show memory layout\
             - set reg val: get a single value to a register\
             - si: step into instruction\
             - start: start the program and stop at the first instruction"
         << endl;
}

void runcmd(string line)
{
    string s;
    stringstream ss(line);
    vector<string> cmdline;
    while (ss >> s)
        cmdline.push_back(s);

    string cmd = cmdline[0];
    if (cmd == "break" || cmd == "b")
    {
        if (checkargs(cmdline.size(), 2))
            bp(s2ull(cmdline[1]));
    }
    else if (cmd == "cont" || cmd == "c")
    {
        cont();
    }
    else if (cmd == "delete")
    {
        if (checkargs(cmdline.size(), 2))
            deletebp(stoi(cmdline[1]));
    }
    else if (cmd == "disasm" || cmd == "d")
    {
        if (cmdline.size() == 1)
            cout << "** no addr is given." << endl;
        else
            disasm(s2ull(cmdline[1]));
    }
    else if (cmd == "dump" || cmd == "x")
    {
        if (cmdline.size() == 1)
            cout << "** no addr is given." << endl;
        else
            dump(s2ull(cmdline[1]));
    }
    else if (cmd == "exit" || cmd == "q")
    {
        exit(EXIT_SUCCESS);
    }
    else if (cmd == "get" || cmd == "g")
    {
        if (checkargs(cmdline.size(), 2))
            get(cmdline[1]);
    }
    else if (cmd == "getregs")
    {
        getregs();
    }
    else if (cmd == "help" || cmd == "h")
    {
        help();
    }
    else if (cmd == "list" || cmd == "l")
    {
        list();
    }
    else if (cmd == "load")
    {
        if (checkargs(cmdline.size(), 2))
        {
            program = cmdline[1];
            load();
        }
    }
    else if (cmd == "run" || cmd == "r")
    {
        run();
    }
    else if (cmd == "vmmap" || cmd == "m")
    {
        vmmap();
    }
    else if (cmd == "set" || cmd == "s")
    {
        if (checkargs(cmdline.size(), 3))
            set(cmdline[1], s2ull(cmdline[2]));
    }
    else if (cmd == "si")
    {
        si();
    }
    else if (cmd == "start")
    {
        start();
    }
    else
    {
        cerr << "** invalid command." << endl;
    }
}

int main(int argc, char *argv[])
{
    int c;
    string script_path, line;

    while ((c = getopt(argc, argv, "s:")) != -1)
        switch (c)
        {
        case 's':
            script_path = optarg;
            break;
        case '?':
            cerr << "usage: ./hw4 [-s script] [program]" << endl;
            return 1;
        }

    if (script_path == "")
    {
        if (argc > 1)
        {
            program = argv[1];
            load();
        }
        cout << "sdb> ";
        while (getline(cin, line))
        {
            if (line.empty())
            {
                cout << "sdb> ";
                continue;
            }
            runcmd(line);
            cout << "sdb> ";
        }
    }
    else
    {
        if (argc > 3)
        {
            program = argv[3];
            load();
        }
        ifstream file(script_path);
        while (getline(file, line))
        {
            if (line.empty())
            {
                continue;
            }
            runcmd(line);
        }
    }

    return 0;
}