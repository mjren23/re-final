#include <signal.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include<sys/stat.h>

typedef struct {
    char l0:1;
    char g0:1;
    char l1:1;
    char g1:1;
    char l2:1;
    char g2:1;
    char l3:1;
    char g3:1;
    char le:1;
    char ge:1;
    char reserved1:3;
    char gd:1;
    char reserved2:2;
    char rw0:2;
    char len0:2;
    char rw1:2;
    char len1:2;
    char rw2:2;
    char len2:2;
    char rw3:2;
    char len3:2;
} dr7_t;

long extract_bit_range(long num, unsigned high, unsigned low);

dr7_t fill_control(long reg) {
    dr7_t new_dr7 = {0};
    new_dr7.l0 = extract_bit_range(reg, 0, 0);
    new_dr7.g0 = extract_bit_range(reg, 1, 1);
    new_dr7.l1 = extract_bit_range(reg, 2, 2);
    new_dr7.g1 = extract_bit_range(reg, 3, 3);
    new_dr7.l2 = extract_bit_range(reg, 4, 4);
    new_dr7.g2 = extract_bit_range(reg, 5, 5);
    new_dr7.l3 = extract_bit_range(reg, 6, 6);
    new_dr7.g3 = extract_bit_range(reg, 7, 7);
    new_dr7.le = extract_bit_range(reg, 8, 8);
    new_dr7.ge = extract_bit_range(reg, 9, 9);
    new_dr7.reserved1 = extract_bit_range(reg, 10, 12);
    new_dr7.gd = extract_bit_range(reg, 13, 13);
    new_dr7.reserved2 = extract_bit_range(reg, 14, 15);
    new_dr7.rw0 = extract_bit_range(reg, 16, 17);
    new_dr7.len0 = extract_bit_range(reg, 18, 19);
    new_dr7.rw1 = extract_bit_range(reg, 20, 21);
    new_dr7.len1 = extract_bit_range(reg, 22, 23);
    new_dr7.rw2 = extract_bit_range(reg, 24, 25);
    new_dr7.len2 = extract_bit_range(reg, 26, 27);
    new_dr7.rw3 = extract_bit_range(reg, 28, 29);
    new_dr7.len3 = extract_bit_range(reg, 30, 31);
    return new_dr7;
}

long extract_bit_range(long num, unsigned high, unsigned low) {
    long range = (high - low + 1);
    long result = 0;
    long mask = ((1 << range) - 1) << low;

    result = num & mask;
    result = result >> low; 

    return result;
}

void get_dbreg(pid_t pid, int reg_num) {
    long reg = ptrace(PTRACE_PEEKUSER, pid, offsetof (struct user, u_debugreg[reg_num]), NULL);

    if (reg_num < 7) {
        printf("REGISTER DR%d:\n\t'0x%lx'\n", reg_num, reg);
    
    } else {
        dr7_t new_dr7 = fill_control(reg);
        printf("REGISTER DR%d:\n", reg_num);
        printf("\t Global Detect 0: 0x%x\n", new_dr7.g0);
        printf("\t Local Detect 0: %s\n", new_dr7.l0 == 0x1 ? "ON" : "OFF");
        printf("\t Global Detect 0: %s\n", new_dr7.g0 == 0x1 ? "ON" : "OFF");
        printf("\t Local Detect 1: %s\n", new_dr7.l1 == 0x1 ? "ON" : "OFF");
        printf("\t Global Detect 1: %s\n", new_dr7.g1 == 0x1 ? "ON" : "OFF");
        printf("\t Local Detect 2: %s\n", new_dr7.l2 == 0x1 ? "ON" : "OFF");
        printf("\t Global Detect 2: %s\n", new_dr7.g2 == 0x1 ? "ON" : "OFF");
        printf("\t Local Detect 3: %s\n", new_dr7.l3 == 0x1 ? "ON" : "OFF");
        printf("\t Global Detect 3: %s\n", new_dr7.g3 == 0x1 ? "ON" : "OFF");
        printf("\t Local Enable: %s\n", new_dr7.le == 0x1 ? "ON" : "OFF");
        printf("\t Global Enable: %s\n", new_dr7.ge == 0x1 ? "ON" : "OFF");
        printf("\t Global Detect: %s\n", new_dr7.gd == 0x1 ? "ON" : "OFF");
        printf("\t Read/Write 0: 0x%x\n", new_dr7.rw0);
        printf("\t Length 0: %d bytes\n", new_dr7.len0);
        printf("\t Read/Write 1: 0x%x\n", new_dr7.rw1);
        printf("\t Length 1: %d bytes\n", new_dr7.len1);
        printf("\t Read/Write 2: 0x%x\n", new_dr7.rw2);
        printf("\t Length 2: %d bytes\n", new_dr7.len2);
        printf("\t Read/Write 3: 0x%x\n", new_dr7.rw3);
        printf("\t Length 3: %d bytes\n", new_dr7.len3);
    } 

    return;
}

void set_dbreg(pid_t pid, void* addr) {
    if (ptrace(PTRACE_POKEUSER, pid, offsetof (struct user, u_debugreg[0]), addr))    //Configure DR0 with address
        perror("ptrace() error!\n");
    long control = 0xD0602;
    if (ptrace(PTRACE_POKEUSER, pid, offsetof (struct user, u_debugreg[7]), 0xD2602)) //Configure DR7 with Global Detect bit
        perror("ptrace() error!\n");
    return;
}

void signal_handler(int sig){
	switch(sig){
        case SIGTRAP:
            printf("\nKernel got SIGTRAP\n");
            break;
        case SIGUSR1:
            printf("\nKernel got SIGUSR1\n");
            break;
        default:
            printf("\nKernel got signal #%i\n", sig);
	}
}

struct stat buf;

int main(int argc, char * argv[])
{
    pid_t pid;

    //Set up signal handlers
    signal(SIGTRAP, signal_handler);
    signal(SIGUSR1, signal_handler);

    switch (pid = fork()) {
        case -1:
            perror("fork() error!\n");
            break;

        case 0:
            printf("Tracee starting\n");

            if(ptrace(PTRACE_TRACEME, 0, 0, 0))
                perror("ptrace() error!\n");

            printf("\nTracee is indicating it is ready to be watched...\n");

            //Signal to tracer
            raise(SIGUSR1);

            //Create file for use in system call
            fopen("temp", "r");

            //Writing memory from userland
            printf("\nTracee is updating watched memory from userland...\n");
            buf.st_uid = 12;

            //Writing memory from kernel land
            printf("\nTracee is updating watched memory from kernelland...\n");
            stat("temp", &buf);

            //Remove temporary file
            remove("temp");
    
            printf("\nTracee exiting\n");
                    break;

        default:
            while(1)
            {
                int status;
                int sig;

                //Wait for signal from tracee
                wait(&status);

                //tracee exited
                if (WIFEXITED(status) || WIFSIGNALED(status))
                    break;

                sig = WSTOPSIG(status);

                switch(sig){
                    //Trap signal (Watchpoint hit)
                    case SIGTRAP:
                        printf("\nTracer caught tracee signal SIGTRAP\n");
                        printf("\nWatchpoint hit!\n");
                        break;
                    
                    //User-defined signal (tracee is ready to get watchpoint)
                    case SIGUSR1:
                        printf("\nTracer caught tracee signal SIGUSR1\n");
                        printf("\n-------------------- DEBUG REGISTERS -----------------\n");
                        get_dbreg(pid, 0);
                        get_dbreg(pid, 7);

                        printf("\n\nSeting debug registers...\n");
                        printf("\n\n-------------------- DEBUG REGISTERS -----------------\n");
                        set_dbreg(pid, &(buf.st_uid)); //Update debug registers
                        get_dbreg(pid, 0);
                        get_dbreg(pid, 7);
                        printf("\n");
                        break;

                    //Unhandled signal (Undefined)
                    default:
                        printf("\nTracer caught tracee signal #%i\nContinuing...\n", sig);
                }
                

                if (ptrace(PTRACE_CONT, pid, NULL, sig))
                    perror("ptrace() error");
            }
	}
    return 0;
}