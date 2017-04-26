/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing system calls
 */


#define NDEBUG

#include <stdio.h>
#include <unistd.h>

#include <sys/syscall.h>
#include "pin.H"

#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#include <iostream>
#include <fstream>
#include <string.h>

typedef struct sysent {
    unsigned nargs;
    int sys_num;
    const char *sys_name;
} struct_sysent;

const struct_sysent sysent[] = {
#include "syscall_list.h"
};

FILE * trace;
ofstream TraceFile;

unsigned long sys_arg[6];
unsigned long syscall_num;
bool isMainProgram = false;

KNOB<BOOL>   KnobReplay(KNOB_MODE_WRITEONCE,  "pintool",
    "replay", "0", "count instructions, basic blocks and threads in the application");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "trace.out", "specify output file name");

#define RANDOM "rand"
#define SLEEP "sleep"


VOID MainBegin()
{
    isMainProgram = true;
}

VOID MainReturn()
{
    isMainProgram = false;
}

VOID SimulateSignal(INT32 signal)
{
    int cur_pid = PIN_GetPid();
    // leave the kill error
    int err = kill(cur_pid, signal);
    cout << "[PINTOOL] Replay: Simulate signal <SIG"<< sys_signame[signal] <<">, current pid is " << cur_pid << ", return is " << err << endl;
    exit(1);
}

VOID SimulateSyscall(CONTEXT *ctxt, long ret, ADDRINT nextAddr)
{
    PIN_SetContextReg(ctxt, REG_RAX, ret);
    PIN_SetContextReg(ctxt, REG_INST_PTR, nextAddr);
    PIN_ExecuteAt(ctxt);
}

VOID RandRecord(ADDRINT ret)
{
    INT32 sig = 0;
    fwrite(&sig, sizeof(INT32), 1, trace);
    fwrite(&ret, sizeof(long), 1, trace);
}

VOID RandReplay(CONTEXT *ctxt, ADDRINT nextAddr)
{
    long ret;
    INT32 sig;
    fread(&sig, sizeof(INT32), 1, trace);
    if(sig > 0) SimulateSignal(sig);
    fread(&ret, sizeof(long), 1, trace);
    SimulateSyscall(ctxt, ret, nextAddr);
}

VOID SleepSecRecord(ADDRINT ret)
{
    INT32 sig = 0;
    fwrite(&sig, sizeof(INT32), 1, trace);
    fwrite(&ret, sizeof(ADDRINT), 1, trace);
}

VOID SleepReplay(CONTEXT *ctxt, ADDRINT nextAddr)
{
    // tiny flaw, need to be solved later
    long ret;
    INT32 sig;
    fread(&sig, sizeof(INT32), 1, trace);
    if(sig > 0) SimulateSignal(sig);
    fread(&ret, sizeof(long), 1, trace);
    SimulateSyscall(ctxt, ret, nextAddr);
}

// VOID SleepLeftRecord(ADDRINT time)
// {
//     cout << "Sleep left time is " << time <<" s, INTERRUPT by signal" << endl;
// }

VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, CONTEXT *ctxt, ADDRINT nextAddr)
{
    if(!isMainProgram) return;

    syscall_num = num;
    sys_arg[0] = (unsigned long)arg0;
    sys_arg[1] = (unsigned long)arg1;
    sys_arg[2] = (unsigned long)arg2;
    sys_arg[3] = (unsigned long)arg3;
    sys_arg[4] = (unsigned long)arg4;
    sys_arg[5] = (unsigned long)arg5;

    if(KnobReplay)
    {
        INT32 sig;
        long ret, err;
        if(syscall_num == __NR_read || syscall_num == __NR_gettimeofday || syscall_num == __NR_open 
            || syscall_num == __NR_socket || syscall_num == __NR_connect
            || syscall_num == __NR_sendto || syscall_num == __NR_recvfrom 
            || syscall_num == __NR_listen
            // || syscall_num == __NR_nanosleep
            )
        {
            fread(&sig, sizeof(INT32), 1, trace);
            if(sig > 0) SimulateSignal(sig);
            // replay error OR regular replay
            fread(&err, sizeof(long), 1, trace);
            fread(&ret, sizeof(long), 1, trace);
            switch(syscall_num)
            {
                case __NR_read: 
                    if(ret < 0) {
                        INT32 s;
                        fread(&s, sizeof(INT32), 1, trace);
                        if(s > 0) SimulateSignal(s);
                    }
                    fread((VOID*)sys_arg[1], sizeof(char), ret, trace);
                    // cout << "before __NR_read ret is " << (long) ret <<" err is "<<(long) err 
                    // << " sig "<< sig << " val " << (char*)sys_arg[1] << endl;
                    break;
                case __NR_gettimeofday: 
                    fread((VOID*)sys_arg[0], sizeof(timeval), 1, trace);
                    break;
                case __NR_open: 
                    size_t len;
                    fread(&len, sizeof(size_t), 1, trace);
                    if(sys_arg[0] != 0)
                    {
                        fread((VOID*)sys_arg[0], sizeof(char), len, trace);
                    } else {
                        if(sig >= 0) {
                            // replay with no input file condition
                            char* f_name = (char*)malloc(sizeof(char));
                            fread(f_name, sizeof(char), len, trace);
                            sys_arg[0] = *f_name;
                            free(f_name);
                        }
                    }
                    break;
                case __NR_nanosleep: 
                    ret = 0;
                    break;
                case __NR_socket: break;
                case __NR_connect: break;
                case __NR_listen: break;
                case __NR_sendto: 
                    fread((VOID*)sys_arg[1], sizeof(char), ret, trace);
                    if(ret < 0) cout << "[PINTOOL] Replay: fail to sent message " << (char*) sys_arg[1] << endl;
                    break;
                case __NR_recvfrom: 
                    if(ret < 0) {
                        INT32 s;
                        fread(&s, sizeof(INT32), 1, trace);
                        if(s > 0) SimulateSignal(s);
                    }
                    fread((VOID*)sys_arg[1], sizeof(char), ret, trace);
                    break;
            }
            SimulateSyscall(ctxt, ret, nextAddr);
        }
    }
    else {
        // test
        if(syscall_num == __NR_listen)
        {
        //     // struct sockaddr *sa = (sockaddr *)malloc(sizeof(struct sockaddr));
        //     // memcpy(sa, (VOID*)sys_arg[1], sizeof(sockaddr)*sys_arg[2]);
        //     // cout << sa->sa_data << endl;
        //     // // cout <<" before "<< (sa->sa_data)[0] << "   " <<(sa->sa_data)[1] << "   " << sa->sa_family << endl;
        //     // // cout << "before arg0 " << (long)sys_arg[0]
        //     // // << " arg1 " << (char*)sys_arg[1]
        //     // // << " arg2 " << (long)sys_arg[2]
        //     // // << endl;
        //     // free(sa);
        //     // cout << "before __NR_sendto "  
        //     //         << " ag0 " << (long)sys_arg[0]
        //     //         << " ag1 " << (long)sys_arg[1]
        //     //         << " ag2 " << (long)sys_arg[2]
        //     //         << endl;
            // cout << "__NR_listen" <<endl;

        }
    }
}

VOID SysAfter(ADDRINT ret, ADDRINT err)
{
    /* record order
    1, signal(ignore 2-4 if signal is captured, set as -1 if err)
    2, errno
    3, return
    4, value (set null if err)
    */
    if(!isMainProgram) return;
    if(!KnobReplay) {
        INT32 sig = 0, errsig = -1;
        if(syscall_num == __NR_read || syscall_num == __NR_gettimeofday || syscall_num == __NR_open 
            || syscall_num == __NR_socket || syscall_num == __NR_connect
            || syscall_num == __NR_sendto || syscall_num == __NR_recvfrom 
            || syscall_num == __NR_listen
            // || syscall_num == __NR_nanosleep
            )
        {
            fwrite((long)ret < 0 ? (&errsig) : (&sig), sizeof(INT32), 1, trace);
            fwrite(&err, sizeof(long), 1, trace);
            // error handler
            if((long)ret < 0) ret = -err;
            fwrite(&ret, sizeof(long), 1, trace);
            switch(syscall_num)
            {
                case __NR_read: 
                    // cout << "after __NR_read ret is " << (long) ret <<" err is "<<(long) err 
                    // // << " ag0 " << (long)sys_arg[0]
                    // << " ag1 " << (char*)sys_arg[1]
                    // // << " ag2 " << (long)sys_arg[2]
                    // << endl;
                    fwrite((VOID*)sys_arg[1], sizeof(char), (long)ret < 0 ? 0 : (long)ret, trace);
                    break;
                case __NR_gettimeofday: 
                    fwrite((VOID*)sys_arg[0], sizeof(timeval), 1, trace);
                    break;
                case __NR_open: 
                    // err -14 EFAULT no input argument for open syscall, err 2 No such file or directory
                    if(sys_arg[0] != 0) {
                        // input file path
                        size_t len = strlen((char*)sys_arg[0]);
                        fwrite(&len, sizeof(size_t), 1, trace);
                        fwrite((VOID*)sys_arg[0], sizeof(char), len, trace);
                    }
                    break;
                case __NR_nanosleep: break;
                case __NR_socket: break;
                case __NR_connect: break;
                case __NR_listen: break;
                case __NR_sendto: 
                    fwrite((VOID*)sys_arg[1], sizeof(char), (long)sys_arg[2], trace);
                    break;
                case __NR_recvfrom: 
                    fwrite((VOID*)sys_arg[1], sizeof(char), (long)ret < 0 ? 0 : (long)ret, trace);
                    break;
            }
        }
    }
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallErrno(ctxt, std));
}

BOOL SigFunc(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler, const EXCEPTION_INFO *exception, void *)
{
    /* Mutex */
    PIN_LockClient();
    fwrite(&sig, sizeof(INT32), 1, trace);
    /* Mutex */
    PIN_UnlockClient();
    // not pass signal to application if return FALSE
    return TRUE;
}

VOID Instruction(INS ins, VOID *v)
{
    // SYSCALL_STANDARD : SYSCALL_STANDARD_IA32E_LINUX
    if(INS_IsSyscall(ins)) {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                        IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                        IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                        IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                        IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                        IARG_CONTEXT, IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
    }
    if(KnobReplay) {
        RTN rtn = INS_Rtn(ins);
        if (RTN_Valid(rtn))
        {
            // if(RTN_Name(rtn) == "rand") {
            //     cout << "RTN id "<<RTN_Id(rtn)<< " RTN_Name "<<RTN_Name(rtn) << endl;
            //     if(INS_IsCall(ins))
            //     {
            //        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RandReplay), IARG_CONTEXT, IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
            //     }
            // }

            // if(RTN_Name(rtn) == "sleep") {
            //     cout << "RTN id "<<RTN_Id(rtn)<< " RTN_Name "<<RTN_Name(rtn) << endl;
            // }
            switch(RTN_Id(rtn))
            {
                case 221:
                    // random
                    if(INS_IsCall(ins))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RandReplay), IARG_CONTEXT, IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
                    } 
                case 767:
                    // sleep
                    if(INS_IsCall(ins))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SleepReplay), IARG_CONTEXT, IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
                    }                
            }
           
        }
    }
}

VOID Image(IMG img, VOID *v)
{
    RTN mainRtn = RTN_FindByName(img, "main");
    if(RTN_Valid(mainRtn))
    {
        RTN_Open(mainRtn);
        RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)MainBegin, IARG_END);
        RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)MainReturn, IARG_END);
        RTN_Close(mainRtn);
    }


    RTN randRtn = RTN_FindByName(img, RANDOM);
    if(RTN_Valid(randRtn))
    {
        RTN_Open(randRtn);
        if(!KnobReplay)
        {
            RTN_InsertCall(randRtn, IPOINT_AFTER, (AFUNPTR)RandRecord, IARG_G_RESULT0, IARG_END);
        }
        RTN_Close(randRtn);
    }

    RTN sleepRtn = RTN_FindByName(img, SLEEP);
    if(RTN_Valid(sleepRtn))
    {
        RTN_Open(sleepRtn);
        if(!KnobReplay)
        {
            // before capture sleep sec IARG_SYSCALL_ARG0 / IARG_FUNCARG_ENTRYPOINT_VALUE, after capture left if signal IARG_G_RESULT0
            // RTN_InsertCall(sleepRtn, IPOINT_BEFORE, (AFUNPTR)SleepSecRecord, IARG_SYSCALL_ARG0, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            /* print after finish sleep */
            RTN_InsertCall(sleepRtn, IPOINT_AFTER, (AFUNPTR)SleepSecRecord, IARG_SYSCALL_ARG0, IARG_END);
        }
        RTN_Close(sleepRtn);
    }
}

VOID Fini(INT32 code, VOID *v)
{
        fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    // TraceFile.open(KnobOutputFile.Value().c_str());
    if (KnobReplay) {
        printf("====== REPLAY MODE =======\n");
        // trace = fopen("trace.out", "r");
        trace = fopen(KnobOutputFile.Value().c_str(), "r");
    } else {
        printf("====== RECORDING MODE =======\n");
        // trace = fopen("trace.out", "w");
        trace = fopen(KnobOutputFile.Value().c_str(), "w");
    }
    
    if(trace == NULL) {
        fprintf(stderr, "File open error! (trace.out)\n");
        return 0;
    }

    IMG_AddInstrumentFunction(Image, 0);
    // PIN_AddSyscallEntryFunction(syscall_entry, 0);
    PIN_InterceptSignal(SIGINT, SigFunc, 0);
    PIN_UnblockSignal(SIGINT, TRUE);
    // PIN_AddContextChangeFunction(OnSignal, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
