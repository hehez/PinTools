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
#include <iostream>
#include <fstream>
#include "pin.H"

FILE *outfile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount

// This function is called before every block
// VOID printip(ADDRINT ip) { fprintf(outfile, "%lx\n", ip); }

VOID printcall(ADDRINT src, ADDRINT dest, char *c) 
{
    fprintf(outfile, "%s [%lx/%lx]\n", c, src, dest);
    cout << *c << hex << " [" << src << "/" << dest << "]" << endl;
}

// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
VOID Trace(TRACE trace, VOID *v)
{
    // IMG img;
    // SEC sec;
    // RTN rtn;
    // rtn = TRACE_Rtn(trace);
    // if(!RTN_Valid(rtn)) return;
    // sec = RTN_Sec(rtn);
    // if(!SEC_Valid(sec)) return;
    // img = SEC_Img(sec);
    // if(!IMG_Valid(img)) return;
    // if(!IMG_IsMainExecutable(img)) return;

    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins))
        {
            // Insert a call to printip before every ins, passing the number of instructions
            char *command;
            if(INS_IsCall(ins)) {
                command = new char('C');
                // if(INS_IsDirectBranchOrCall(ins))
                // {
                //     // const ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
                //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printcall, IARG_ADDRINT, 
                //         INS_Address(ins), IARG_ADDRINT, INS_DirectBranchOrCallTargetAddress(ins), IARG_PTR, command, IARG_END);
                    
                // }
                // if(INS_IsIndirectBranchOrCall(ins)) 
                // {
                //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printcall, IARG_ADDRINT, 
                //         INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_PTR, command, IARG_END);
                // }
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printcall, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_PTR, command, IARG_END);
            } else {
                // sometimes code is not an image
            }
            if(INS_IsBranch(ins)) {
                command = new char('J');
                // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printcall, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_PTR, command, IARG_END);
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)printcall, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_PTR, command, IARG_END);
                if (INS_HasFallThrough(ins))
                {
                    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)printcall, IARG_INST_PTR, IARG_FALLTHROUGH_ADDR, IARG_PTR, command, IARG_END);
                }
            }
            if(INS_IsRet(ins)) {
                command = new char('R');
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printcall, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_PTR, command, IARG_END);
            }
		}
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "inscount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
		fprintf(outfile, "#eof\n");
		fclose(outfile);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    outfile = fopen("proj1.out", "w");
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
