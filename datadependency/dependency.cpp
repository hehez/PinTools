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

#include <map>

FILE* outFile;

bool isMainProgram = false;
ADDRINT highImgAddr = 0;

struct shm
{
	ADDRINT ip;
	ADDRINT ep;
};
map<string, shm> ssMap;
map<ADDRINT, int> insMap;

VOID updateExecPoint(ADDRINT ip, BOOL isMulIp)
{
	if(!isMulIp)insMap[ip]++;
}

VOID updateShm(string key, ADDRINT ip, BOOL isMulIp)
{
	ssMap[key].ip = ip;
	if(!isMulIp)ssMap[key].ep++;
}

shm getExecPoint(string key)
{
	return ssMap[key];
}

ADDRINT ip_hit = 0;

BOOL isMulInsPoint(ADDRINT ip)
{
	return ip == ip_hit;
}

VOID memWrite(ADDRINT ip, ADDRINT target, const string filename, UINT32 line)
{
	if(!isMainProgram) return;
	if(target >= highImgAddr) return;
	if(filename.empty()) return;

	// update the shadow space
	char str[18];
	sprintf(str, "0x%lx", target);
	BOOL b = isMulInsPoint(ip);
	updateExecPoint(ip, b);
	updateShm(str, ip, b);
	ip_hit = ip;
}

VOID memRead(ADDRINT ip, ADDRINT target,const string filename, UINT32 line)
{
	// record into output file for memory read
	if(!isMainProgram) return;
	if(target >= highImgAddr) return;
	if(filename.empty()) return;

	char str[18];
	sprintf(str, "0x%lx", target);
	BOOL b = isMulInsPoint(ip);
	updateExecPoint(ip, b);
	ip_hit = ip;
	fprintf(outFile, "M, 0x%lx, 0x%d, 0x%lx, 0x%lx, 0x%d, - %s:%d\n", ip, insMap[ip], target, getExecPoint(str).ip, insMap[getExecPoint(str).ip], filename.c_str(), line);

}

VOID regWrite(ADDRINT ip, string str, const string filename, UINT32 line)
{
	if(!isMainProgram) return;
	if(filename.empty()) return;
	// update the shadow space
	BOOL b = isMulInsPoint(ip);
	updateExecPoint(ip, b);
	updateShm(str, ip, b);
	ip_hit = ip;
}

VOID regRead(ADDRINT ip, string str, const string filename, UINT32 line)
{
	if(!isMainProgram) return;
	if(filename.empty()) return;

	BOOL b = isMulInsPoint(ip);
	updateExecPoint(ip, b);
	ip_hit = ip;
	fprintf(outFile, "R, 0x%lx, 0x%d, %s, 0x%lx, 0x%d, - %s:%d\n", ip, insMap[ip], str.c_str(), getExecPoint(str).ip, insMap[getExecPoint(str).ip], filename.c_str(), line);
}

BOOL ignoreReg(REG reg)
{
	switch(reg)
	{
		// case REG_RAX:  return true;
		// case REG_EAX:  return true;
		// case REG_AX:   return true;
		// case REG_AH:   return true;
		// case REG_AL:   return true;
			// break;

		// case REG_RBX:  return true;
		// case REG_EBX:  return true;
		// case REG_BX:   return true;
		// case REG_BH:   return true;
		// case REG_BL:   return true;
		// 	break;

		// case REG_RCX:  return true;
		// case REG_ECX:  return true;
		// case REG_CX:   return true;
		// case REG_CH:   return true;
		// case REG_CL:   return true;
		// 	break;

		// case REG_RDX:  return true;
		// case REG_EDX:  return true;
		// case REG_DX:   return true;
		// case REG_DH:   return true;
		// case REG_DL:   return true;
		// 	break;

		// case REG_RDI:  return true;
		// case REG_EDI:  return true;
		// case REG_DI:   return true;
		// case REG_DIL:  return true;
		// 	break;

		// case REG_RSI:  return true;
		// case REG_ESI:  return true;
		// case REG_SI:   return true;
		// case REG_SIL:  return true;
		// 	break;

		case REG_RIP:  return true;
		case REG_EIP:  return true;
		case REG_RBP:  return true;
		case REG_RSP:  return true;
		case REG_RDI:  return true;
		case REG_EDI:  return true;
		case REG_RSI:  return true;
		case REG_ESI:  return true;
		case REG_ESP:  return true;
		case REG_FLAGS:  return true;
		case REG_EFLAGS:  return true;
		case REG_RFLAGS:  return true;

		default:
			break;
	}
	return false;
}

VOID MainBegin()
{
	isMainProgram = true;
}

VOID MainReturn()
{
	isMainProgram = false;
}

bool IsAddressInMainExecutable(ADDRINT addr)
{
	RTN rtn = RTN_FindByAddress(addr);

	if (rtn == RTN_Invalid())
		return false;

	SEC sec = RTN_Sec(rtn);
	if (sec == SEC_Invalid())
		return false;

	IMG img = SEC_Img(sec);
	if (img == IMG_Invalid())
		return false;
	if(IMG_IsMainExecutable(img)) return true;

	return false;
}

VOID Image(IMG img, VOID *v)
{
	if(highImgAddr < IMG_HighAddress(img)) highImgAddr = IMG_HighAddress(img);

	RTN mainRtn = RTN_FindByName(img, "main");

	if(RTN_Valid(mainRtn))
	{
		RTN_Open(mainRtn);
		RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)MainBegin, IARG_END);
		RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)MainReturn, IARG_END);
		RTN_Close(mainRtn);
	}
}

VOID Instruction(INS ins, VOID *v)
{
	if (!IsAddressInMainExecutable(INS_Address(ins))) return;

	string filename;
	INT32 line;

	PIN_GetSourceLocation(INS_Address(ins), NULL, &line, &filename);

	if(INS_IsMemoryRead(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR) memRead,
			IARG_INST_PTR,
			IARG_MEMORYREAD_EA,
			IARG_PTR, new string(filename),
			IARG_UINT32, line,
			IARG_END);
	}

	if(INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR) memWrite,
			IARG_INST_PTR,
			IARG_MEMORYWRITE_EA,
			IARG_PTR, new string(filename),
			IARG_UINT32, line,
			IARG_END);
	}

	// for handling register operands
	unsigned int max_read_regs = INS_MaxNumRRegs(ins);
	for (unsigned int i = 0; i < max_read_regs; i++)
	{
		REG reg = INS_RegR(ins, i);
		if (REG_valid(reg))
		{
			if(!ignoreReg(reg))
			{
				INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR) regRead,
				IARG_INST_PTR,
				IARG_PTR, new string(REG_StringShort(reg)),
				IARG_PTR, new string(filename),
				IARG_UINT32, line,
				IARG_END);
			}
		}
	}	

	unsigned int max_write_regs = INS_MaxNumWRegs(ins);
	for (unsigned int i = 0; i < max_write_regs; i++)
	{
		REG reg = INS_RegW(ins, i);
		if(REG_valid(reg))
		{
			if(!ignoreReg(reg))
			{
				INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR) regWrite,
				IARG_INST_PTR,
				IARG_PTR, new string(REG_StringShort(reg)),
				IARG_PTR, new string(filename),
				IARG_UINT32, line,
				IARG_END);
			}
		}
	}
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "proj2.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	fclose(outFile);
	// consider calling another function to parse the output file
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This tool capture data dependence edges and generate a trace." << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	PIN_InitSymbols();
	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();

	outFile = fopen(KnobOutputFile.Value().c_str(), "w");
	if(outFile == NULL) {
		fprintf(stderr, "Fail to open the output file - %s\n", KnobOutputFile.Value().c_str());
		return 0;
	}

	IMG_AddInstrumentFunction(Image, 0);
	// Register Instruction to be called to instrument instructions
	INS_AddInstrumentFunction(Instruction, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}
