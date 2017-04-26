/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
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

/*! @file
 *  Basic taint analyzer 3 (retain source offset of the taint)
 *  This taint analyzer only supports the propogation of taint through
 *  MOV family of instructions. 
 *  
 *  This version does retain the taint source
 */


/*#include "pin.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <string.h>
#include "xed-iclass-enum.h"

//#include <stdlib.h>
//#include "sysdep.h"


//#include <Wdm.h>

//typedef void *HANDLE;
//HANDLE inputfile;



enum type_def {type_BYTE,type_WORD,type_DWORD,type_unknown};

struct TDS{
       UINT32 opcode;  // opcode of operation
       TDS * source;   // pointer to predecessor
       ADDRINT memaddr; // Tainted Address
       ADDRINT offset;// The origin of the taint
	   UINT32 var_length;
	   bool pointer;
	   type_def var_type;
};

struct TYPE_reg{
	bool pointer;
	ADDRINT pointaddr;
	type_def var_type;
};
*/

#include "MyPinTool.h"
#include "summary.h"


std::ofstream out;// output file
std::ifstream in;

struct TYPE_reg pointer[REG_LAST][REG_LAST];

map<ADDRINT, TDS * > TaintedAddrs;                 // tainted memory addresses
TDS* TaintedRegs[REG_LAST] = {NULL};  // tainted registers
//std::ofstream out;// output file
//std::ifstream in;//input data addr
TDS* Ftaint; // final taint
ADDRINT memRetStack;
bool bbl_taintedmem = 0;
//bool bbl_looptaint = 0;
bool TAINT_Analysis_On = 0;
bool TAINT_Instrumentation_On = 0;





//auxiliary function


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "taint.out", "specify file name for the output file");

INT32 Usage()
{
    cerr << "This tool follows the taint defined by the first argument to " << endl <<
            "the instumented program command line and outputs details to a file" << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID InsertTaintInstrumentation()
{
  TAINT_Analysis_On = true;
  if (!TAINT_Instrumentation_On)
  {
    TAINT_Instrumentation_On = true;
    PIN_RemoveInstrumentation();
  }
}

VOID AddTaint(ADDRINT toTaintAdd,UINT32 toTaintLen,type_def toTaintType)//Add taint address in byte-level
{
			
/*		for (int i = 0; i < n; i++)
		{
			TDS *tds_temp = new TDS;
			tds_temp->offset = i+1;
			tds_temp->memaddr = taint+i;
			TaintedAddrs[taint + i] = tds_temp;

			out<<i+1<<"   "<<tds_temp->memaddr<<endl;
		}
*/
	out <<endl<<"add taint for variable in byte-level"<<endl;
	for(int i=0; i < toTaintLen;i++)
	{
		TDS *tds_temp = new TDS;
		tds_temp->offset = i;
		tds_temp->memaddr = toTaintAdd+i;
		tds_temp->var_length = toTaintLen;//
		tds_temp->var_type = toTaintType;
		tds_temp->pointer = 0;
		TaintedAddrs[toTaintAdd+i] = tds_temp;

//		tds_temp->memaddr = taint+2;
//		TaintedAddrs[taint+2] = tds_temp;
		out <<" offset in variable: "<<tds_temp->offset<<"  address: "<<tds_temp->memaddr<<"  type: "<<tds_temp->var_type<<endl;
	}

}

bool INS_has_immed(INS ins)
{
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
    {
        if (INS_OperandIsImmediate(ins, i))
        {
            return true;
        }
    }
    return false;
}

// returns the full name of the first register operand written
REG INS_get_write_reg(INS ins)
{
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
    {
        if (INS_OperandIsReg(ins, i) && INS_OperandWritten(ins, i))
        {
            return REG_FullRegName(INS_OperandReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

// returns the full name of the first register operand read
REG INS_get_read_reg(INS ins)
{
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
    {
        if (INS_OperandIsReg(ins, i) && INS_OperandRead(ins, i))
        {
            return REG_FullRegName(INS_OperandReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

REG INS_get_mem_indexreg(INS ins)
{
	for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
	{
        if (INS_OperandIsMemory(ins, i) && INS_OperandRead(ins, i))
        {
            return REG_FullRegName(INS_OperandMemoryIndexReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

REG INS_get_mem_basereg(INS ins)
{
	for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
	{
        if (INS_OperandIsMemory(ins, i) && INS_OperandRead(ins, i))
        {
            return REG_FullRegName(INS_OperandMemoryBaseReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

REG INS_get_memwr_indexreg(INS ins)
{
	for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
	{
        if (INS_OperandIsMemory(ins, i) && INS_OperandWritten(ins, i))
        {
            return REG_FullRegName(INS_OperandMemoryIndexReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

REG INS_get_memwr_basereg(INS ins)
{
	for (unsigned int i = 0; i < INS_OperandCount(ins); i++)
	{
        if (INS_OperandIsMemory(ins, i) && INS_OperandWritten(ins, i))
        {
            return REG_FullRegName(INS_OperandMemoryBaseReg(ins, i));
        }
    }
    
    return REG_INVALID();
}


//analysis routine:
//three level :function\BBL\instruction

VOID InvokeFunTaint()
{
	string infileName = "c:\\pinInput.txt";
	ADDRINT argu0=0;
	ADDRINT argu1=0;


	in.open(infileName.c_str());


	in >> hex;

	in >> argu0;
	in >> argu1;

	in.close();

	out <<"argu0 " <<argu0 <<endl;

	out <<"argu1 " <<argu1 <<endl;

	if(argu1!=0)
	{
		int n = 2*wcslen((wchar_t *)argu1);
		out <<endl<<"senmatic: argu2"<<endl;
		out << "variable address: "<<argu1<<endl;
		out <<"variable type: BSTR"  << endl;
		out <<"variable length-byte: " << n <<endl;
		ADDRINT taint = (ADDRINT)argu1;
		AddTaint(taint,n,type_WORD);
		InsertTaintInstrumentation();//find taint source , then enable DTA and instruction-level taint analysis
	}
}

VOID funcend(ADDRINT lpWideCharStr,UINT32 cchWideChar,ADDRINT lpMultiByteStr,UINT32 cbMultiByte)
{
	TAINT_Instrumentation_On = 1;//enable instruction-level of DTA in this analysis code instrumented into function
}


VOID funcbegin(ADDRINT lpWideCharStr,UINT32 cchWideChar,ADDRINT lpMultiByteStr,UINT32 cbMultiByte)
{
	TAINT_Instrumentation_On = 0;//disable instruction-level of DTA in this analysis code instrumented into function
	if(TaintedAddrs.count(lpWideCharStr)&&cbMultiByte!=0)
	{
		out<<endl;
		out<<"function summary:"<<endl<<"WideCharToMultiByte()"<<endl;
		out<<"function argu: "<<endl;
		out<<"lpWideCharStr "<< lpWideCharStr << endl;
		out<<"cchWideChar "<< cchWideChar << endl;
		out<<"lpMultiByteStr "<< lpMultiByteStr <<endl;
		out<<"cbMultiByte "<< cbMultiByte <<endl;

			TDS *tds_temp = new TDS;

			tds_temp->source = TaintedAddrs[lpWideCharStr];
			tds_temp->memaddr = lpMultiByteStr;
			tds_temp->var_length = cbMultiByte;
			tds_temp->var_type = type_BYTE;
			tds_temp->offset = 0;

			TaintedAddrs[lpMultiByteStr] = tds_temp;
			
			out <<endl;
			out <<"this variable tainted from address:"<<lpWideCharStr<<endl;
			out <<"tainted variable address: "<<tds_temp->memaddr<<endl;
			out <<"variable type: "<<" character string "<<endl;
			out <<"variable length-byte:"<<tds_temp->var_length<<endl;

			AddTaint(tds_temp->memaddr,tds_temp->var_length,tds_temp->var_type);
	}
}

void bblBegin()
{
	bbl_taintedmem = 0;
}

void TaintedRegPointMem(ADDRINT reg_base, ADDRINT reg_index, ADDRINT mem_w,UINT32 mem_scale,bool index)
{
	TDS * tds_temp = new TDS;
 
//	tds_temp->offset = TaintedRegs[reg_r]->offset;
//	tds_temp->var_length = TaintedRegs[reg_r]->var_length;
	
	switch(mem_scale)
	{
	case 1:
		tds_temp->var_type = type_BYTE;
		break;
	case 2:
		tds_temp->var_type = type_WORD;
		break;
	case 4:
		tds_temp->var_type = type_DWORD;
		break;
	default:
		tds_temp->var_type = type_unknown;
		break;
	}
	tds_temp->memaddr = mem_w;
//	tds_temp->opcode = op;
	if(index)
		tds_temp->source = TaintedRegs[reg_index];
	else
		tds_temp->source = TaintedRegs[reg_base];
	tds_temp->pointer = 0; 

	TaintedAddrs[mem_w] = tds_temp; 


	pointer[reg_base][reg_index].pointer=1;
	pointer[reg_base][reg_index].pointaddr=mem_w;
	pointer[reg_base][reg_index].var_type=tds_temp->var_type;

	out<<endl<<" tainted reg point this untainted mem: "<<reg_base<<" && "<<reg_index<<" type: "<<tds_temp->var_type<<endl;
}


// This function represents the case of a register copied to memory
void RegTaintMem(ADDRINT reg_r, UINT32 mem_scale, ADDRINT reg_base, ADDRINT reg_index, ADDRINT mem_w, UINT32 op,ADDRINT inst_addr)
{
	
    if (TaintedRegs[reg_r]) 
    {
	
		bbl_taintedmem = 1;
		
        TDS *tds_temp = new TDS;
        
		tds_temp->offset = TaintedRegs[reg_r]->offset;
		tds_temp->var_length = TaintedRegs[reg_r]->var_length;
		
		switch(mem_scale)
		{
		case 1:
			tds_temp->var_type = type_BYTE;
			break;
		case 2:
			tds_temp->var_type = type_WORD;
			break;
		case 4:
			tds_temp->var_type = type_DWORD;
			break;
		default:
			tds_temp->var_type = type_unknown;
			break;
		}

        tds_temp->memaddr = mem_w;
		tds_temp->opcode = op;
		tds_temp->source = TaintedRegs[reg_r];
		tds_temp->pointer = TaintedRegs[reg_r]->pointer;
        
		TaintedAddrs[mem_w] = tds_temp;

		if(reg_base!=REG_INVALID())
		{
			pointer[reg_base][reg_index].pointer=1;
			pointer[reg_base][reg_index].pointaddr=mem_w;
			pointer[reg_base][reg_index].var_type = tds_temp->var_type;
		}

		out << " reg point this tainted mem: "<<reg_base<<" && "<<reg_index<<" type: "<<tds_temp->var_type<<endl;

		out << endl;
		out << "register to memory " << inst_addr <<endl;
		if ( op >= XED_ICLASS_MOV && op <= XED_ICLASS_MOVZX)
		{
			out << "MOV " <<" scale: "<<mem_scale<<endl;
			if( mem_w == memRetStack )
			{
				out <<"detect overwriting of function's retaddr at stack!"<<endl;
				out <<"retaddress in stack at: "<<mem_w<<endl;
			}
		}

		out << "T " << mem_w << " source " << TaintedRegs[reg_r]->memaddr<<endl;

       
		
		// for (TDS * t=TaintedAddrs[mem_w];t;t=t->source)
		 //out << "trace " << t->memaddr << endl;
	}
    else //reg not tainted --> mem not tainted
    {
        if (TaintedAddrs.count(mem_w)) // if mem is already not tainted nothing to do
        {
            TaintedAddrs.erase(mem_w);
            out << "U by clean memory addr " << mem_w << endl;
        }
    }
}

// this function represents the case of a memory copied to register
void MemTaintReg(ADDRINT mem_r, UINT32 mem_scale, ADDRINT reg_base, ADDRINT reg_index, ADDRINT reg_w, UINT32 op, ADDRINT inst_addr)//ADDRINT insad)
{

//	out<<"reg_w:"<<reg_w<<endl;
    if (TaintedAddrs.count(mem_r)) //count is either 0 or 1 for set
    {
		TDS *tds_temp = new TDS;

        tds_temp->offset = TaintedAddrs[mem_r]->offset;
		tds_temp->var_length = TaintedAddrs[mem_r]->var_length;
        tds_temp->memaddr = reg_w;
		tds_temp->opcode = op;
		tds_temp->source = TaintedAddrs[mem_r];
		tds_temp->pointer = TaintedAddrs[mem_r]->pointer;

		switch(mem_scale)
		{
		case 1:
			tds_temp->var_type = type_BYTE;
			break;
		case 2:
			tds_temp->var_type = type_WORD;
			break;
		case 4:
			tds_temp->var_type = type_DWORD;
			break;
		default:
			tds_temp->var_type = type_unknown;
			break;
		}

        TaintedRegs[reg_w] = tds_temp; 
	
		if(reg_index!=REG_INVALID())
		{
			
			if(TaintedRegs[reg_index])
			{
				out<<endl<<" tainted reg point this tainted mem: "<<reg_index<<" && "<<reg_base<<" type: "<<tds_temp->var_type<<endl;
				TaintedRegs[reg_index]->pointer=1;
			}
			else if(TaintedRegs[reg_base])
			{
				out<<endl<<" tainted reg point this tainted mem: "<<reg_index<<" && "<<reg_base<<" type: "<<tds_temp->var_type<<endl;
				TaintedRegs[reg_base]->pointer=1;
			}
			else
				out<<endl<<" untainted reg point this tainted mem: "<<reg_index<<" && "<<reg_base<<" type: "<<tds_temp->var_type<<endl;
		}
		else if(reg_base!=REG_INVALID())
		{
			if(TaintedRegs[reg_base])
			{
				out<<endl<<"a tainted reg point this tainted mem: "<<reg_base<<" type: "<<tds_temp->var_type<<endl;
				TaintedRegs[reg_base]->pointer=1;
			}
			else
				out<<endl<<"a untainted reg point this tainted mem: "<<reg_base<<" type: "<<tds_temp->var_type<<endl;
		}

		pointer[reg_base][reg_index].pointer=1;
		pointer[reg_base][reg_index].pointaddr=mem_r;
		pointer[reg_base][reg_index].var_type=tds_temp->var_type;

		out << endl;
		out <<  "memory to register " <<inst_addr<<endl;
		if ( op >= XED_ICLASS_MOV && op <= XED_ICLASS_MOVZX)
			out << "MOV " <<" scale: "<<mem_scale<<endl;
		out << "T " << reg_w << " source " << TaintedAddrs[mem_r]->memaddr <<endl;

    }
	else if(TaintedRegs[reg_index])//first taint index reg
	{

		out << endl;
		out <<"tainted index-register point to this untainted mem "<<inst_addr<<endl;
		//RegTaintMem(reg_index,mem_scale,reg_base,reg_index,mem_r,0,inst_addr);
		TaintedRegPointMem(reg_base,reg_index,mem_r,mem_scale,1);

		TaintedRegs[reg_index]->pointer=1;//after taint mem,set pointer of reg,because can't propagate this attribute to mem
			


		TDS *tds_temp = new TDS;

	    tds_temp->offset = TaintedAddrs[mem_r]->offset;
		tds_temp->var_length = TaintedAddrs[mem_r]->var_length;
		tds_temp->memaddr = reg_w;
		tds_temp->opcode = op;
		tds_temp->source = TaintedRegs[mem_r];
		tds_temp->pointer = TaintedRegs[mem_r]->pointer;

		switch(mem_scale)
		{
		case 1:
			tds_temp->var_type = type_BYTE;
			break;
		case 2:
			tds_temp->var_type = type_WORD;
			break;
		case 4:
			tds_temp->var_type = type_DWORD;
			break;
		default:
			tds_temp->var_type = type_unknown;
			break;
		}

		TaintedRegs[reg_w] = tds_temp;

		if ( op >= XED_ICLASS_MOV && op <= XED_ICLASS_MOVZX)
				out << "MOV " <<" scale: "<<mem_scale<<endl;
		out << "T " << reg_w << " source " << TaintedRegs[mem_r]->memaddr<<endl;

		TaintedAddrs.erase(mem_r);//clean [base+index] after move
	}
	else if(TaintedRegs[reg_base]&&reg_index!=REG_INVALID())//second taint base reg if index reg exist
	{
		out << endl;
		out <<"tainted base-register point to this untainted mem " <<inst_addr<<endl;	
		//RegTaintMem(reg_base,mem_scale,reg_base,reg_index,mem_r,0,inst_addr);
		TaintedRegPointMem(reg_base,reg_index,mem_r,mem_scale,0);//reg_base is the index reg!!!


		TaintedRegs[reg_base]->pointer=1;//after taint mem,set pointer of reg,because can't propagate this attribute to mem

		TDS *tds_temp = new TDS;
		tds_temp->offset = TaintedAddrs[mem_r]->offset;
		tds_temp->var_length = TaintedAddrs[mem_r]->var_length;
		tds_temp->memaddr = reg_w;
		tds_temp->opcode = op;
		tds_temp->source = TaintedAddrs[mem_r];
		tds_temp->pointer = TaintedAddrs[mem_r]->pointer;

		switch(mem_scale)
		{
		case 1:
			tds_temp->var_type = type_BYTE;
			break;
		case 2:
			tds_temp->var_type = type_WORD;
			break;
		case 4:
			tds_temp->var_type = type_DWORD;
			break;
		default:
			tds_temp->var_type = type_unknown;
			break;
		}

		TaintedRegs[reg_w] = tds_temp;

		if ( op >= XED_ICLASS_MOV && op <= XED_ICLASS_MOVZX)
				out << "MOV " <<" scale: "<<mem_scale<<endl;

		out << "T " << reg_w << " source " << TaintedAddrs[mem_r]->memaddr<<endl;

		TaintedAddrs.erase(mem_r);//clean [base+index] after move

	}
	else 
	{
		TaintedRegs[reg_w] = NULL;
	}
}

// this function represents the case of a reg copied to another reg
void RegTaintReg(ADDRINT reg_r, ADDRINT reg_w, UINT32 op,ADDRINT inst_addr)
{
	if(TaintedRegs[reg_r])
	{

		out << endl;
		out <<  "register to register " <<inst_addr<<endl;	

		TDS *tds_temp = new TDS;
		tds_temp->offset = TaintedRegs[reg_r]->offset;
		tds_temp->var_length = TaintedRegs[reg_r]->var_length;
		tds_temp->var_type = TaintedRegs[reg_r]->var_type;
		tds_temp->memaddr = reg_w;
		tds_temp->opcode = op;
		tds_temp->source = TaintedRegs[reg_r];
		tds_temp->pointer = TaintedRegs[reg_r]->pointer;

		TaintedRegs[reg_w] = tds_temp;
		
		if ( op >= XED_ICLASS_MOV && op <= XED_ICLASS_MOVZX)
				out << "MOV " <<endl;
		
		out << "T " << reg_w << " source " << TaintedRegs[reg_r]->memaddr<<endl; //<< " as well as"<< TaintedAddrs[mem_w]<< "ins "<< inst_addr<< endl;
      
	}

	else //reg is clean -> reg is cleaned
    {
        TaintedRegs[reg_w] = NULL;
    }
}

// this function represents the case of an immediate copied to a register
void ImmedCleanReg(ADDRINT reg_w)
{
    TaintedRegs[reg_w] = NULL;
}

// this function represent the case of an immediate copied to memory
void ImmedCleanMem(ADDRINT mem_w)
{
    if (TaintedAddrs.count(mem_w)) // if mem is already not tainted nothing to do
    {
		out << " U by immediate #  " << mem_w << endl;
        TaintedAddrs.erase(mem_w);
    }
}
void MemofRetAddr(ADDRINT mem_w)
{
	memRetStack = mem_w;
	//out << mem_w <<endl;
}

//check EIP tainted?
void checkEIP(ADDRINT ins_addr)
{
	if(TaintedAddrs.count(ins_addr))
	{
		out << "attack!" << endl;
		out <<"instruction address:"<<ins_addr<<endl;
		TAINT_Analysis_On = 0;
	}
}



//instrumentation routine :
//two way:IMG TRACE 

VOID Trace(TRACE trace, VOID *v)
{
	if(TAINT_Analysis_On&&TAINT_Instrumentation_On)
	{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
  {
	  if(bbl_taintedmem)
	  BBL_InsertCall(bbl,IPOINT_BEFORE,(AFUNPTR)bblBegin,IARG_END);

	  
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)checkEIP,IARG_INST_PTR,IARG_END);
	
		if(INS_IsCall(ins))//detect overflow of stack
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemofRetAddr,
                                            IARG_MEMORYOP_EA, 0,
                                            IARG_END);
		}
        if ( INS_Opcode(ins) >= XED_ICLASS_MOV && INS_Opcode(ins) <= XED_ICLASS_MOVZX )//&& INS_Address(ins) == 0x7c80a2f0)//||INS_Address(ins)==0x7c80a2f3))//||( (INS_Opcode(ins) >= XED_ICLASS_POP) && (INS_Opcode(ins) <= XED_ICLASS_POPFQ))||((INS_Opcode(ins) >= XED_ICLASS_PUSH) && (INS_Opcode(ins) <= XED_ICLASS_PUSHFQ))||(INS_Opcode(ins) == XED_ICLASS_LEA))
        {
		
            if (INS_has_immed(ins))
            {
                if (INS_IsMemoryWrite(ins)) //immed -> mem
                {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ImmedCleanMem,
                                            IARG_MEMORYOP_EA, 0,
                                            IARG_END);
                }
                else						//immed -> reg
                {
                    REG insreg1 = INS_get_write_reg(ins);
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ImmedCleanReg,
                                            IARG_ADDRINT, (ADDRINT)insreg1,
                                            IARG_END);
                }
            }
            else if (INS_IsMemoryRead(ins)) //mem -> reg 
            {
                //in this case we call MemTaintReg to copy the taint if relevant
                REG insreg2 = INS_get_write_reg(ins);
				REG basereg2 = INS_get_mem_basereg(ins);
				REG indexreg2 = INS_get_mem_indexreg(ins);

				//ADDRINT insadd = INS_Address(ins);
				//string insdis = INS_Disassemble(ins);
				//out <<  "instruction 2 opcode " << INS_Opcode(ins)<<endl;
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemTaintReg,
                                        IARG_MEMORYOP_EA, 0,
										IARG_UINT32,INS_MemoryScale(ins),
										IARG_ADDRINT, (ADDRINT)basereg2,
										IARG_ADDRINT, (ADDRINT)indexreg2,
                                        IARG_ADDRINT, (ADDRINT)insreg2,										
										IARG_UINT32, INS_Opcode(ins),
										IARG_INST_PTR,
                                        IARG_END);


            }
            else if (INS_IsMemoryWrite(ins)) //reg -> mem 
            {
                //in this case we call RegTaintMem to copy the taint if relevant
                REG insreg3 = INS_get_read_reg(ins);
				REG basereg3 = INS_get_memwr_basereg(ins);
				REG indexreg3 = INS_get_memwr_indexreg(ins);
				//ADDRINT insadd = INS_Address(ins);
				//IARG_INST_PTR


                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegTaintMem,
                                        IARG_ADDRINT,(ADDRINT)insreg3,
										IARG_UINT32,INS_MemoryScale(ins),
										IARG_ADDRINT, (ADDRINT)basereg3,
                                        IARG_ADDRINT, (ADDRINT)indexreg3,	
										IARG_MEMORYOP_EA, 0,
										IARG_UINT32, INS_Opcode(ins),
										IARG_INST_PTR,
										IARG_END);
            }
            else if (INS_RegR(ins, 0) != REG_INVALID()) //reg -> reg
            {
                //in this case we call RegTaintReg
                REG Rreg = INS_get_read_reg(ins); 
                REG Wreg = INS_get_write_reg(ins);
				//ADDRINT insadd = INS_Address(ins);
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegTaintReg,
                                        IARG_ADDRINT, (ADDRINT)Rreg,
                                        IARG_ADDRINT, (ADDRINT)Wreg,
										IARG_UINT32, INS_Opcode(ins),
										IARG_INST_PTR,
										IARG_END);
            }
            else	//should never happen
            {
                out << "serious error?!\n" << endl;
            }		
		} // IF opcode is a MOV
		/*
		if(bbl_taintedmem == 1&&INS_IsBranch(ins))
		{
			out << BBL_Address(bbl) <<endl;
			out << INS_Address(ins)<<endl;
			out << INS_NextAddress(ins)<<endl;
			out << INS_DirectBranchOrCallTargetAddress(ins)<<endl;
			out << " taintBBL: "<<endl;
			out << INS_Disassemble(ins) <<endl;
			if(INS_NextAddress(ins)>=BBL_Address(bbl)&&INS_NextAddress(ins)<=INS_Address(ins))
			{
				out << "find bbl loop"<<endl;
				//bblLoop = 1;
			}
		}
		*/
		if(bbl_taintedmem ==1 && ins==BBL_InsTail(bbl))
		{
//			out <<"find tainted bbl " <<endl;
//			out <<"bbl start address: "<< BBL_Address(bbl) <<endl;
//			out <<"bbl size: "<<BBL_Size(bbl) << endl;
//			out <<"bbl head: "<< INS_Disassemble(BBL_InsHead(bbl))<<endl;
//			out <<"bbl tail: "<< INS_Disassemble(ins) <<endl;
			if(INS_DirectBranchOrCallTargetAddress(ins)>=BBL_Address(bbl)&&INS_DirectBranchOrCallTargetAddress(ins)<=INS_Address(ins))
			{
				out<<endl<<"this tainted bbl is a loop"<<endl;
				//BBL_InsertCall(bbl,IPOINT_AFTER,(AFUNPTR)loopBblEnd,IARG_END);
			}
		}
    }// For INS
  }  // For BBL
  }//for enable DTA
} // VOID Trace

VOID rtnInst(IMG img, VOID *v)
{
//	for(IMG temp = img; IMG_Valid(temp); temp = IMG_Next(temp))

//	out <<IMG_Name(img)<<endl;
	
//	char * temp = "KVWebSvr.dll";
	string dllname = IMG_Name(img);
	RTN dispatchRtn;
	ADDRINT funaddr;
	if(dllname.find("KVWebSvr.dll")!=string::npos)
	{
		

		out <<dllname<<"start address 0x " <<IMG_LowAddress(img) <<endl;
		out <<dllname<<"end address 0x "<<IMG_HighAddress(img) <<endl;

		funaddr = IMG_LowAddress(img)+0x18060;

//		RTN_CreateAt(0x100183b0,"sub_100183b0");//022D8060

//		RTN_CreateAt(0x022D8060,"sub_invoke");

//		dispatchRtn = RTN_FindByName(img, "sub_invoke");

		RTN_CreateAt(funaddr,"sub_invoke");

//		RTN_CreateAt(0x10019210,"sub_10019210");

		dispatchRtn = RTN_FindByName(img, "sub_invoke");
//		dispatchRtn = RTN_FindByAddress(0x100183b0);

		if (RTN_Valid(dispatchRtn))
		{
			out << "find the taint source function" << endl;
			RTN_Open(dispatchRtn);
			RTN_InsertCall(dispatchRtn,IPOINT_BEFORE,(AFUNPTR)InvokeFunTaint,IARG_END);

//			RTN_InsertCall(dispatchRtn, IPOINT_BEFORE, (AFUNPTR)InputFunAddTaint,
//                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
//                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
//					   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
//                       IARG_END);

			RTN_Close(dispatchRtn);
//			out << RTN_Address(dispatchRtn)<< endl;
		}
	}


	//function-level taint

	inst_func_summary(img);
}

VOID InstructionProp(INS ins, VOID *v)
{
	PIN_LockClient();
	for (IMG image = APP_ImgHead();image!=IMG_Invalid();image=IMG_Next(image))
	{
		inst_func_summary(image);
	}
	PIN_UnlockClient();

}


VOID Fini(INT32 code, VOID *v)
{
	//out<<tempbuffer<<endl;
    //DumpTaint();
    out.close();
}



/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
    cout << "At follow child callback" << endl << flush;
    cout << "Child process id = " << CHILD_PROCESS_GetId(childProcess) << endl << flush;
//	int argc = 4;
//	char *argv[4];
//	argv[0]="c:\\axmock-commit_1013\\bin\\pin.exe";
//	argv[1]="-t";
//	argv[2]="c:\\axmock-commit_1013\\bin\\findinvoke.dll";
//	argv[3]="--";
		//["c:\\mypin\\pin.exe", "-t","c:\\mypin\\findinvoke.dll","--"];
//	CHILD_PROCESS_SetPinCommandLine(childProcess,argc,argv);
    return TRUE;
}


int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 

    
	PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }


    
    // Register function to be called to instrument traces
    
//	PIN_AddSyscallEntryFunction(SyscallEntryF,0);
//  PIN_AddSyscallExitFunction(SyscallExitF,0);

//	TRACE_AddInstrumentFunction(TraceIns, 0);

//	INS_AddInstrumentFunction(Instruction,0);

	PIN_AddFollowChildProcessFunction(FollowChild, 0);

	IMG_AddInstrumentFunction(rtnInst, 0);

//	INS_AddInstrumentFunction(InstructionProp, 0);//for function summary




	TRACE_AddInstrumentFunction(Trace, 0);

	// Register function to be called when the application exits


	
	PIN_AddFiniFunction(Fini, 0);
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;

        string fileName = KnobOutputFile.Value();



		out.open(fileName.c_str());
		out << hex;
//        out.open(fileName.c_str());
//        out << hex;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
