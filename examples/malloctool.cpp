#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#define MALLOC "malloc"
#define FREE "free"
#define FREE "realloc"

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "malloctrace.out", "specify trace file name");
KNOB<BOOL> KnobValues(KNOB_MODE_WRITEONCE, "pintool",
    "values", "1", "Output memory values reads and written");
KNOB<UINT32> KnobThreshold(KNOB_MODE_WRITEONCE, "pintool",
    "k","400", "Initial threshold");

int MallocRegions = 0;
unsigned int MallocArrayLocation[1000]; 
int MallocArraySize[1000];
int MallocArrayValid[1000];
int MallocArrayAccesses[1000];

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */
VOID FreeBefore(CHAR * name, ADDRINT location)
{
  int i;
   for (i = 0; i < MallocRegions; i++ ) {
	if (MallocArrayLocation[i] == location) {
             MallocArrayValid[i] = 0;
        }
   }
}
VOID ReallocBefore(CHAR * name, ADDRINT size)
{
    // TraceFile << name << "(" << size << ")" << endl;
}
 
VOID MallocBefore(CHAR * name, ADDRINT size)
{
    // TraceFile << name << "(" << size << ")" << endl;

    MallocArraySize[MallocRegions] = size;
    MallocArrayValid[MallocRegions] = 1;
}

VOID MallocAfter(ADDRINT ret)
{
    // TraceFile << "  returns " << ret << endl;
    MallocArrayLocation[MallocRegions] = ret;
    MallocRegions = MallocRegions + 1;
}


/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
   
VOID Image(IMG img, VOID *v)
{
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    //
    //  Find the malloc() function.
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
    // Find the free() function.
    RTN reallocRtn = RTN_FindByName(img, REALLOC);
    if (RTN_Valid(reallocRtn))
    {
        RTN_Open(reallocRtn);
        RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                       IARG_ADDRINT, REALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(reallocRtn);
    }
}




/* ===================================================================== */


/* ===================================================================== */

static INT32 Usage()
{
    cerr <<
        "This tool produces a memory address trace.\n"
        "For each (dynamic) instruction reading or writing to memory the the ip and ea are recorded\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}


static VOID RecordMem(VOID * ip, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{

   int i;
   for (i= 0; i < MallocRegions; i++ ) {

      if (MallocArrayValid[i] == 0) 
	continue;

      if ((unsigned int) addr  < MallocArrayLocation[i]) 
	continue;

      if ((unsigned int) addr <  MallocArrayLocation[i] + MallocArraySize[i])   {
		MallocArrayAccesses[i] = MallocArrayAccesses[i] + 1;
		return;
      }
   }

}

static VOID RecordMemWrite(VOID * ip, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{

   int i;
   for (i= 0; i < MallocRegions; i++ ) {

      if (MallocArrayValid[i] == 0) 
	continue;

      if ((unsigned int) addr  < MallocArrayLocation[i]) 
	continue;

      if ((unsigned int) addr <  MallocArrayLocation[i] + MallocArraySize[i])   {
		MallocArrayAccesses[i] = MallocArrayAccesses[i] + 1;
		return;
      }
   }
}

VOID Instruction(INS ins, VOID *v)
{

    // instruments loads using a predicated call, i.e.
    // the call happens iff the load will be actually executed
        
    if (INS_IsMemoryRead(ins))
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
            IARG_INST_PTR,
            IARG_UINT32, 'R',
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_UINT32, INS_IsPrefetch(ins),
            IARG_END);
    }

    // instruments stores using a predicated call, i.e.
    // the call happens iff the store will be actually executed
    if (INS_IsMemoryWrite(ins))
    {

       INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
            IARG_INST_PTR,
            IARG_UINT32, 'W',
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_UINT32, INS_IsPrefetch(ins),
            IARG_END);
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
   int i;
    TraceFile << "Malloc Region Information" << endl;

    for (i=0; i < MallocRegions; i++) {
	

	if (MallocArrayValid[i] == 0)
	  continue;

	TraceFile << "Malloc region " << i << " [size, location, accesses] = ";
	TraceFile << MallocArraySize[i] << " ";
        TraceFile << hex << MallocArrayLocation[i] << " ";
	TraceFile << dec << MallocArrayAccesses[i] << endl;
    }
    
    TraceFile.close();
}


int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
 
    // Write to a file since cout and cerr maybe closed by the application
    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile.setf(ios::showbase);
    
    // Register Image and INS to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);
    //INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

