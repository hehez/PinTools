# PinTools

## examples

### control flow trace
  This tool will capture direct and indirect branches in a program at runtime. This type of dynamic analysis technique becomes  increasingly popular in the context of software testing and debugging. You will use Intel PIN to observe and instrument a program at runtime. 

### data dependency slice
  This tool has two modules: 
  1) A pintool that uses shadow memory technique to capture data dependence edges at runtime and generates an output; 
  2) A standalone tool (written in C, C++ or Python) that reads the output of Pintool to identify complete slices for a given slice criterion.
  
### recording and replay
  This tool has two modules: 
  1) a recording module captures non deterministic inputs (e.g., non deterministic system calls, signals, library calls) and stores into a file; 
  2) a replay module replays non  deterministic events (restore input from the file and bypass the events).
