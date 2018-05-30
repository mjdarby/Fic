* What is it
KnightFic is a Z-Machine interpreter for Windows/Mac/Linux written in Python

* TODOs

** Read-write
- Reading story file
- Writing save files

** Architecture
- PC
- Stack
- Global variables (table begins at word 6, or byte 12)
- Local variables
- Hardware interaction
- Memory map - Done
- R_O - Done
- R_S - Done
- Random number generator
-- Seeding
-- Predictable
-- True random
- ZSCII
- Reading instructions - Branching and some other stuff left
- Executing instructions
- Decode packed addresses - Done
- Calling routines - Setting initial values
- Calling routines - Managing the routine call-stack

** Opcodes
- All
- Factor out the argument decoding

Rename 'getNumber' to 'getWord'?