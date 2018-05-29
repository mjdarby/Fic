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
- Hardware interaction
- Memory map - Done
- R_O - Done
- R_S - Done
- Random number generator
-- Seeding
-- Predictable
-- True random
- ZSCII
- Reading instructions
- Executing instructions
- Decode packed addresses - Done?

** Opcodes
- All