# What is it
Fic is a work-in-progress Z-Machine interpreter for Windows/Mac/Linux written in Python.

# TODOs
## Read-write
- Reading story file
- Writing save files

## Architecture
- PC - Done
- Stack - Done
- Global variables - Done
- Local variables - Done
- Hardware interaction
- Memory map - Done
- R_O - Done
- R_S - Done
- Random number generator
  - Seeding
  - Predictable
  - True random
- ZSCII - Done?
- Reading instructions - Done
- Executing instructions - Done
- Decode packed addresses - Done
- Calling routines - Setting initial values - Done
- Calling routines - Managing the routine call-stack - Done

## Opcodes
- Factor out the argument decoding - Done
- DEC
- DIV
- GET_NEXT_PROP
- LOAD
- MOD
- OR
- RANDOM
- READ

- QUIT
- RESTART
- RESTORE
- SAVE
- VERIFY

## Maybes
- Rename 'getNumber' to 'getWord'?

## Known issues
- Negative number storage - currently do not correctly convert to negative form