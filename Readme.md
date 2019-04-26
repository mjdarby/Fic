# What is it
Fic is a work-in-progress Z-Machine interpreter for Windows/Mac/Linux written in Python.

# TODOs
## Read-write
- Reading story file
- Writing save files

## Architecture / Done
- PC
- Stack
- Global variables
- Local variables
- Memory map
- R_O
- R_S
- ZSCII
- Reading instructions
- Executing instructions
- Decode packed addresses
- Calling routines - Setting initial values
- Calling routines - Managing the routine call-stack

## Architecture / To Do
- Screen model
  - Setting screen dimensions
  - Split screen support
- Input/output streams
- Sound effects
- Random number generator
  - Seeding
  - Predictable
  - True random

## Opcodes implemented
- add
- and
- call
- clear_attr
- dec
- dec_chk
- div
- get_child
- get\_next_prop
- get_parent
- get_prop
- get\_prop_addr
- get\_prop_len
- get_sibling
- inc
- inc_chk
- insert_obj
- je
- jg
- jin
- jl
- jump
- jz
- load
- loadb
- loadw
- mod
- mul
- new_line
- or
- print
- print_addr
- print_char
- print_num
- print_obj
- print_paddr
- print_ret
- pull
- push
- put_prop
- quit
- random
- read
- remove_obj
- restart
- ret
- ret_popped
- rfalse
- rtrue
- set_attr
- show_status
- store
- storeb
- storew
- sub
- test
- test_attr
- verify

## Opcodes remaining for Zork 1 / Seastalker (v3) to work
- restore
- save

## Opcodes remaining for v1
- pop
- nop

## Opcodes remaining for v3 in general
- save
- restore
- output_stream (seem to be used more for debug commands)
- input_stream
- not (1OP)
- sound_effect (probably)
- split_window (can delay implementation by disabling upper window in flags 1)
- set_window (can delay implementation by disabling upper window in flags 1)

## Opcodes remaining for v4
- call_2s
- call_1s
- save (v4)
- restore (v5)
- NOT call_vs (replaces call from v1)
- sread (v4 - adds time + callback interrupt)
- call_vs2
- erase_window
- erase_line
- get_cursor
- set_cursor
- set_text_style
- buffer_mode
- read_char
- scan_table

## Opcodes remaining for v5
- call_2n
- set_colour
- throw
- call_1n
- save (v5, becomes EXT)
- restore (v5, becomes EXT)
- catch
- piracy
- aread (v5)
- output_stream (v5)
- not (v5)
- call_vn
- call_vn2
- tokenise
- encode_text
- copy_table
- print_table
- check\_arg\_count
- log_shift
- art_shift
- set_font
- save_undo
- restore_undo
- print_unicode
- check_unicode

## Opcodes remaining for v6
- set_colour (v6)
- pull (v6)
- erase_line (v6)
- set_cursor (v6)
- output_stream (v6)
- draw_picture
- picture_data
- erase_picture
- set_margins
- move_window
- window_size
- window_style
- get\_wind_prop
- scroll_window
- pop_stack
- read_mouse
- mouse_window
- push_stack
- put\_wind_prop
- print_form
- make_menu
- picture_table

## Known issues
- Negative number storage - currently do not correctly convert to negative form
