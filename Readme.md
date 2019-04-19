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
- store
- storeb
- storew
- sub
- test
- test_attr

## Opcodes remaining for Zork 1 (v3) to work
- restore
- save
- verify

## Other opcodes to implement
- aread
- art_shift
- buffer_mode
- call_1n
- call_1s
- call_2n
- call_2s
- call_vn
- call_vn2
- call_vs
- call_vs2
- catch
- check\_arg_count
- check_unicode
- copy_table
- draw_picture
- encode_text
- erase_line
- erase_picture
- erase_window
- get_cursor
- get\_wind_prop
- input_stream
- log_shift
- make_menu
- mouse_window
- move_window
- nop
- not
- output_stream
- picture_data
- picture_table
- piracy
- pop
- pop_stack
- print_form
- print_table
- print_unicode
- push_stack
- put\_wind_prop
- read_char
- read_mouse
- restore_undo
- save_undo
- scan_table
- scroll_window
- set_colour
- set_cursor
- set_font
- set_margins
- set\_text_style
- set_window
- show_status
- sound_effect
- split_window
- sread - time/routine
- throw
- tokenise
- window_size
- window_style

## Maybes
- Rename 'getNumber' to 'getWord'?

## Known issues
- Negative number storage - currently do not correctly convert to negative form
