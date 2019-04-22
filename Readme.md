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

## Opcodes remaining for v1
- pop

## Opcodes remaining for v3 in general
- show_status
- restore
- save
- verify
- split_window
- set_window
- output_stream
- input_stream
- not (1OP)

## Opcodes remaining for v4
- call_2s
- call_1s
- call_1n
- save (v4)
- restore (v5)
- NOT call_vs (replaces call from v1)
- sread (v4 - adds time + callback interrupt)
- call_vs2
- erase_window
- erase_line
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
