# What is it
Fic is a work-in-progress Z-Machine interpreter for Windows/Mac/Linux written in Python. Currently supports most V3 Z-Code games, minus The Lurking Horror and the fancy features of Seastalker. It might even support Z1/Z2, unless you type numbers..? I really need write test cases...

# Usage
- Install the Python pre-reqs as per requirements.txt
-     python fic.py <your Z-code game>

# Dones
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
- input_stream
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
- nop
- not
- or
- output_stream
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
- pop
- restore
- rfalse
- rtrue
- save
- set_attr
- show_status
- store
- storeb
- storew
- sub
- test
- test_attr
- verify

# TODOs
## Enhancements
- Better recording/replaying - prompt for filenames on input_stream = 1, output_stream = 4

## Refactor
- Split Memory into multiple classes
- Lots of mixing of underscore variable names + camelcase
- getOpcode needs tidying - mixes decimal with hex

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

## Opcodes remaining for v3 in general
- sound_effect (for Lurking Horror only)

## Opcodes remaining for v4
- call_2s
- call_1s
- save (v4)
- restore (v5)
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
- output_stream (REDIRECT)

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
