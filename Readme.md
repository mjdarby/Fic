# Fic
Fic is a work-in-progress Z-Machine interpreter for Windows/Mac/Linux written in Python 3. It is for use on the terminal, and has been 'tested' in Windows Command Prompt, Windows Powershell, xfce4-terminal

Currently 'supports' all V3 Z-Code games, minus the sound in The Lurking Horror. V1/V2 is mostly supported, except for one edge case where you use two digits in a row for input. Support for V4 is partial, minus games that require timed input.

Work is ongoing for full V4/V5(/V7/V8) support. Will likely never touch V6.

## Usage
- If on Windows, install the Python pre-reqs as per requirements.txt
- Linux users probably already have everything they need on Python 3.7+
-     python fic.py <your Z-code game>

## Known Issues
- Resizing the terminal will do all sorts of horrible things to the interpreter. In this classic scenario of 'Doctor, It Hurts When I...', I suggest you don't resize the window while playing.
- Save files append a space to the end on write..?

## Reporting bugs
Please open a Github issue with a screenshot/copy-paste of the bug you've encountered, and provide:
- the game file that has the issue (if non-commerical!)
- a save file close to the issue, if applicable
- the commands you entered to cause the issue (preferably after the save file)
- your operating system + terminal

## Contributing
If you want to contribute to Fic development, please feel free to raise a pull request! We'll work out the guidelines for this as we go along. Fic is licensed under GPLv3, so any contributions made will also fall under this license.

It's a pain to integration test this stuff, but I recently discovered the joys of CZECH by Amir Karger - so the first little rule we could have is that you run the CZECH suite against v3 + v4 and make sure the score/output you get isn't worse than what we started with. You can find the suite [here](https://www.ifarchive.org/indexes/if-archive/infocom/interpreters/tools/). You'll need to install Inform, but otherwise the Readme is self-explanatory.

# Technical stuff
## Dones
### Opcodes implemented
- add
- and
- art_shift
- buffer_mode
- call
- call_1n
- call_1s
- call_2n
- call_2s
- call_vn
- call_vn2
- call_vs2
- check\_arg\_count
- clear_attr
- dec
- dec_chk
- div
- erase_line
- erase_window
- get_child
- get_cursor
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
- log_shift
- mod
- mul
- new_line
- nop
- not
- not (v5) - instruction moved
- or
- output_stream
- piracy
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
- read_char - minus timing
- remove_obj
- restart
- ret
- ret_popped
- pop
- restore
- restore_undo
- rfalse
- rtrue
- save
- save_undo
- scan_table
- set_attr
- set_colour
- set_cursor
- set_font - basically dummied
- set\_text\_style - minus fixed pitch
- show_status
- store
- storeb
- storew
- sub
- test
- test_attr
- tokenise
- verify

## TODOs
### Enhancements
- Better recording/replaying - prompt for filenames on input\_stream = 1, output\_stream = 4
- '[MORE]' prompts
- Introduce proper sys args stuff, kill the last of the easy-to-see exceptions
  - Give the user lots of cool options
- Implement Queztal save files - if only because the save fil format for Fic will break constantly as opcodes demand memory structure changes
- Unit tests for each opcode
- Full game run tests using replays (only confirm that we reach the end of the game, not that the display is correct)

### Refactor
- Split Memory into multiple classes
- Lots of mixing of underscore variable names + camelcase
- getOpcode needs tidying - mixes decimal with hex
- isAttributeSet/setAttribute needs tidying up
- Split rendering logic out into entirely separate class and loop
  - Preparation for creating GUI client?
- So many magic numbers you can call me Penn AND Teller.

### Architecture / To Do
- Input streams
  - Specifically of read input as only input/output characters
  - Easier/better way of handling replays outside of built-in #comm commands
- Sound effects
- Random number generator
  - Predictable mode

### Opcodes remaining for v3 in general
- sound_effect (for Lurking Horror only) (currently dummied)

### Opcodes remaining for v4
- sread (v4 - adds time + callback interrupt)
- read_char (time + callback interrupt)
- set\_text\_style - Fixed Pitch..? This is a terminal application, so we don't really get a choice

### Opcodes remaining for v5 - ordered by perceived difficulty
- scan_table (form operand)
- aread (v5)
- output_stream (v5)
- encode_text
- copy_table
- save (v5, becomes EXT)
- restore (v5, becomes EXT)
- print_table
- catch
- throw

### Opcodes remaining for v5 - Extension
- print_unicode
- check_unicode
- set\_true\_colour

### Opcodes remaining for v6
- set_colour (v6)
- set_font (v6)
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

### Opcodes remaining for v6 - Extension
- set\_true\_colour (with window)
- buffer_screen
