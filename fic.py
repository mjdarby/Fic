#!/usr/bin/python3

import pickle
import traceback
import sys
import random
import time
import textwrap
import re
import os
import ctypes
import struct
import math
import curses
import curses.textpad
from enum import Enum

# Enums
Form = Enum('Form', 'Short Long Variable Extended')
Operand = Enum('Operand', 'ZeroOP OneOP TwoOP VAR')
OperandType = Enum('OperandType', 'Large Small Variable')
Alphabet = Enum('Alphabet', 'A0 A1 A2')

# 'Needs'
NeedBranchOffset = ["jin","jg","jl","je","inc_chk","dec_chk","jz","get_child","get_sibling","save1","restore1","test_attr","test","verify", "scan_table", "piracy", "check_arg_count"]
NeedStoreVariable = ["call","and","get_parent","get_child","get_sibling","get_prop","add","sub","mul","div","mod","loadw","loadb", "get_prop_addr", "get_prop_len", "get_next_prop", "random", "load", "and", "or", "not", "call_2s", "call_vs2", "call_1s", "call_vs", "read_char", "scan_table", "save4", "restore4", "art_shift", "log_shift", "set_font", "read5", "save_undo", "catch"]
NeedTextLiteral = ["print","print_ret"]

# Alphabet
a0 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y', 'z']))
a1 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y', 'Z']))
a2 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['`','\n','0','1','2','3','4','5','6','7','8','9','.',',','!','?','_','#','\'','"','/','\\','-',':','(', ')']))
a2_v1 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
                 ['`','0','1','2','3','4','5','6','7','8','9','.',',','!','?','_','#','\'','"','/','\\','<','-',':','(', ')']))

input_map = dict(zip(['`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y', 'z', '\n','0','1','2','3','4','5','6','7','8','9','.',',','!','?','_','#','\'','"','/','\\','-',':','(', ')'],
                     [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]))


# Logging
tracefile = open('trace.txt', 'w', buffering=1)
logfile = open('full_log.txt', 'w', buffering=1)
transcript = open('transcript.txt', 'w', buffering=1)
commands = open('commands.txt', 'w', buffering=1)

TRACEPRINT = False
LOGPRINT = False
CZECH_MODE = False

MAX_SAVE_FILE_LENGTH = 20

stdscr = None
input_win = None
colour_map = dict()
main_memory = None

def callCallback():
  main_memory.callbackTriggered = True
  input_win.ungetch(curses.ascii.BEL)

# Horrific code, don't actually do this
def cursesValidator(ch):
  if ch == -1:
    main_memory.callbackTriggered = True
    main_memory.callbackCurrentXPos = input_win.getyx()[1]
    ch = curses.ascii.BEL
  return ch

def printTrace(*string, end=''):
  if TRACEPRINT:
    print(string, end=end, file=tracefile)

def printLog(*string):
  if LOGPRINT:
    print(string, file=logfile)

def buildColourMap():
  # Builds every possible colour pair between the available curses colours,
  # which happen to neatly line up with the Z-Machine colours (without extensions)
  i = 1
  for fore in [curses.COLOR_BLACK, curses.COLOR_BLUE, curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_MAGENTA, curses.COLOR_RED, curses.COLOR_WHITE, curses.COLOR_YELLOW]:
    for back in [curses.COLOR_BLACK, curses.COLOR_BLUE, curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_MAGENTA, curses.COLOR_RED, curses.COLOR_WHITE, curses.COLOR_YELLOW]:
      curses.init_pair(i, fore, back)
      colour_map[(fore, back)] = curses.color_pair(i)
      i += 1

def cursesKeyToZscii(cstring):
  if cstring == 'KEY_DC':
    return 8
  if cstring == 'KEY_BACKSPACE':
    return 8
  if cstring == '\n':
    return 13
  if cstring == '^[':
    return 27
  if cstring == 'KEY_UP':
    return 129
  if cstring == 'KEY_DOWN':
    return 130
  if cstring == 'KEY_LEFT':
    return 131
  if cstring == 'KEY_RIGHT':
    return 132
  if cstring == 'KEY_F(1)':
    return 133
  if cstring == 'KEY_F(2)':
    return 134
  if cstring == 'KEY_F(3)':
    return 135
  if cstring == 'KEY_F(4)':
    return 136
  if cstring == 'KEY_F(5)':
    return 137
  if cstring == 'KEY_F(6)':
    return 138
  if cstring == 'KEY_F(7)':
    return 139
  if cstring == 'KEY_F(8)':
    return 140
  if cstring == 'KEY_F(9)':
    return 141
  if cstring == 'KEY_F(10)':
    return 142
  if cstring == 'KEY_F(11)':
    return 143
  if cstring == 'KEY_F(12)':
    return 144
  # Numpad support would go here, except Curses can't differentiate between
  # numpad keys and the regular arrow keys. Stick with numlock.
  if cstring in " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'abcdefghijklmnopqrstuvwxyz{|}~":
    return ord(cstring)
  return 0

# Instruction
class Instruction:
  def __init__(self,
               opcode,
               operand_types,
               operands,
               store_variable,
               branch_on_true,
               branch_offset,
               text_to_print,
               encoded_string_literal,
               instr_length,
               func,
               first_opcode_byte):
    self.opcode = opcode # Debugging
    self.operand_types = operand_types
    self.operands = operands
    self.store_variable = store_variable
    self.branch_on_true = branch_on_true
    self.branch_offset = branch_offset
    self.text_to_print = text_to_print
    self.encoded_string_literal = encoded_string_literal
    self.instr_length = instr_length
    self.func = func
    self.my_byte = first_opcode_byte

  def run(self, main_memory):
    printTrace("Running opcode: " + str(self.my_byte) + " " + str(self.opcode), end="\n")
    end_loop = self.func(self)
    printLog("end_loop value:", end_loop)
    return end_loop

  def print_debug(self):
    printLog("Printing instr debug")
    printLog(self.opcode)
    printLog(self.operand_types)
    printLog(self.operands)
    for operand in self.operands:
      printLog(hex(operand))
    printLog(self.store_variable)
    printLog(self.branch_offset)
    printLog(self.text_to_print)

# StoryLoader returns a memory map
class StoryLoader:
  def LoadZFile(filename):
    f = open(filename, "rb")
    memory = f.read()
    return Memory(memory)

class RoutineCall:
  def __init__(self):
    self.local_variables = []
    self.stack_state = []
    self.stack = []
    self.called_arg_count = 0
    self.frame_pointer = 0
    self.is_callback = False
    self.return_address = 0x0000


  def print_debug(self):
    printLog("Routine call")
    printLog("Local vars " + str(self.local_variables))
    printLog("Stack " + str(self.stack))
    for var in self.local_variables:
      printLog(var)

# Utility
def getSignedEquivalent(num):
  if num > 0x7FFF:
    num = 0x10000 - num
    num = -num
  return num

def getHexValue(num):
  if num < 0:
    num = 0x10000 + num
  return num

def isNthBitSet(byte, bit):
  return  (byte & (1 << bit)) == (1 << bit)

def setNthBit(byte, bit, val):
  if val:
    return (byte | (1 << bit))
  else:
    return (byte & ~(1 << bit))

# Memory - broken up into dynamic/high/static
class Memory:
  def __init__(self, memory_print):
    self.raw = memory_print
    self.mem = bytearray(memory_print)
    self.version = self.mem[0x00]
    self.dynamic = 0
    self.static = self.mem[0x0e]
    self.high = self.mem[0x04]
    self.routine_offset = self.mem[0x28]
    self.string_offset = self.mem[0x2a]
    self.global_table_start = self.getWord(0x0c)
    self.object_table_start = self.getWord(0x0a)
    self.abbreviation_table_start = self.getWord(0x18)
    self.dictionary_table_start = self.getWord(0x08)
    self.stack = []
    self.routine_callstack = []
    self.lock_alphabets = []
    self.current_abbrev = None
    self.ten_bit_zscii_bytes_needed = None
    self.ten_bit_zscii_bytes = None
    self.word_separators = []
    self.dictionary_mapping = dict()
    self.timedGame = False
    self.bufferText = True
    self.transcript = ""
    self.getFirstAddress()
    self.setFlags()
    self.setScreenDimensions()
    self.setDefaultColours()
    self.setInterpreterNumberVersion(2, ord('I')) # Beyond Zork...
    self.active_output_streams = [1]
    self.stream = ""
    self.targetWindow = 0
    self.topWinRows = 0
    self.topWinCursor = (0,0)
    self.bottomWinCursor = (0,0)
    self.z_memory_buffer = ""
    self.z_memory_address = 0x00
    self.active_input_stream = 0
    self.input_current_line = 0
    self.input_lines = []
    self.text_reverse_video = False
    self.text_bold = False
    self.text_italic = False
    self.text_fixed_pitch = False
    self.restoring = False
    self.readRanOnce = False # Necessary to avoid z3 status bar print before 'read'
    self.currentFont = 1 # 1: Normal, 2: Picture, 3: CharGraphics, 4: Fixed-width Courier-style
    self.currentForeground = 9 # White
    self.currentBackground = 2 # Black
    self.undo_buffer = []
    self.callbackCurrentString = ""
    self.callbackCurrentXPos = 0
    self.callbackReturnValue = 0
    self.callbackRoutine = 0
    self.callbackTriggered = False
    self.opcodeMap = {}
    self.populateOpcodeMap()
    printLog(self.version)
    printLog(self.static)
    printLog(self.high)

  def setWidthHeight(self, width, height):
    self.mem[0x20] = height
    self.mem[0x21] = width

  def setInterpreterNumberVersion(self, number, version):
    self.mem[0x1e] = number
    self.mem[0x1f] = version

  def setFlags(self):
    # Set interpreter capabilities in flags 1/2
    # Flags 1 - general availability + score/time game flag
    flags = self.mem[0x01]
    printLog("starting flags: " + bin(flags))
    if self.version < 4:
      # Bit 1: Score/Time Game
      # Bit 2: Story file split across discs (don't care)
      # Bit 4: Status line not available? (0 = Available, 1 = Not Available)
      # Bit 5: Screen split available? (0 = Not available, 1 = Available)
      # Bit 6: Variable width is default? (0 = Not default, 1 = Default)
      self.timedGame = isNthBitSet(flags, 1)
      flags = setNthBit(flags, 4, False) # Status line available
      flags = setNthBit(flags, 5, True) # No split screen
      flags = setNthBit(flags, 6, False) # Fixed width by default
      self.mem[0x01] = flags
      printLog("flags set: " + bin(self.mem[0x01]))
    else:
      # All of these are 0 = Unavailable, 1 = Available)
      # Bit 0: Colours?
      flags = setNthBit(flags, 0, True) # Probably? TODO: Should actually use Curses to check this
      # Bit 1: Picture display?
      flags = setNthBit(flags, 1, False) # Nah. Probably never.
      # Bit 2: Boldface?
      flags = setNthBit(flags, 2, True) # Yup.
      # Bit 3: Italic?
      flags = setNthBit(flags, 3, True) # Yeah.
      # Bit 4: Fixed-pitch?
      flags = setNthBit(flags, 4, True) # Probably the only font we have!
      # Bit 5: Sound effects?
      flags = setNthBit(flags, 5, False) # Not yet.
      # Bit 7: Timed keyboard input?
      flags = setNthBit(flags, 7, True) # Kind of!
      self.mem[0x01] = flags
      printLog("flags set: " + bin(self.mem[0x01]))

    # Flags 2 - specific availability/current status
    flags = self.mem[0x10]
    # Bits 0-3 are dynamically set
    # Bit 3: Game wants to use pictures
    flags = setNthBit(flags, 3, False) # No can do, my friend.
    # Bit 4: Game wants to use UNDO opcodes
    flags = setNthBit(flags, 4, False) # Not yet..
    # Bit 5: Game wants to use a mouse
    flags = setNthBit(flags, 5, False) # Not yet..
    # Bit 6: Game wants to use colours
    flags = setNthBit(flags, 6, True) # Sure! Probably! Need to use Curses to determine terminal capability
    # Bit 7: Game wants to use sounds
    flags = setNthBit(flags, 7, False) # Not yet...
    # Bit 8: Game wants to use menus
    flags = setNthBit(flags, 8, False) # No - and we probably won't ever support v6 anyway.
    self.mem[0x10] = flags

  def setDefaultColours(self):
    self.mem[0x2c] = 2 # Default black background
    self.mem[0x2d] = 9 # Default white foreground

  def populateOpcodeMap(self):
    self.opcodeMap[Operand.TwoOP] = {}
    self.opcodeMap[Operand.TwoOP][0x1] = ("je", self.je)
    self.opcodeMap[Operand.TwoOP][0x2] = ("jl", self.jl)
    self.opcodeMap[Operand.TwoOP][0x3] = ("jg", self.jg)
    self.opcodeMap[Operand.TwoOP][0x4] = ("dec_chk", self.dec_chk)
    self.opcodeMap[Operand.TwoOP][0x5] = ("inc_chk", self.inc_chk)
    self.opcodeMap[Operand.TwoOP][0x6] = ("jin", self.jin)
    self.opcodeMap[Operand.TwoOP][0x7] = ("test", self.test)
    self.opcodeMap[Operand.TwoOP][0x8] = ("or", self.or_1)
    self.opcodeMap[Operand.TwoOP][0x9] = ("and", self.and_1)
    self.opcodeMap[Operand.TwoOP][0xa] = ("test_attr", self.test_attr)
    self.opcodeMap[Operand.TwoOP][0xb] = ("set_attr", self.set_attr)
    self.opcodeMap[Operand.TwoOP][0xc] = ("clear_attr", self.clear_attr)
    self.opcodeMap[Operand.TwoOP][0xd] = ("store", self.store)
    self.opcodeMap[Operand.TwoOP][0xe] = ("insert_obj", self.insert_obj)
    self.opcodeMap[Operand.TwoOP][0xf] = ("loadw", self.loadw)
    self.opcodeMap[Operand.TwoOP][0x10] = ("loadb", self.loadb)
    self.opcodeMap[Operand.TwoOP][0x11] = ("get_prop", self.get_prop)
    self.opcodeMap[Operand.TwoOP][0x12] = ("get_prop_addr", self.get_prop_addr)
    self.opcodeMap[Operand.TwoOP][0x13] = ("get_next_prop", self.get_next_prop)
    self.opcodeMap[Operand.TwoOP][0x14] = ("add", self.add)
    self.opcodeMap[Operand.TwoOP][0x15] = ("sub", self.sub)
    self.opcodeMap[Operand.TwoOP][0x16] = ("mul", self.mul)
    self.opcodeMap[Operand.TwoOP][0x17] = ("div", self.div)
    self.opcodeMap[Operand.TwoOP][0x18] = ("mod", self.mod)
    self.opcodeMap[Operand.TwoOP][0x19] = ("call_2s", self.call)
    self.opcodeMap[Operand.TwoOP][0x1A] = ("call_2n", self.call)
    self.opcodeMap[Operand.TwoOP][0x1B] = ("set_colour", self.set_colour)
    self.opcodeMap[Operand.TwoOP][0x1C] = ("throw", self.throw)

    self.opcodeMap[Operand.OneOP] = {}
    self.opcodeMap[Operand.OneOP][0x0] = ("jz", self.jz)
    self.opcodeMap[Operand.OneOP][0x1] = ("get_sibling", self.get_sibling)
    self.opcodeMap[Operand.OneOP][0x2] = ("get_child", self.get_child)
    self.opcodeMap[Operand.OneOP][0x3] = ("get_parent", self.get_parent)
    self.opcodeMap[Operand.OneOP][0x4] = ("get_prop_len", self.get_prop_len)
    self.opcodeMap[Operand.OneOP][0x5] = ("inc", self.inc)
    self.opcodeMap[Operand.OneOP][0x6] = ("dec", self.dec)
    self.opcodeMap[Operand.OneOP][0x7] = ("print_addr", self.print_addr)
    self.opcodeMap[Operand.OneOP][0x8] = ("call_1s", self.call)
    self.opcodeMap[Operand.OneOP][0x9] = ("remove_obj", self.remove_obj)
    self.opcodeMap[Operand.OneOP][0xa] = ("print_obj", self.print_obj)
    self.opcodeMap[Operand.OneOP][0xb] = ("ret", self.ret)
    self.opcodeMap[Operand.OneOP][0xc] = ("jump", self.jump)
    self.opcodeMap[Operand.OneOP][0xd] = ("print_paddr", self.print_paddr)
    self.opcodeMap[Operand.OneOP][0xe] = ("load", self.load)
    if self.version < 5:
      self.opcodeMap[Operand.OneOP][0xf] = ("not", self.not_1)
    else:
      self.opcodeMap[Operand.OneOP][0xf] = ("call_1n", self.call)

    self.opcodeMap[Operand.ZeroOP] = {}
    self.opcodeMap[Operand.ZeroOP][0x0] = ("rtrue", self.rtrue)
    self.opcodeMap[Operand.ZeroOP][0x1] = ("rfalse", self.rfalse)
    self.opcodeMap[Operand.ZeroOP][0x2] = ("print", self.print_1)
    self.opcodeMap[Operand.ZeroOP][0x3] = ("print_ret", self.print_ret)
    self.opcodeMap[Operand.ZeroOP][0x4] = ("nop", self.nop)
    if self.version < 4:
      self.opcodeMap[Operand.ZeroOP][0x5] = ("save1", self.save)
    else:
      self.opcodeMap[Operand.ZeroOP][0x5] = ("save4", self.save)
    if self.version < 4:
      self.opcodeMap[Operand.ZeroOP][0x6] = ("restore1", self.restore)
    else:
      self.opcodeMap[Operand.ZeroOP][0x6] = ("restore4", self.restore)
    self.opcodeMap[Operand.ZeroOP][0x7] = ("restart", self.restart)
    self.opcodeMap[Operand.ZeroOP][0x8] = ("ret_popped", self.ret_popped)
    if self.version < 5:
      self.opcodeMap[Operand.ZeroOP][0x9] = ("pop", self.pop)
    else:
      self.opcodeMap[Operand.ZeroOP][0x9] = ("catch", self.catch)
    self.opcodeMap[Operand.ZeroOP][0xa] = ("quit", self.quit)
    self.opcodeMap[Operand.ZeroOP][0xb] = ("new_line", self.new_line)
    self.opcodeMap[Operand.ZeroOP][0xc] = ("show_status", self.show_status)
    self.opcodeMap[Operand.ZeroOP][0xd] = ("verify", self.verify)
    self.opcodeMap[Operand.ZeroOP][0xf] = ("piracy", self.piracy)

    self.opcodeMap[Operand.VAR] = {}
    self.opcodeMap[Operand.VAR][224] = ("call", self.call)
    self.opcodeMap[Operand.VAR][225] = ("storew", self.storew)
    self.opcodeMap[Operand.VAR][226] = ("storeb", self.storeb)
    self.opcodeMap[Operand.VAR][227] = ("put_prop", self.put_prop)
    if self.version < 5:
      self.opcodeMap[Operand.VAR][228] = ("read", self.read)
    else:
      self.opcodeMap[Operand.VAR][228] = ("read5", self.read)
    self.opcodeMap[Operand.VAR][229] = ("print_char", self.print_char)
    self.opcodeMap[Operand.VAR][230] = ("print_num", self.print_num)
    self.opcodeMap[Operand.VAR][231] = ("random", self.random)
    self.opcodeMap[Operand.VAR][232] = ("push", self.push)
    self.opcodeMap[Operand.VAR][233] = ("pull", self.pull)
    self.opcodeMap[Operand.VAR][234] = ("split_window", self.split_window)
    self.opcodeMap[Operand.VAR][235] = ("set_window", self.set_window)
    self.opcodeMap[Operand.VAR][236] = ("call_vs2", self.call)
    self.opcodeMap[Operand.VAR][237] = ("erase_window", self.erase_window)
    self.opcodeMap[Operand.VAR][238] = ("erase_line", self.erase_line)
    self.opcodeMap[Operand.VAR][239] = ("set_cursor", self.set_cursor)
    self.opcodeMap[Operand.VAR][240] = ("get_cursor", self.get_cursor)
    self.opcodeMap[Operand.VAR][241] = ("set_text_style", self.set_text_style)
    self.opcodeMap[Operand.VAR][242] = ("buffer_mode", self.buffer_mode)
    self.opcodeMap[Operand.VAR][243] = ("output_stream", self.output_stream)
    self.opcodeMap[Operand.VAR][244] = ("input_stream", self.input_stream)
    self.opcodeMap[Operand.VAR][245] = ("sound_effect", self.sound_effect)
    self.opcodeMap[Operand.VAR][246] = ("read_char", self.read_char)
    self.opcodeMap[Operand.VAR][247] = ("scan_table", self.scan_table)
    self.opcodeMap[Operand.VAR][248] = ("not", self.not_1)
    self.opcodeMap[Operand.VAR][249] = ("call_vn", self.call)
    self.opcodeMap[Operand.VAR][250] = ("call_vn2", self.call)
    self.opcodeMap[Operand.VAR][251] = ("tokenise", self.tokenise)
    self.opcodeMap[Operand.VAR][252] = ("encode_text", self.encode_text)
    self.opcodeMap[Operand.VAR][253] = ("copy_table", self.copy_table)
    self.opcodeMap[Operand.VAR][254] = ("print_table", self.print_table)
    self.opcodeMap[Operand.VAR][255] = ("check_arg_count", self.check_arg_count)

    self.opcodeMap["EXT"] = {}
    self.opcodeMap["EXT"][0x0] = ("save4", self.save)
    self.opcodeMap["EXT"][0x1] = ("restore4", self.restore)
    self.opcodeMap["EXT"][0x2] = ("log_shift", self.log_shift)
    self.opcodeMap["EXT"][0x3] = ("art_shift", self.art_shift)
    self.opcodeMap["EXT"][0x4] = ("set_font", self.set_font)
    self.opcodeMap["EXT"][0x9] = ("save_undo", self.save_undo)
    self.opcodeMap["EXT"][0xA] = ("restore_undo", self.restore_undo)

  # read dictionary
  def readStandardDictionary(self):
    dict_addr = self.dictionary_table_start
    self.dictionary_mapping, self.word_separators = self.readDictionaryAtAddress(dict_addr)

  def readDictionaryAtAddress(self, dict_addr):
    word_dict = dict()
    separators = []
    byte = 0
    # How many separators?
    num_separators = self.getByte(dict_addr + byte)
    byte += 1
    for i in range(num_separators):
      separators.append(self.getByte(dict_addr + byte))
      byte += 1

    # How big is a dictionary entry?
    entry_size = self.getByte(dict_addr + byte)
    byte += 1

    # How many entries?
    num_entries = getSignedEquivalent(self.getWord(dict_addr + byte))
    # Sorted-ness doesn't really matter to us... (-n means unsorted)
    num_entries = abs(num_entries)
    byte += 2

    # Load 'em up!
    for i in range(num_entries):
      if self.version < 4:
        word_1, word_2 = self.getWord(dict_addr + byte), self.getWord(dict_addr + byte + 2)
        word_dict[(word_1 << 16) + word_2] = dict_addr + byte
      else:
        word_1, word_2, word_3 = self.getWord(dict_addr + byte), self.getWord(dict_addr + byte + 2), self.getWord(dict_addr + byte + 4)
        word_dict[(word_1 << 32) + (word_2 << 16) + word_3] = dict_addr + byte
      byte += entry_size

    return word_dict, separators

  # Input shenaningans
  def getTextBufferLength(self, address):
    return self.mem[address] + 1

  def writeToTextBuffer(self, string, address):
    string = string.lower()
    string = string.strip()
    printLog("Text Buffer:", string)
    num_bytes = len(string)
    text_offset = 1

    # Version 5: write the number of characters in the first
    # not-max-length byte of the buffer.
    if (self.version > 4):
      self.mem[address+1] = num_bytes
      text_offset = 2

    # Write the text to the buffer
    for i in range(num_bytes):
      self.mem[address+text_offset+i] = ord(string[i])

    # If version < 5, add a zero terminator
    if (self.version < 5):
      self.mem[address+text_offset+num_bytes] = 0

  def readFromTextBuffer(self, address):
    string = ""
    # Only used in V5, so make assumptions...
    str_len = self.mem[address+1]
    for i in range(str_len):
      string += chr(self.mem[address+2+i])
    return string

  def readFromZsciiBuffer(self, address, length):
    # Used for encode_text, which doesn't use text buffers like read/tokenise...
    string = ""
    for i in range(length):
      string += chr(self.mem[address+i])
    return string

  def tokeniseString(self, string, separators):
    strip = string.lower()
    string = string.strip()
    for idx in separators:
      sep = self.getZsciiCharacter(idx)
      string = string.replace(sep, ' ' + sep + ' ') # Force separators to be separate tokens
    tokens = list(filter(None, string.split(' '))) # Split on space, remove empties
    printLog("Tokens: ", tokens)
    return tokens

  def parseString(self, string, address, text_buffer_address, dictionary=None, separators=None, write_unrecognised_words=True):
    if dictionary is None:
      dictionary = self.dictionary_mapping
    if separators is None:
      separators = self.word_separators
    # Lexical parsing! Oh my
    tokens = self.tokeniseString(string, separators)
    # Second byte of addr should store total number of tokens parsed
    self.mem[address+1] = len(tokens)
    # Look up each token in the dictionary
    for idx, token in enumerate(tokens):
      eff_idx = idx*4
      byte_encoding = self.tokenToDictionaryLookup(token)
      if self.version < 4:
        key = ((byte_encoding[0] << 24) + (byte_encoding[1] << 16) + (byte_encoding[2] << 8) + (byte_encoding[3]))
      else:
        key = ((byte_encoding[0] << 40) + (byte_encoding[1] << 32) + (byte_encoding[2] << 24) + (byte_encoding[3] << 16) + (byte_encoding[4] << 8) + (byte_encoding[5]))
      # Give addr of word in dict or 0 if not found (2 bytes)
      if key in dictionary:
        byte_1, byte_2 = self.breakWord(dictionary[key])
        printLog("Found word", key, "at", byte_1, byte_2)
        self.mem[address+2+eff_idx] = byte_1
        self.mem[address+2+eff_idx+1] = byte_2
      elif write_unrecognised_words:
        printLog("Did not find word", key)
        self.mem[address+2+eff_idx] = 0
        self.mem[address+2+eff_idx+1] = 0
      # Give length of word in third byte
      self.mem[address+2+eff_idx+2] = len(token)
      # Give position of word in fourth byte
      string_idx = string.find(token)+1
      if self.version > 4:
        string_idx += 1 # Because of the size byte in the text buffer
      self.mem[address+2+eff_idx+3] = string_idx

  def tokenToDictionaryLookup(self, string):
    # Truncate to 6 (v3) or 9 (v4+) characters
    trunc_length = 6
    if (self.version > 3):
      trunc_length = 9
    string = string[0:trunc_length]
    # Encode it
    return self.stringToEncodedBytes(string)

  def stringToEncodedBytes(self, string):
    min_length = 4 if self.version < 4 else 9
    zbytes = []
    cur_zbyte = 0
    characters_left = 3
    # Sanitise...
    string = string.lower()
    printLog("String to tokenise:", string)

    # Add `a before the non-alpha characters
    for key in a2:
      string = string.replace(a2[key], '`' + a2[key])
    # For 10-bit ascii, you have to do A2 switch + `
    # else commands like $ve won't work
    for key in input_map:
      if key in a0.values() or key in a1.values() or key in a2.values():
        continue
      string = string.replace(key, '`a' + key)

    printLog("String post-replacements:", string)

    bit_string = ''
    for character in string:
      if character in input_map:
        bit_string += format(self.getFiveBitEncoding(character), '05b')
      else:
        bit_string += format(ord(character), '010b')
    byte_list = [bit_string[i:i+5] for i in range(0, len(bit_string), 5)]

    # Ensure we generate two words by padding if necessary...
    # But not too much padding!
    while len(byte_list) < min_length or (len(byte_list) % 3 != 0):
      byte_list.append('00101') # 5

    printLog("stringToEncode, string, bytes", string, byte_list)

    for character in byte_list:
      characters_left -= 1
      encoding = int(character, 2)
      cur_zbyte += (encoding << (5 * characters_left))
      if (characters_left == 0):
        zbyte_1 = (cur_zbyte & 0xff00) >> 8
        zbyte_2 = (cur_zbyte & 0x00ff)
        zbytes.append(zbyte_1)
        zbytes.append(zbyte_2)
        cur_zbyte = 0
        characters_left = 3

    # Mark last byte-pair as the end
    last_byte = zbytes[-2]
    last_byte |= 0x80
    zbytes[-2] = last_byte

    return zbytes

  def getFiveBitEncoding(self, character):
    return input_map[character]

  def activatePrivateStream(self):
    self.stored_active_streams = self.active_output_streams
    self.active_output_streams = [5] # Our private output stream
    self.stream = ""

  def deactivatePrivateStream(self):
    self.active_output_streams = self.stored_active_streams
    self.stored_output_streams = None

  # print
  def getEncodedAbbreviationString(self, idx):
    abbrev_addr = self.abbreviation_table_start + (idx*2)
    abbrev_addr = self.getWord(abbrev_addr)*2
    return self.getEncodedTextLiteral(abbrev_addr)[0]

  def print_string(self, string, starting_alphabet=Alphabet.A0):
    # We gather the full string before printing for potential buffering purposes
    self.activatePrivateStream()
    self._print_string(string, starting_alphabet)
    self.deactivatePrivateStream()
    self.printToStream(self.stream, end='')

  def _print_string(self, string, starting_alphabet=Alphabet.A0):
    # Nested strings use fresh locked alphabets for version 1/2
    self.lock_alphabets.append(starting_alphabet)
    current_alphabet = self.lock_alphabets[-1]
    for characters in string:
      first_char  = (characters & 0b0111110000000000) >> 10
      second_char = (characters & 0b0000001111100000) >> 5
      third_char  = (characters & 0b0000000000011111)
      if (self.version < 3):
        current_alphabet = self.printZCharacterV1(first_char, current_alphabet)
        current_alphabet = self.printZCharacterV1(second_char, current_alphabet)
        current_alphabet = self.printZCharacterV1(third_char, current_alphabet)
      else:
        current_alphabet = self.printZCharacterV3(first_char, current_alphabet)
        current_alphabet = self.printZCharacterV3(second_char, current_alphabet)
        current_alphabet = self.printZCharacterV3(third_char, current_alphabet)

    # Nasty consequence of how we deal with ten-bit ZSCII (we only print it
    # if we're printing another character after it)... so we have to deal
    # with a special case here.
    if self.ten_bit_zscii_bytes_needed == 0:
      self.print_zscii_character(self.ten_bit_zscii_bytes)

    # If we ended up with an incomplete double-byte, throw it away (just in case)
    self.ten_bit_zscii_bytes_needed = None

    # Version 1/2: Throw away the lock alphabet we just used
    self.lock_alphabets.pop()

  def printZCharacterV1(self, key, current_alphabet):
    # Handle ten-bit ZSCII
    if (self.ten_bit_zscii_bytes_needed == 2):
      self.ten_bit_zscii_bytes += key << 5
      self.ten_bit_zscii_bytes_needed -= 1
      return current_alphabet
    elif (self.ten_bit_zscii_bytes_needed == 1):
      self.ten_bit_zscii_bytes_needed -= 1
      self.ten_bit_zscii_bytes += key
      return current_alphabet
    elif (self.ten_bit_zscii_bytes_needed == 0):
      self.print_zscii_character(self.ten_bit_zscii_bytes)
      self.ten_bit_zscii_bytes_needed = None

    # Print abbreviations - we're in V2 so we can drop the complicated maths
    if (self.current_abbrev != None):
      abbrev_idx = key
      self.current_abbrev = None
      self._print_string(self.getEncodedAbbreviationString(abbrev_idx))
      return current_alphabet
    elif key == 1 and self.version == 2:
      self.current_abbrev = key
      return current_alphabet

    # Handle shift characters
    if key == 2:
      if (current_alphabet == Alphabet.A0):
        return Alphabet.A1
      if (current_alphabet == Alphabet.A1):
        return Alphabet.A2
      if (current_alphabet == Alphabet.A2):
        return Alphabet.A0
    if key == 3:
      if (current_alphabet == Alphabet.A0):
        return Alphabet.A2
      if (current_alphabet == Alphabet.A1):
        return Alphabet.A0
      if (current_alphabet == Alphabet.A2):
        return Alphabet.A1

    if key == 4:
      if (current_alphabet == Alphabet.A0):
        self.lock_alphabets[-1] = Alphabet.A1
      if (current_alphabet == Alphabet.A1):
        self.lock_alphabets[-1] = Alphabet.A2
      if (current_alphabet == Alphabet.A2):
        self.lock_alphabets[-1] = Alphabet.A0
    if key == 5:
      if (current_alphabet == Alphabet.A0):
        self.lock_alphabets[-1] = Alphabet.A2
      if (current_alphabet == Alphabet.A1):
        self.lock_alphabets[-1] = Alphabet.A0
      if (current_alphabet == Alphabet.A2):
        self.lock_alphabets[-1] = Alphabet.A1

    # Handle printing
    if key == 0:
      self.printToStream(" ", '')

    if key == 1 and self.version == 1:
      self.printToStream("\n", '')

    alphabet = a0
    if current_alphabet == Alphabet.A1:
      alphabet = a1
    elif current_alphabet == Alphabet.A2:
      if self.version == 1:
        alphabet = a2_v1
      else:
        alphabet = a2

    if key == 6 and current_alphabet == Alphabet.A2:
      # 10-bit Z-character to process
      self.ten_bit_zscii_bytes_needed = 2
      self.ten_bit_zscii_bytes = 0
    elif key in alphabet:
      self.printToStream(alphabet[key], '')

    return self.lock_alphabets[-1]

  def printZCharacterV3(self, key, current_alphabet):
    # Handle ten-bit ZSCII
    if (self.ten_bit_zscii_bytes_needed == 2):
      self.ten_bit_zscii_bytes += key << 5
      self.ten_bit_zscii_bytes_needed -= 1
      return current_alphabet
    elif (self.ten_bit_zscii_bytes_needed == 1):
      self.ten_bit_zscii_bytes_needed -= 1
      self.ten_bit_zscii_bytes += key
      return current_alphabet
    elif (self.ten_bit_zscii_bytes_needed == 0):
      self.print_zscii_character(self.ten_bit_zscii_bytes)
      self.ten_bit_zscii_bytes_needed = None

    # Print abbreviations
    if (self.current_abbrev != None):
      abbrev_idx = ((32*(self.current_abbrev-1)) + key)
      self.current_abbrev = None
      self._print_string(self.getEncodedAbbreviationString(abbrev_idx), current_alphabet)
      return current_alphabet
    elif key in [1,2,3]:
      self.current_abbrev = key
      return current_alphabet

    # Handle shift characters
    if key == 4:
      return Alphabet.A1
    if key == 5:
      return Alphabet.A2

    # Print other characters
    if key == 0:
      self.printToStream(" ", '')
    alphabet = a0
    if current_alphabet == Alphabet.A1:
      alphabet = a1
    elif current_alphabet == Alphabet.A2:
      alphabet = a2

    if key == 6 and current_alphabet == Alphabet.A2:
      # 10-bit Z-character to process
      self.ten_bit_zscii_bytes_needed = 2
      self.ten_bit_zscii_bytes = 0
    elif key in alphabet:
      self.printToStream(alphabet[key], '')

    return Alphabet.A0

  def print_number(self, number):
    self.printToStream(str(number), '')

  def getZsciiCharacter(self, idx):
    # Returns valid output characters (TODO: missing v6 + extra chars)
    # CHECK: If we receive a character outside of the range,
    #        log something and print nothing.
    #        This is to get around the fact that some games call
    #        read_char (which takes input-only characters)
    #        and then tries to print them.

    if idx  == 13: # Newline
      return '\n'

    if idx >= 32 and idx < 127: # Regular ASCII
      target_character = chr(idx)
      return target_character

    printLog("getZsciiCharacter: Unsupported ZSCII in operand:", idx)
    return ''

  def print_zscii_character(self, character):
    target_character = self.getZsciiCharacter(character)
    self.printToStream(target_character, '')

  def handleInput(self, length, time=0, routine=0, currentString=""):
    global input_win # :(

    if input_win is not None: # Tidy up the old input window
      del input_win
      stdscr.touchwin()
      stdscr.refresh()
      input_win = None

    y, x = stdscr.getyx()
    maxy, maxx = stdscr.getmaxyx()
    length = min(length, maxx - x - 2) # Not exactly conforming to standard here...
    input_win = stdscr.subwin(1, length, y, x)
    input_win.addstr(currentString)
    input_win.move(0, self.callbackCurrentXPos)
    if time != 0 and routine != 0:
      self.callbackRoutine = routine
      input_win.timeout(time) # rate passed is time/10, timeout is in milliseconds...
    tb = curses.textpad.Textbox(input_win)
    text = tb.edit(cursesValidator)
    return text

  def copyTable(self, fromAddr, toAddr, size):
    # copyTable both copies tables and zeroes them, depending on input

    # toAddr == 0? Zero the first size bytes of fromAddr
    if toAddr == 0:
      printLog("copy_table: zero operation")
      size = abs(size)
      for i in range(size):
        self.mem[fromAddr + i] = 0
    else:
    # toAddr != 0? Copy data from one address to the other but
    # be careful not to overwrite the original data if size
    # is >0
      mustCopyForward = size < 0
      size = abs(size)
      # Will we start writing over fromAddr's own data?
      willCorruptFromAddrData = fromAddr + size > toAddr
      if not willCorruptFromAddrData or mustCopyForward:
        printLog("copy_table: forwards copy")
        for i in range(size):
          self.mem[toAddr + i] = self.mem[fromAddr + i]
      else:
        # TODO: What does 'copy backwards' mean..?
        # We'll have to do some experiments later on to
        # try and understand.
        printLog("copy_table: backwards copy")
        for i in range(size):
          index = size - i
          index -= 1
          self.mem[toAddr + index] = self.mem[fromAddr + index]

  def printTable(self, text_addr, width, height, skip):
    char_idx = 0
    if self.targetWindow == 0:
      currentCursor = self.bottomWinCursor
    elif self.targetWindow == 1:
      currentCursor = self.topWinCursor
    start_y, start_x = currentCursor
    for i in range(height):
      for j in range(width):
        self.setCursor(start_y + i, start_x + j)
        self.print_zscii_character(self.mem[text_addr + char_idx])
        char_idx += 1
      char_idx += skip

  # opcodes
  def restart(self, instruction):
    printLog("restart")
    # Wipe it all.
    self.__init__(self.raw)
    self.readStandardDictionary()
    y, x = stdscr.getmaxyx()
    self.bottomWinCursor = (y-1, 0)
    stdscr.clear()

  def read(self, instruction):
    printLog("read")
    decoded_opers  = self.decodeOperands(instruction)

    current_string = ""
    # See if we're coming back as part of the callback
    if self.callbackTriggered:
      self.callbackTriggered = False # Don't let it run again
      current_string = self.callbackCurrentString
      if self.callbackReturnValue == 1:
        # Premature quit of read
        # self.eraseInput() ???
        self.callbackCurrentXPos = 0
        self.callbackCurrentString = ""
        self.setVariable(instruction.store_variable, 0)
        self.pc += instruction.instr_length
        return

    # Terrible v3 specific code
    if self.version == 3 and not self.readRanOnce:
      self.readRanOnce = True
    # Flush the buffer
    self.drawWindows()

    text_buffer_address = decoded_opers[0]
    if len(decoded_opers) > 1: # Etude has a READ with no parse buffer...
                               # Spec implies it should be passing a zero
                               # parameter, but let's just cater for it.
      parse_buffer_address = decoded_opers[1]
    else:
      parse_buffer_address = 0

    if len(decoded_opers) > 2:
      time = decoded_opers[2]
      routine = decoded_opers[3]
    else:
      time = 0
      routine = 0

    maxLen = self.getTextBufferLength(text_buffer_address)
    iy, ix = stdscr.getyx()
    if (self.active_input_stream == 0):
      string = self.handleInput(maxLen, time, routine, current_string)
    else:
      # Get next line from file... if we run out of lines
      # or the file doesn't exist, go back to the old input method
      try:
        string = self.input_lines[self.input_current_line]
        self.input_current_line += 1
      except Exception:
        self.printToStream("End of input file.", '\n')
        self.active_input_stream = 0
        self.printToStream(">", '')
        self.refreshWindows()
        string = self.handleInput(maxLen)

    # Write what we have - seems necessary for interrupts in ver 5?
    self.writeToTextBuffer(string, text_buffer_address)

    if self.callbackTriggered:
      # Go do the routine, then come back
      callback_routine, new_pc = self.buildCallbackRoutineCall(self.callbackRoutine)
      self.callbackCurrentString = string.strip()
      self.callRoutine(new_pc)
      return
    else:
      # Input terminated normally, kill any running callbacks
      self.callbackRoutine = 0
      self.callbackReturnValue = 0
      self.callbackCurrentString = ""
      self.callbackCurrentXPos = 0

    self.printToCommandStream(string, '\n')
    self.printToStream(string, '\n')
    # Parsing is option in v5+:
    if parse_buffer_address > 0:
      self.parseString(string, parse_buffer_address, text_buffer_address)

    # TODO: Handle function keys and timeouts
    if self.version > 4:
      self.setVariable(instruction.store_variable, 13) # Hardcode newline terminator for now

    self.pc += instruction.instr_length

  def tokenise(self, instruction):
    printLog("tokenise")
    decoded_opers  = self.decodeOperands(instruction)
    text_buffer_address = decoded_opers[0]
    parse_buffer_address = decoded_opers[1]
    dictionary_addr = None
    dictionary = separators = None
    flag = True
    if len(decoded_opers) > 2 and dictionary_addr != 0:
      dictionary_addr = decoded_opers[2]
    if len(decoded_opers) > 3:
      flag = decoded_opers[3] == 0 # 1 means do not write unrecognised words

    if dictionary_addr:
      dictionary, separators = self.readDictionaryAtAddress(dictionary_addr)

    string = self.readFromTextBuffer(text_buffer_address)
    self.parseString(string, parse_buffer_address, text_buffer_address, dictionary, separators, flag)

    self.pc += instruction.instr_length

  def read_char(self, instruction):
    printLog("read_char")
    self.drawWindows()

    decoded_opers  = self.decodeOperands(instruction)
    useless_argument = decoded_opers[0]
    if len(decoded_opers) > 1:
      time = decoded_opers[1]
      routine = decoded_opers[2]
      raise Exception("read_char with callback - not implemented")

    ch_val = 0
    while ch_val == 0: # Only read valid ZSCII characters, discard all else
      string = stdscr.getkey()
      ch_val = cursesKeyToZscii(string)

    self.setVariable(instruction.store_variable, ch_val)

    self.pc += instruction.instr_length

  def encode_text(self, instruction):
    printLog("encode_text")
    decoded_opers  = self.decodeOperands(instruction)
    zscii_buffer = decoded_opers[0]
    length = decoded_opers[1]
    start = decoded_opers[2]
    coded_text_addr = decoded_opers[3]

    string = self.readFromZsciiBuffer(zscii_buffer + start, length)
    string_bytes = self.stringToEncodedBytes(string)
    for i, byte in enumerate(string_bytes):
      self.mem[coded_text_addr + i] = byte

    self.pc += instruction.instr_length

  def copy_table(self, instruction):
    printLog("copy_table")
    decoded_opers  = self.decodeOperands(instruction)
    from_addr = decoded_opers[0]
    to_addr = decoded_opers[1]
    size = getSignedEquivalent(decoded_opers[2])
    self.copyTable(from_addr, to_addr, size)
    self.pc += instruction.instr_length

  def print_table(self, instruction):
    printLog("print_table")
    decoded_opers  = self.decodeOperands(instruction)
    text_addr = decoded_opers[0]
    width = decoded_opers[1]
    if len(decoded_opers) > 2:
      height = decoded_opers[2]
    else:
      height = 1
    if len(decoded_opers) > 3:
      skip = decoded_opers[3]
    else:
      skip = 0

    self.printTable(text_addr, width, height, skip)

    self.pc += instruction.instr_length

  def check_arg_count(self, instruction):
    printLog("check_arg_count")
    decoded_opers  = self.decodeOperands(instruction)
    arg_to_check = decoded_opers[0]
    arg_passed = self.checkArgCount(arg_to_check)
    self.pc += instruction.instr_length
    self.handleJumpDestination(arg_passed, instruction)

  def set_attr(self, instruction):
    printLog("set_attr")
    decoded_opers  = self.decodeOperands(instruction)
    obj_num = decoded_opers[0]
    attrib_num = decoded_opers[1]
    self.setAttribute(obj_num, attrib_num, True)
    self.pc += instruction.instr_length

  def clear_attr(self, instruction):
    printLog("clear_attr")
    decoded_opers  = self.decodeOperands(instruction)
    obj_num = decoded_opers[0]
    attrib_num = decoded_opers[1]
    self.setAttribute(obj_num, attrib_num, False)
    self.pc += instruction.instr_length

  def push(self, instruction):
    printLog("push")
    decoded_opers  = self.decodeOperands(instruction)
    value_to_push = decoded_opers[0]
    self.setVariable(0, value_to_push)
    self.pc += instruction.instr_length

  def pull(self, instruction):
    printLog("pull")
    decoded_opers  = self.decodeOperands(instruction)
    variable_to_pull_to = decoded_opers[0]
    stack_val = self.getVariable(0)
    self.setVariableInPlace(variable_to_pull_to, stack_val)
    self.pc += instruction.instr_length

  def erase_window(self, instruction):
    printLog("erase_window")
    decoded_opers  = self.decodeOperands(instruction)
    window = getSignedEquivalent(decoded_opers[0])
    self.eraseWindow(window)
    self.pc += instruction.instr_length

  def split_window(self, instruction):
    printLog("split_window")
    decoded_opers  = self.decodeOperands(instruction)
    lines = decoded_opers[0]
    self.splitWindow(lines)
    self.pc += instruction.instr_length

  def set_window(self, instruction):
    printLog("set_window")
    decoded_opers  = self.decodeOperands(instruction)
    windowToSwitchTo = decoded_opers[0]
    self.setWindow(windowToSwitchTo)
    self.pc += instruction.instr_length

  def output_stream(self, instruction):
    printLog("output_stream")
    decoded_opers  = self.decodeOperands(instruction)
    stream = getSignedEquivalent(decoded_opers[0])
    table = None
    if stream == 3:
      table = decoded_opers[1]
    self.setOutputStream(stream, table)
    self.pc += instruction.instr_length

  def throw(self, instruction):
    # Keep throwing away routine callstacks until we
    # get to the one we want, then return.
    printLog("throw")
    decoded_opers  = self.decodeOperands(instruction)
    ret_val = decoded_opers[0]
    target_stack_frame = decoded_opers[1]
    while (self.routine_callstack[-1].frame_pointer != target_stack_frame):
      self.routine_callstack.pop()
    self.ret_helper(instruction, ret_val)

  def catch(self, instruction):
    printLog("catch")
    decoded_opers  = self.decodeOperands(instruction)
    current_frame_pointer = self.routine_callstack[-1].frame_pointer
    self.setVariable(instruction.store_variable, current_frame_pointer)
    self.pc += instruction.instr_length

  def set_text_style(self, instruction):
    printLog("set_text_style")
    decoded_opers  = self.decodeOperands(instruction)
    new_style = decoded_opers[0]
    self.setTextStyle(new_style)
    self.pc += instruction.instr_length

  def set_colour(self, instruction):
    printLog("set_colour")
    decoded_opers  = self.decodeOperands(instruction)
    foreground = decoded_opers[0]
    background = decoded_opers[1]
    if len(decoded_opers) > 2 and self.version == 6:
      window = decoded_opers[2]
      raise Exception("set_colour v6: Not implemented")
    self.setColour(foreground, background)
    self.pc += instruction.instr_length

  def set_font(self, instruction):
    printLog("set_font")
    decoded_opers  = self.decodeOperands(instruction)
    new_font = decoded_opers[0]
    if self.version == 6 and len(decoded_opers) > 1:
      window = decoded_opers[1]
      raise Exception("set_font v6: Not implemented")
    self.setFont(new_font)
    self.pc += instruction.instr_length

  def buffer_mode(self, instruction):
    printLog("buffer_mode")
    decoded_opers  = self.decodeOperands(instruction)
    self.bufferText = decoded_opers[0] == 1
    self.pc += instruction.instr_length

  def erase_line(self, instruction):
    printLog("erase_line_cursor")
    decoded_opers  = self.decodeOperands(instruction)
    pixels = decoded_opers[0]
    self.eraseLine(pixels)
    self.pc += instruction.instr_length

  def set_cursor(self, instruction):
    printLog("set_cursor")
    decoded_opers  = self.decodeOperands(instruction)
    line = decoded_opers[0]
    column = decoded_opers[1]
    # Curses starts at 0,0, Z-Machine starts at 1,1
    self.setCursor(line-1, column-1)
    self.pc += instruction.instr_length

  def get_cursor(self, instruction):
    printLog("get_cursor")
    decoded_opers  = self.decodeOperands(instruction)
    array = decoded_opers[0]
    self.getCursor(array)
    self.pc += instruction.instr_length

  def input_stream(self, instruction):
    printLog("input_stream")
    decoded_opers  = self.decodeOperands(instruction)
    input_stream = decoded_opers[0]
    self.setInputStream(input_stream)
    self.pc += instruction.instr_length

  def sound_effect(self, instruction):
    printLog("sound_effect")
    decoded_opers  = self.decodeOperands(instruction)
    # TODO - Implement
    # My favourite unimplemented opcode!
    self.pc += instruction.instr_length

  def insert_obj(self, instruction):
    printLog("insert_obj")
    decoded_opers  = self.decodeOperands(instruction)
    inserted_obj_num = decoded_opers[0]
    destination_obj = decoded_opers[1]
    printLog("insert_obj:obj to insert:", inserted_obj_num)
    printLog("insert_obj:destination obj:", destination_obj)

    self.removeObject(inserted_obj_num)

    # If existing child for destination object, make them siblings
    original_child = self.getObjectChild(destination_obj)
    if (original_child > 0):
      printLog("insert_obj:new sibling: ", original_child)
      self.setObjectSibling(inserted_obj_num, original_child)

    # Finally, establish new parent-child
    self.setObjectParent(inserted_obj_num, destination_obj)
    self.setObjectChild(destination_obj, inserted_obj_num)

    # DEBUG: Confirm new relationships
    if (self.getObjectParent(inserted_obj_num) != destination_obj):
      raise Exception("Busted")
    if (self.getObjectChild(destination_obj) != inserted_obj_num):
      raise Exception("Busted")
    if (self.getObjectSibling(inserted_obj_num) != original_child):
      raise Exception("Busted")

    self.pc += instruction.instr_length

  def removeObject(self, obj_num):
    # Remove original parentage, upgrade sibling if first child
    original_parent = self.getObjectParent(obj_num)
    original_sibling = self.getObjectSibling(obj_num)
    if (original_parent > 0 and self.getObjectChild(original_parent) == obj_num):
      printLog("remove_obj:former parent: ", original_parent)
      self.setObjectChild(original_parent, original_sibling)
    elif (original_parent > 0):
      # Child but not first child
      older_sibling = self.getObjectChild(original_parent)
      while self.getObjectSibling(older_sibling) != obj_num:
        older_sibling = self.getObjectSibling(older_sibling)
      self.setObjectSibling(older_sibling, self.getObjectSibling(obj_num))

    self.setObjectParent(obj_num, 0)
    self.setObjectSibling(obj_num, 0)

  def remove_obj(self, instruction):
    printLog("remove_obj")
    decoded_opers  = self.decodeOperands(instruction)
    obj_num = decoded_opers[0]
    printLog("remove_obj:obj to orphan: ", obj_num)

    self.removeObject(obj_num)
    self.pc += instruction.instr_length

  def inc_chk(self, instruction):
    printLog("inc_chk")
    decoded_opers  = self.decodeOperands(instruction)
    variable_num = decoded_opers[0]
    chk_value = getSignedEquivalent(decoded_opers[1])
    value = getSignedEquivalent(self.peekVariable(variable_num))
    printLog("inc_chk:value_in_var: ", hex(variable_num), value)
    # Inc...
    value += 1
    # Branch check...
    val_bigger = value > chk_value
    value = getHexValue(value)
    self.setVariableInPlace(variable_num, value)
    self.pc += instruction.instr_length
    self.handleJumpDestination(val_bigger, instruction)

  def dec_chk(self, instruction):
    printLog("dec_chk")
    decoded_opers  = self.decodeOperands(instruction)
    variable_num = decoded_opers[0]
    chk_value = getSignedEquivalent(decoded_opers[1])
    value = getSignedEquivalent(self.peekVariable(variable_num))
    printLog("dec_chk:value_in_var:", hex(variable_num), value)
    # Dec...
    value -= 1
    # Branch check...
    val_smaller = value < chk_value
    # Write adjusted value back into memory
    value = getHexValue(value)
    self.setVariableInPlace(variable_num, value)
    # Jump if necessary
    self.pc += instruction.instr_length
    self.handleJumpDestination(val_smaller, instruction)

  def inc(self, instruction):
    printLog("inc")
    decoded_opers  = self.decodeOperands(instruction)
    variable_num = decoded_opers[0]
    value = getSignedEquivalent(self.peekVariable(variable_num))
    value += 1
    value = getHexValue(value)
    self.setVariableInPlace(variable_num, value)
    self.pc += instruction.instr_length

  def dec(self, instruction):
    printLog("dec")
    decoded_opers  = self.decodeOperands(instruction)
    variable_num = decoded_opers[0]
    value = getSignedEquivalent(self.peekVariable(variable_num))
    value -= 1
    value = getHexValue(value)
    self.setVariableInPlace(variable_num, value)
    self.pc += instruction.instr_length

  def new_line(self, instruction):
    printLog("newline")
    #print('')
    self.printToStream('\n', '')
    self.pc += instruction.instr_length

  def print_1(self, instruction):
    printLog("run print")
    self.print_string(instruction.encoded_string_literal)
    self.pc += instruction.instr_length

  def print_ret(self, instruction):
    printLog("print_ret")
    self.print_string(instruction.encoded_string_literal)
    self.printToStream('\n', '') # Weirdly specific to print_ret
    self.rtrue(None)

  def print_addr(self, instruction):
    printLog("print_addr")
    decoded_opers  = self.decodeOperands(instruction)
    string_byte_addr = decoded_opers[0]
    encoded_string_literal = self.getEncodedTextLiteral(string_byte_addr)[0]
    self.print_string(encoded_string_literal)
    self.pc += instruction.instr_length

  def print_paddr(self, instruction):
    printLog("print_paddr")
    decoded_opers  = self.decodeOperands(instruction)
    string_packed_addr = decoded_opers[0]
    string_addr = self.unpackAddress(string_packed_addr, False)
    encoded_string_literal = self.getEncodedTextLiteral(string_addr)[0]
    self.print_string(encoded_string_literal)
    self.pc += instruction.instr_length

  def print_num(self, instruction):
    printLog("print_num")
    decoded_opers  = self.decodeOperands(instruction)
    self.print_number(getSignedEquivalent(decoded_opers[0]))
    self.pc += instruction.instr_length

  def print_char(self, instruction):
    printLog("print_char")
    decoded_opers  = self.decodeOperands(instruction)
    self.print_zscii_character(decoded_opers[0])
    self.pc += instruction.instr_length

  def print_obj(self, instruction):
    printLog("print_obj")
    decoded_opers  = self.decodeOperands(instruction)
    obj_num = decoded_opers[0]
    self.print_string(self.getEncodedObjectShortName(obj_num))
    self.pc += instruction.instr_length

  def show_status(self, instruction):
    printLog("show_status")
    self.drawStatusLine()

    self.pc += instruction.instr_length # Move past the instr regardless

  def verify(self, instruction):
    printLog("verify")
    # Do the checksum: sum all bytes from 0x40 onwards and compare to header value
    file_length = self.getWord(0x1a)
    if self.version < 4:
      file_length *= 2
    elif self.version < 6:
      file_length *= 4
    else:
      file_length *= 8
    # Use the original file...
    sumMem = bytearray(self.raw)
    sumMem = sumMem[0x40:file_length]
    totalSum = sum(sumMem) % 0x10000
    checkSum = self.getWord(0x1c)

    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(totalSum == checkSum, instruction)

  def ret(self, instruction):
    # Return value in parameter
    printLog("ret")
    decoded_opers  = self.decodeOperands(instruction)
    self.ret_helper(instruction, decoded_opers[0])

  def nop(self, instruction):
    # No operation - do nothing
    printLog("nop")

  def ret_popped(self, instruction):
    # Return bottom of stack
    printLog("ret_popped")
    self.ret_helper(instruction, self.getVariable(0))

  def save(self, instruction):
    printLog("save")
    # Another instruction that gets moved around...
    decoded_opers  = self.decodeOperands(instruction)
    if (self.version > 4):
      if len(decoded_opers) > 0:
        table = decoded_opers[0]
        byte_count = decoded_opers[1]
        suggested_name = decoded_opers[2]
        raise Exception("save: Additional parameters unimplemented")
      if len(decoded_opers) > 3:
        should_prompt = decoded_opers[3]
        raise Exception("save: Additional parameters unimplemented")

    if self.restoring:
      save_successful = 2
      self.restoring = False
    else:
      save_successful = self.saveGame()

    # Save should use the PC for the address of the save
    # as this is what is responsible for passing the
    # 'just loaded flag' to the game.
    self.pc += instruction.instr_length
    # Version 1-3: Jump
    if (self.version < 4):
      self.handleJumpDestination(save_successful, instruction)
    # Version 4+: Store result
    else:
      self.setVariable(instruction.store_variable, save_successful)

  def save_undo(self, instruction):
    printLog("save_undo")
    if self.restoring:
      save_successful = 2
      self.restoring = False
    else:
      save_successful = getHexValue(-1)
      # save_successful = self.saveGameForUndo()
      # This is murdering games like I-0... needs to be faster
    self.pc += instruction.instr_length
    self.setVariable(instruction.store_variable, save_successful)

  def restore_undo(self, instruction):
    printLog("save_undo")
    self.pc += instruction.instr_length
    self.restoreFromUndo() # Assume this always works?
    self.setVariable(instruction.store_variable, 0)

  def restore(self, instruction):
    printLog("restore")
    # Another instruction that gets moved around...
    if (self.version > 4):
      decoded_opers  = self.decodeOperands(instruction)
      if len(decoded_opers) > 0:
        table = decoded_opers[0]
        byte_count = decoded_opers[1]
        suggested_name = decoded_opers[2]
        raise Exception("restore: Additional parameters unimplemented")
      if len(decoded_opers) > 3:
        should_prompt = decoded_opers[3]
        raise Exception("restore: Additional parameters unimplemented")


    self.pc += instruction.instr_length
    restore_successful = self.restoreFromFile()
    # Version 1-3: Jump
    if (self.version < 4):
      self.handleJumpDestination(restore_successful, instruction)
    # Version 4+: Store result
    else:
      self.setVariable(instruction.store_variable, restore_successful)

  def pop(self, instruction):
    # Pop stack!
    printLog("pop")
    # Another instruction that gets moved around...
    if (self.version > 4):
      raise Exception("catch: Not implemeneted")
    self.popStack()
    self.pc += instruction.instr_length

  def rtrue(self, instruction):
    # Return true
    printLog("rtrue")
    self.ret_helper(instruction, 1)

  def rfalse(self, instruction):
    # Return false
    printLog("rfalse")
    self.ret_helper(instruction, 0)

  def ret_helper(self, instruction, ret_val):
    # Pop the current routine so setVariable is targeting the right set of locals
    current_routine = self.routine_callstack.pop()
    # Return ret_val into store variable and...
    printLog("Returning", ret_val, "into", current_routine.store_variable)
    # Cater for throwaway calls
    if current_routine.store_variable is not None:
      self.setVariable(current_routine.store_variable, ret_val)
    # kick execution home - stack is scope limited to the routine so no need to
    # do anything with it.
    self.pc = current_routine.return_address
    if current_routine.is_callback:
      self.callbackReturnValue = ret_val
      printLog("Callback return:", ret_val)

  def piracy(self, instruction):
    printLog("piracy")
    decoded_opers  = self.decodeOperands(instruction)
    # By the power of Truth, I, while living, have discerned this
    # software to be genuine!
    arcane_truth = True
    self.pc += instruction.instr_length
    self.handleJumpDestination(arcane_truth, instruction)

  def jin(self, instruction):
    printLog("jin")
    decoded_opers  = self.decodeOperands(instruction)
    child = decoded_opers[0]
    parent = decoded_opers[1]
    actual_parent = self.getObjectParent(child)
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(parent == actual_parent, instruction)

  def handleJumpDestination(self, condition_met, instruction):
    printLog("jump offset: " + hex(instruction.branch_offset))
    printLog("jump on true: " + str(instruction.branch_on_true))
    if condition_met and instruction.branch_on_true:
      if (instruction.branch_offset == 0):
        self.rfalse(None)
        printLog("jump op:branch_on_true:ret false " + hex(self.pc))
      elif (instruction.branch_offset == 1):
        self.rtrue(None)
        printLog("jump op:branch_on_true:ret true " + hex(self.pc))
      else:
        self.pc += instruction.branch_offset - 2
        printLog("jump op:branch_on_true:jumped to " + hex(self.pc))
    elif not condition_met and not instruction.branch_on_true:
      if (instruction.branch_offset == 0):
        self.rfalse(None)
        printLog("jump op:branch_on_false:ret false " + hex(self.pc))
      elif (instruction.branch_offset == 1):
        self.rtrue(None)
        printLog("jump op:branch_on_false:ret true " + hex(self.pc))
      else:
        self.pc += instruction.branch_offset - 2
        printLog("jump op:branch_on_false:jumped to " + hex(self.pc))

  def je(self, instruction):
    printLog("je")
    decoded_opers  = self.decodeOperands(instruction)
    test_val = decoded_opers[0]
    match = False
    for compare_val in decoded_opers[1:]:
      match |= test_val == compare_val
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(match, instruction)

  def jg(self, instruction):
    printLog("jg")
    decoded_opers  = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(decoded_opers[0] > decoded_opers[1], instruction)

  def jl(self, instruction):
    printLog("jl")
    decoded_opers  = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(decoded_opers[0] < decoded_opers[1], instruction)

  def jz(self, instruction):
    printLog("jz")
    decoded_opers  = self.decodeOperands(instruction)
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(decoded_opers[0] == 0, instruction)

  def test_attr(self, instruction):
    printLog("test_attr")
    decoded_opers  = self.decodeOperands(instruction)
    obj_number = decoded_opers[0]
    attrib_number = decoded_opers[1]
    printLog("obj_number: " + str(obj_number))
    printLog("attrib_number: " + str(attrib_number))
    attrib_set = self.isAttributeSet(obj_number, attrib_number)
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(attrib_set, instruction)

  def test(self, instruction):
    printLog("testbitmap")
    decoded_opers  = self.decodeOperands(instruction)
    bitmap = decoded_opers[0]
    flags = decoded_opers[1]
    printLog("bitmap: " + bin(bitmap))
    printLog("flags: " + bin(flags))
    printLog("jump offset: " + hex(instruction.branch_offset))
    printLog("jump on true: " + str(instruction.branch_on_true))
    flags_match = (bitmap & flags) == flags
    self.pc += instruction.instr_length # Move past the instr regardless
    self.handleJumpDestination(flags_match, instruction)

  def jump(self, instruction):
    printLog("jump")
    decoded_opers  = self.decodeOperands(instruction)
    jump_offset = getSignedEquivalent(decoded_opers[0])
    self.pc += instruction.instr_length + jump_offset - 2

  def get_prop_addr(self, instruction):
    printLog("get_prop_addr")
    decoded_opers  = self.decodeOperands(instruction)
    obj_number = decoded_opers[0]
    prop_number = decoded_opers[1]
    printLog("Obj number: " + str(obj_number))
    printLog("Prop number: " + str(prop_number))
    # Prop address without size byte
    prop_addr = self.getPropertyAddress(obj_number, prop_number)
    if (prop_addr != 0):  # We found one
      prop_bytes, skip_bytes = self.getPropertySize(prop_addr)
      prop_addr = prop_addr + skip_bytes # Offset for size byte
    self.setVariable(instruction.store_variable, prop_addr)
    self.pc += instruction.instr_length # Move past the instr

  def get_next_prop(self, instruction):
    printLog("get_next_prop")
    decoded_opers  = self.decodeOperands(instruction)
    obj_number = decoded_opers[0]
    prop_number = decoded_opers[1]
    printLog("Obj number: " + str(obj_number))
    printLog("Prop number: " + str(prop_number))

    next_prop_num = self.getNextProperty(obj_number, prop_number)
    self.setVariable(instruction.store_variable, next_prop_num)
    self.pc += instruction.instr_length # Move past the instr

  def get_prop_len(self, instruction):
    printLog("get_prop_len")
    decoded_opers  = self.decodeOperands(instruction)
    # This is the address immediately after the size byte, so minus one
    # or two depending on the property.
    # Luckily, those clever designers made it possible to determine
    # the size of the property from the immdiately preceeding byte
    # in both v3 and v4+
    prop_bytes = 0
    if decoded_opers[0] != 0: # get_prop_len 0 must return zero...
      prop_addr = decoded_opers[0] - 1
      printLog("Prop addr: " + hex(prop_addr))
      prop_bytes = self.getPropertySizeFromOneByte(prop_addr)
    self.setVariable(instruction.store_variable, prop_bytes)
    self.pc += instruction.instr_length # Move past the instr

  def put_prop(self, instruction):
    printLog("put_prop")
    decoded_opers  = self.decodeOperands(instruction)
    printLog(decoded_opers)
    obj_number = decoded_opers[0]
    prop_number = decoded_opers[1]
    value = decoded_opers[2]
    printLog("Obj number: " + str(obj_number))
    printLog("Prop number: " + str(prop_number))
    printLog("Value: " + hex(value))
    self.setProperty(obj_number, prop_number, value)

    # DEBUG: Validate
    if (self.getProperty(obj_number, prop_number) != value):
        raise Exception("Error setting property")

    self.pc += instruction.instr_length # Move past the instr

  def get_parent(self, instruction):
    printLog("get_parent")
    decoded_opers  = self.decodeOperands(instruction)
    obj = decoded_opers[0]
    parent = self.getObjectParent(obj)
    printLog("get_parent: obj:", obj)
    printLog("get_parent: parent:", parent)
    self.setVariable(instruction.store_variable, parent)
    self.pc += instruction.instr_length # Move past the instr

  def get_child(self, instruction):
    printLog("get_child")
    decoded_opers  = self.decodeOperands(instruction)
    obj = decoded_opers[0]
    child = self.getObjectChild(obj)
    printLog("get_child: Child got:", child)
    child_exists = child != 0
    self.setVariable(instruction.store_variable, child)
    self.pc += instruction.instr_length # Move past the instr
    self.handleJumpDestination(child_exists, instruction)

  def get_sibling(self, instruction):
    printLog("get_sibling")
    decoded_opers  = self.decodeOperands(instruction)
    obj = decoded_opers[0]
    sibling = self.getObjectSibling(obj)
    printLog("get_sibling: Sibling got:", sibling)
    sibling_exists = sibling != 0
    self.setVariable(instruction.store_variable, sibling)
    self.pc += instruction.instr_length # Move past the instr
    self.handleJumpDestination(sibling_exists, instruction)

  def get_prop(self, instruction):
    printLog("get_prop")
    decoded_opers  = self.decodeOperands(instruction)
    obj = decoded_opers[0]
    property_num = decoded_opers[1]
    self.setVariable(instruction.store_variable, self.getProperty(obj, property_num))
    self.pc += instruction.instr_length # Move past the instr

  def store(self, instruction):
    printLog("store")
    decoded_opers  = self.decodeOperands(instruction)
    target_var = decoded_opers[0]
    value = decoded_opers[1]
    printLog("target_var: " + hex(target_var))
    printLog("value: " + str(value))
    self.setVariableInPlace(target_var, value)

    # DEBUG: Validate
    if (self.peekVariable(target_var) != value):
      raise Exception("Error storing value")

    self.pc += instruction.instr_length # Move past the instr

  def load(self, instruction):
    printLog("load")
    decoded_opers  = self.decodeOperands(instruction)
    loading_var = decoded_opers[0]
    # Don't pop stack if 0x00!
    value_to_load = self.peekVariable(loading_var)

    printLog("loading_var: " + hex(loading_var))
    self.setVariable(instruction.store_variable, value_to_load)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != value_to_load):
      raise Exception("Error storing value")

    self.pc += instruction.instr_length # Move past the instr

  def loadw(self, instruction):
    printLog("loadw")
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    printLog("Base addr: " + hex(base_addr))
    printLog("Idx: " + hex(idx))
    printLog("Target addr: ", hex(base_addr + (2*idx)))
    printLog("Store target: " + hex(instruction.store_variable))
    word = self.getWord(base_addr + (2*idx))
    self.setVariable(instruction.store_variable, word)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != word):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length # Move past the instr

  def loadb(self, instruction):
    printLog("loadb")
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    printLog("Base addr: " + hex(base_addr))
    printLog("Idx: " + hex(idx))
    printLog("Store target: " + hex(instruction.store_variable))
    byte = self.mem[base_addr + (idx)]
    self.setVariable(instruction.store_variable, byte)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != byte):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length # Move past the instr

  def storew(self, instruction):
    printLog("storew")
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    value = decoded_opers[2]
    printLog("Base addr: " + hex(base_addr))
    printLog("Idx: " + hex(idx))
    printLog("Value to store: " + hex(value))
    # Split value into bytes
    top_byte, bottom_byte = self.breakWord(value)
    self.mem[base_addr + (2*idx)] = top_byte
    self.mem[base_addr + (2*idx) + 1] = bottom_byte

    # DEBUG: Validate
    if (self.getWord(base_addr + (2*idx)) != value):
      raise Exception("Error storing word")

    self.pc += instruction.instr_length # Move past the instr

  def storeb(self, instruction):
    printLog("storeb")
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    value = decoded_opers[2]
    printLog("Base addr: " + hex(base_addr))
    printLog("Idx: " + hex(idx))
    printLog("Value to store: " + hex(value))
    self.mem[base_addr + (idx)] = value

    # DEBUG
    if (self.getByte(base_addr + (idx)) != value):
      raise Exception("Error storing word")

    self.pc += instruction.instr_length # Move past the instr

  def not_1(self, instruction):
    printLog("not")
    decoded_opers  = self.decodeOperands(instruction)
    value = decoded_opers[0]
    value = ~value & 0xffff

    self.setVariable(instruction.store_variable, value)
    self.pc += instruction.instr_length # Move past the instr regardless

  def log_shift(self, instruction):
    printLog("log_shift")
    # Python's default shift is arithmetic, so life's difficult here

    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0]
    shift = decoded_opers[1]

    if shift > 0:
      val = (val << shift) & 0xffff
    elif val >= 0:
      val = (val >> -shift) & 0xffff
    else:
      val = ((val+0x10000) >> -shift) & 0xffff


    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def art_shift(self, instruction):
    printLog("art_shift")
    # Python's default shift is arithmetic, so life's easy here.

    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0]
    shift = decoded_opers[1]

    if shift > 0:
      val = (val << shift) & 0xffff
    else:
      val = (val >> -shift) & 0xffff

    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def add(self, instruction):
    printLog("add")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0] + decoded_opers[1]
    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def mul(self, instruction):
    printLog("mul")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0] * decoded_opers[1]
    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error MULing values")

    self.pc += instruction.instr_length

  def and_1(self, instruction):
    printLog("and_1")
    decoded_opers = self.decodeOperands(instruction)
    printLog(decoded_opers)
    anded = decoded_opers[0] & decoded_opers[1]
    printLog("And'd value:", anded)
    self.setVariable(instruction.store_variable, anded)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != decoded_opers[0] & decoded_opers[1]):
      raise Exception("Error ANDing values")

    self.pc += instruction.instr_length

  def or_1(self, instruction):
    printLog("or_1")
    decoded_opers = self.decodeOperands(instruction)
    printLog(decoded_opers)
    ored = decoded_opers[0] | decoded_opers[1]
    printLog("Or'd value:", ored)
    self.setVariable(instruction.store_variable, ored)

    # DEBUG: Validate
    if (self.peekVariable(instruction.store_variable) != decoded_opers[0] | decoded_opers[1]):
      raise Exception("Error ORing values")

    self.pc += instruction.instr_length

  def sub(self, instruction):
    printLog("sub")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    printLog(decoded_opers)
    val = decoded_opers[0] - decoded_opers[1]
    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def div(self, instruction):
    printLog("div")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = (decoded_opers[0] / decoded_opers[1])

    # CZECH: Work towards zero - floor if above 0, ceil if below
    if val > 0:
      val = math.floor(val)
    else:
      val = math.ceil(val)
    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def mod(self, instruction):
    printLog("mod")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]

    # CZECH: mod in Python doesn't work the way the Z-Machine thinks
    #        it should. Do it manually by doing a Z-Machine divide
    #        as described in 'div' and then multiply by divisor
    #        and subtract the result from the dividend.
    val = decoded_opers[0] / decoded_opers[1]
    if val > 0:
      val = math.floor(val)
    else:
      val = math.ceil(val)

    val = val * decoded_opers[1]
    val = decoded_opers[0] - val

    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def random(self, instruction):
    printLog("random")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0]
    if val > 0:
      random_val = random.randint(1, val)
      self.setVariable(instruction.store_variable, random_val)
    else:
      if val == 0:
        # Do the standard seeding...
        random.seed(time.time())
      else:
        random.seed(val)
      self.setVariable(instruction.store_variable, 0)
    self.pc += instruction.instr_length

  def scan_table(self, instruction):
    printLog("scan_table")
    decoded_opers = self.decodeOperands(instruction)
    scan_value = decoded_opers[0]
    table_addr = decoded_opers[1]
    num_words = decoded_opers[2]
    if len(decoded_opers) > 3:
      form = decoded_opers[3]
    else:
      form = 0x82 # word-search, fields of length two

    addr_value, word_found = self.scanTable(scan_value, table_addr, num_words, form)

    self.pc += instruction.instr_length
    self.setVariable(instruction.store_variable, addr_value)
    self.handleJumpDestination(word_found, instruction)

  def buildCallbackRoutineCall(self, address, instruction=None, decoded_opers=None):
    # Create a new routine object
    new_routine = RoutineCall()
    # Grab the return addr
    if instruction:
      new_routine.return_address = self.pc + instruction.instr_length
      new_routine.store_variable = instruction.store_variable
      new_routine.is_callback = False
    else:
      new_routine.return_address = self.pc # Come back to where we left off
      new_routine.store_variable = None
      new_routine.is_callback = True
    new_routine.stack_state = list(self.stack) # ??? Is this right?
    new_routine.frame_pointer = len(self.routine_callstack)
    routine_address = self.unpackAddress(address, True)
    printLog("Routine address: " + hex(routine_address))
    # How many local variables?
    local_var_count = self.getByte(routine_address)
    printLog("Total local variables: " + str(local_var_count))
    # For versions 1-4, we have initial values for these variables
    # Versions 5+ use zero instead
    for i in range(local_var_count):
      if (self.version < 5):
        variable_value = self.getWord(routine_address + 1 + (2*i))
        new_routine.local_variables.append(variable_value)
      else:
        new_routine.local_variables.append(0)

    printLog("Locals before operand set", new_routine.local_variables)
    # Now set the locals as per the operands
    # Throw away 'extra' operands
    if instruction:
      decoded_opers.pop(0)
      for index, operand in enumerate(decoded_opers):
        if index >= len(new_routine.local_variables):
          break
        new_routine.local_variables[index] = operand
      new_routine.called_arg_count = len(decoded_opers)
    else:
      new_routine.called_arg_count = 0

    # Finally, add the routine to the stack
    self.routine_callstack.append(new_routine)
    printLog(self.routine_callstack)
    new_routine.print_debug()

    printLog("Locals after operand set", new_routine.local_variables)

    printLog("Called with these values:")
    printLog(new_routine.local_variables)

    # Now set the pc to the instruction after the header
    # and default local variables
    new_pc = routine_address + 1

    # Version 5+ doesn't have these local variables
    if (self.version < 5):
      new_pc += 2 * local_var_count

    printLog("Next instruction at: " + hex(new_pc))

    return new_routine, new_pc

  def callRoutine(self, new_pc):
    self.pc = new_pc

  def call(self, instruction):
    printLog("Routine call during run")
    decoded_opers = self.decodeOperands(instruction)
    # First operand is calling address
    calling_addr = decoded_opers[0]
    # Check for address 0
    if (calling_addr == 0):
      self.setVariable(instruction.store_variable, 0)
      self.pc += instruction.instr_length
      return

    # Create a new routine object
    new_routine, new_pc = self.buildCallbackRoutineCall(calling_addr, instruction, decoded_opers)
    self.callRoutine(new_pc)


  def quit(self, instruction):
    printLog("quit")
    stdscr.addstr("\n[Press any key to exit.]")
    stdscr.getch()
    quit()

  def eraseWindow(self, window):
    maxy, maxx = stdscr.getmaxyx()
    if window == 0:
      stdscr.addstr(self.topWinRows, 0, ' ' * maxx * (maxy-self.topWinRows), self.getTextAttributes())
      if self.version < 5:
        self.bottomWinCursor = (maxy-1, 0)
      else:
        self.bottomWinCursor = (self.topWinRows, 0)
    if window == 1:
      stdscr.addstr(1, 0, ' ' * maxx * (self.topWinRows), self.getTextAttributes())
      self.topWinCursor = (0, 0)
    if window == -1:
      self.splitWindow(0)
      stdscr.addstr(1, 0, ' ' * maxx * maxy, self.getTextAttributes())
      if self.version < 5:
        self.bottomWinCursor = (maxy-1, 0)
      else:
        self.bottomWinCursor = (self.topWinRows, 0)
      self.topWinCursor = (0, 0)
    if window == -2:
      stdscr.addstr(1, 0, ' ' * maxx * maxy, self.getTextAttributes())
      if self.version < 5:
        self.bottomWinCursor = (maxy-1, 0)
      else:
        self.bottomWinCursor = (self.topWinRows, 0)
      self.topWinCursor = (0, 0)

  def splitWindow(self, rows):
    # Lots of annoying offset logic depending on if there's
    # a status line (<V4) or not.

    self.topWinRows = rows

    # Store cursor
    y, x = stdscr.getyx()
    maxy, maxx = stdscr.getmaxyx()
    printLog("Split window:", rows, maxy, maxx)

    # Let the bottom part of the window scroll
    if (rows+1 < maxy):
      stdscr.move(rows+1, 0) # This line is needed by windows-curses
                             # as it seems that the cursor must be
                             # in the scrollable area for the call to
                             # succeed. Not needed when tested on
                             # Linux.
      if self.version < 4:
        stdscr.setscrreg(rows+1, maxy-1)
      else:
        stdscr.setscrreg(rows, maxy-1)
    else:
      pass # The whole screen is the upper window

    if rows == 0:
      return

    if self.version < 4:
      # Clear the window
      stdscr.addstr(1, 0, ' ' *maxx * rows, self.getTextAttributes())
      self.topWinCursor = (1,0)
    else:
      self.topWinCursor = (0,0)
    stdscr.move(y,x)

    # The spec implies that you need to have the bottom window
    # selected to do a split, so theoretically we should be
    # able to assume the current cursor position is the
    # bottom cursor's location. If this is no longer in the
    # bottom window, move it to the top left of the bottom
    # window.
    if self.bottomWinCursor[0] <= rows:
      self.bottomWinCursor = (rows+1, 0)

  def setWindow(self, window):
    if window > 1:
      raise Exception("Illegal window selected")
    self.targetWindow = window

    # Always reset top cursor for top window selection
    if window == 1:
      if (self.version < 4): # Status line...
        self.topWinCursor = (1,0)
      else:
        self.topWinCursor = (0,0)

  def decodeOperands(self, instruction):
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        printLog("Variable Operand:", hex(self.peekVariable(operand_pair[1])))
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        printLog("Operand:", hex(operand_pair[1]))
        decoded_opers.append(operand_pair[1])
    printLog(decoded_opers)
    return decoded_opers

  def getVariable(self, variable_number):
    if (variable_number == 0x00):
      return self.popStack()
    if (variable_number > 0x00 and variable_number < 0x10):
      return self.getLocalVariable(variable_number - 0x01)
    else:
      return self.getGlobalVariableValue(variable_number - 0x10)

  def peekVariable(self, variable_number):
    if (variable_number == 0x00):
      return self.getStack()[-1]
    if (variable_number > 0x00 and variable_number < 0x10):
      return self.getLocalVariable(variable_number - 0x01)
    else:
      return self.getGlobalVariableValue(variable_number - 0x10)

  def setVariable(self, variable_number, value):
    if (variable_number == 0x00):
      self.pushStack(value)
    elif (variable_number > 0x00 and variable_number < 0x10):
      self.setLocalVariable(variable_number - 0x01, value)
    else:
      self.setGlobalVariable(variable_number - 0x10, value)

  def setVariableInPlace(self, variable_number, value):
    if (variable_number == 0x00):
      self.setTopOfStack(value)
    elif (variable_number > 0x00 and variable_number < 0x10):
      self.setLocalVariable(variable_number - 0x01, value)
    else:
      self.setGlobalVariable(variable_number - 0x10, value)

  def getStack(self):
    if (len(self.routine_callstack) > 0):
      return self.routine_callstack[-1].stack
    return self.stack

  def setTopOfStack(self, value):
    self.getStack()[-1] = value

  def pushStack(self, value):
    self.getStack().append(value)

  def popStack(self):
    return self.getStack().pop()

  def getLocalVariable(self, variable_number):
    top_routine = self.routine_callstack[-1]
    return top_routine.local_variables[variable_number]

  def setLocalVariable(self, variable_number, value):
    top_routine = self.routine_callstack[-1]
    top_routine.local_variables[variable_number] = value

  def getGlobalVariableAddr(self, variable_number):
    return self.global_table_start + (variable_number * 2)

  def getGlobalVariableValue(self, variable_number):
    return self.getWord(self.getGlobalVariableAddr(variable_number))

  def setGlobalVariable(self, variable_number, value):
    printLog("Setting global variable", variable_number)
    # Split value into two bytes
    top_byte, bottom_byte = self.breakWord(value)
    top_addr = self.getGlobalVariableAddr(variable_number)
    printLog("Global variable addr:", hex(top_addr))
    self.mem[top_addr] = top_byte
    self.mem[top_addr + 1] = bottom_byte
    printLog("Top byte:")
    printLog(hex(self.mem[top_addr]))
    printLog("Bottom byte:")
    printLog(hex(self.mem[top_addr+1]))

  # First address depends on version
  def getFirstAddress(self):
    printLog("getFirstAddress")
    if (self.version != 6):
      self.pc = self.getWord(0x06)
    else:
      self.pc = self.unpackAddress(self.getWord(0x06), True)
    printLog(self.pc)

  def getBytes(self, addr, count):
    num = 0
    for i in range(count):
      num += self.mem[addr + i] << (i*8)
    return num

  # Most numbers are stored as two adjacent bytes
  def getWord(self, addr):
    return (self.mem[addr] << 8) + self.mem[addr+1]

  # Some are small!
  def getByte(self, addr):
    return self.mem[addr]

  # Read an instruction (probably at PC)
  # Bit complicated due to versioning...
  def getInstruction(self, addr):
    printLog("getInstruction at " + hex(addr))
    printTrace(hex(addr) + " ")
    next_byte = addr
    # First, determine the opcode
    first_opcode_byte = self.mem[addr]
    printLog("Opcode:" + str(first_opcode_byte) + "(" + hex(first_opcode_byte) + ")")
    next_byte += 1
    opcode = None
    form = None
    opcount = None
    operands = []
    store_variable = None
    branch_offset = None
    text_to_print = None
    func = None
    operand_types = []
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      opcode, func = self.opcodeMap["EXT"][self.mem[next_byte]]
      form = Form.Extended
      next_byte += 1

    # Figure out instruction form
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      form = Form.Extended
    elif ((first_opcode_byte & 0b11000000) == 0b11000000):
      form = Form.Variable
    elif ((first_opcode_byte & 0b10000000) == 0b10000000):
      form = Form.Short
    else:
      form = Form.Long

    printLog("Got form: " + form.name)

    # Figure out the operand count and type(s)
    opcount = self.getOperandCount(form, first_opcode_byte)
    if (not opcode):
      opcode, func = self.getOpcode(first_opcode_byte, opcount)

    if (opcount != Operand.ZeroOP):
      if (form == Form.Extended or form == Form.Variable):
        operand_types = self.getOperandType(form, self.mem[next_byte])
        next_byte += 1
        # Special case: call_vs2 and call_vn2 can have 4 more args
        if (opcode == 'call_vs2' or opcode == 'call_vn2'):
          operand_types += self.getOperandType(form, self.mem[next_byte])
          next_byte += 1
      else:
        operand_types = self.getOperandType(form, first_opcode_byte)

      # Now get that many operands...
      for operand_type in operand_types:
        if (operand_type == OperandType.Large):
          operands.append(self.getWord(next_byte))
          next_byte += 2
        if (operand_type == OperandType.Small):
          operands.append(self.getByte(next_byte))
          next_byte += 1
        if (operand_type == OperandType.Variable):
          operands.append(self.getByte(next_byte))
          next_byte += 1

    # If this opcode needs a store variable, get it...
    if (needsStoreVariable(opcode)):
      store_variable = self.getByte(next_byte)
      next_byte += 1

    # If this opcode needs a branch offset, get that...
    branch_on_true = None
    if (needsBranchOffset(opcode)):
      branch_byte = self.getByte(next_byte)
      branch_on_true = (branch_byte & 0b10000000) == 0b10000000
      next_byte += 1
      if ((branch_byte & 0b01000000) == 0b01000000):
        branch_offset = branch_byte & 0b00111111
      else:
        branch_byte_two = self.getByte(next_byte)
        # Annoying 15-bit sign conversion
        val = ((branch_byte & 0b00011111) << 8) + branch_byte_two
        if ((branch_byte & 0b00100000) == 0b00100000):
          val = -(0x2000 - val)
        branch_offset = val
        next_byte += 1

    # If this opcode needs a string literal, get that...
    text_literal = None
    if (needsTextLiteral(opcode, self.version)):
      text_literal, next_byte = self.getEncodedTextLiteral(next_byte)

    instr_length = next_byte - addr

    return Instruction(opcode,
                       operand_types,
                       operands,
                       store_variable,
                       branch_on_true,
                       branch_offset,
                       text_to_print,
                       text_literal,
                       instr_length,
                       func,
                       first_opcode_byte)

  def getEncodedTextLiteral(self, next_byte):
    chars = self.getWord(next_byte)
    text_literal = []
    # First two-byte set with the first bit set to '0' is the end of the stream
    while ((chars & 0x8000) != 0x8000):
      text_literal.append(chars)
      next_byte += 2
      chars = self.getWord(next_byte)
    text_literal.append(chars)
    next_byte += 2
    return (text_literal, next_byte)

  def scanTable(self, scan_value, table_addr, num_words, form):
    # Search for a match in a given table
    # Form determines if we search for words/bytes, and the length of each
    # field in the table.
    word_found = False # Feels superfluous - can you return address zero AND branch..?
    addr_value = 0
    search_for_word = isNthBitSet(form, 7)
    field_length = form & 0b01111111
    for i in range(num_words):
      addr_to_check = table_addr +  (i * field_length)
      if search_for_word:
        value_in_table = self.getWord(addr_to_check)
      else:
        value_in_table = self.getByte(addr_to_check)
      if scan_value == value_in_table:
        addr_value = addr_to_check
        word_found = True
        break
    return addr_value, word_found

  def getPropertyDefault(self, prop_number):
    # Prop_number >= 1 < 32 for versions 1-3, < 64 for version 4
    # Need to offset
    start_addr = self.object_table_start
    prop_addr = self.object_table_start + ((prop_number-1) * 2)
    printLog("getPropertyDefault: return word: prop num:", prop_number, "val:", self.getWord(prop_addr))
    prop_default = self.getWord(prop_addr)
    return prop_default

  def getObjSize(self):
    if self.version > 3:
      return 14
    return 9

  def getObjectAddress(self, obj_number):
    num_prop_defaults = 31
    if (self.version > 3):
      num_prop_defaults = 63
    obj_tree_start_address = self.object_table_start + (num_prop_defaults * 2)
    # Object number starts from '1', so need to offset
    obj_address = obj_tree_start_address + ((obj_number-1) * self.getObjSize())
    return obj_address

  def getEncodedObjectShortName(self, obj_number):
    prop_addr = self.getPropertyTableAddress(obj_number)
    return self.getEncodedTextLiteral(prop_addr+1)[0]

  def isAttributeSet(self, obj_number, attrib_number):
    if self.version < 4:
      return self.isAttributeSetV1(obj_number, attrib_number)
    else:
      return self.isAttributeSetV4(obj_number, attrib_number)

  def isAttributeSetV1(self, obj_number, attrib_number):
    obj_addr = self.getObjectAddress(obj_number)
    attrib_bit = 0x80000000 >> (attrib_number)
    first_two_attribute_bytes = self.getWord(obj_addr)
    last_two_attribute_bytes = self.getWord(obj_addr+2)
    full_flags = (first_two_attribute_bytes << 16) + last_two_attribute_bytes
    return (attrib_bit & full_flags) == attrib_bit

  def isAttributeSetV4(self, obj_number, attrib_number):
    obj_addr = self.getObjectAddress(obj_number)
    attrib_bit = 0x800000000000 >> (attrib_number)
    first_two_attribute_bytes = self.getWord(obj_addr)
    middle_two_attribute_bytes = self.getWord(obj_addr+2)
    last_two_attribute_bytes = self.getWord(obj_addr+4)
    full_flags = (first_two_attribute_bytes << 32) + (middle_two_attribute_bytes << 16) + last_two_attribute_bytes
    return (attrib_bit & full_flags) == attrib_bit

  def checkArgCount(self, arg_number):
    return arg_number <= self.routine_callstack[-1].called_arg_count

  def setAttribute(self, obj_number, attrib_number, value):
    if self.version < 4:
      return self.setAttributeV1(obj_number, attrib_number, value)
    else:
      return self.setAttributeV4(obj_number, attrib_number, value)

  def setAttributeV1(self, obj_number, attrib_number, value):
    printLog("setAttribute", obj_number, attrib_number, value)
    obj_addr = self.getObjectAddress(obj_number)
    full_flags = (self.getWord(obj_addr) << 16) + self.getWord(obj_addr+2)
    printLog(bin(full_flags))
    if (value):
      printLog("Setting", attrib_number, "on", obj_number, "to True")
      attrib_bit = 0x80000000 >> attrib_number
      full_flags |= attrib_bit
    else:
      printLog("Setting", attrib_number, "on", obj_number, "to False")
      attrib_bit = 0xffffffff
      attrib_bit -= (0x80000000 >> attrib_number)
      full_flags &= attrib_bit
    printLog(bin(full_flags))
    word_1 = full_flags >> 16
    word_2 = full_flags & 0x0000ffff
    byte_1, byte_2 = self.breakWord(word_1)
    byte_3, byte_4 = self.breakWord(word_2)

    self.mem[obj_addr] = byte_1
    self.mem[obj_addr+1] = byte_2
    self.mem[obj_addr+2] = byte_3
    self.mem[obj_addr+3] = byte_4

    # DEBUG - Validate
    if (self.isAttributeSet(obj_number, attrib_number) != value):
      raise Exception("Failure setting attribute")

    return

  def setAttributeV4(self, obj_number, attrib_number, value):
    printLog("setAttribute", obj_number, attrib_number, value)
    obj_addr = self.getObjectAddress(obj_number)
    full_flags = (self.getWord(obj_addr) << 32) + (self.getWord(obj_addr+2) << 16) + self.getWord(obj_addr+4)
    printLog(bin(full_flags))
    if (value):
      printLog("Setting", attrib_number, "on", obj_number, "to True")
      attrib_bit = 0x800000000000 >> attrib_number
      full_flags |= attrib_bit
    else:
      printLog("Setting", attrib_number, "on", obj_number, "to False")
      attrib_bit = 0xffffffffffff
      attrib_bit -= (0x800000000000 >> attrib_number)
      full_flags &= attrib_bit
    printLog(bin(full_flags))
    word_1 = full_flags >> 32
    word_2 = (full_flags & 0xffff0000) >> 16
    word_3 = full_flags & 0x0000ffff
    byte_1, byte_2 = self.breakWord(word_1)
    byte_3, byte_4 = self.breakWord(word_2)
    byte_5, byte_6 = self.breakWord(word_3)

    self.mem[obj_addr] = byte_1
    self.mem[obj_addr+1] = byte_2
    self.mem[obj_addr+2] = byte_3
    self.mem[obj_addr+3] = byte_4
    self.mem[obj_addr+4] = byte_5
    self.mem[obj_addr+5] = byte_6

    # DEBUG - Validate
    if (self.isAttributeSet(obj_number, attrib_number) != value):
      raise Exception("Failure setting attribute")

  def getObjectRelationshipsAddress(self, obj_number):
    obj_addr = self.getObjectAddress(obj_number)
    if (self.version > 3):
      return obj_addr + 6
    return obj_addr + 4

  def getObjectParentAddress(self, obj_number):
    return self.getObjectRelationshipsAddress(obj_number)

  def getObjectSiblingAddress(self, obj_number):
    sibling_addr = self.getObjectParentAddress(obj_number)
    if (self.version > 3):
      sibling_addr += 2
    else:
      sibling_addr += 1
    return sibling_addr

  def getObjectChildAddress(self, obj_number):
    child_addr = self.getObjectSiblingAddress(obj_number)
    if (self.version > 3):
      child_addr += 2
    else:
      child_addr += 1
    return child_addr

  def getObjectParent(self, obj_number):
    parent_addr = self.getObjectParentAddress(obj_number)
    if (self.version > 3):
      return self.getWord(parent_addr)
    return self.getByte(parent_addr)

  def getObjectSibling(self, obj_number):
    sibling_addr = self.getObjectSiblingAddress(obj_number)
    if (self.version > 3):
      return self.getWord(sibling_addr)
    return self.getByte(sibling_addr)

  def getObjectChild(self, obj_number):
    child_addr = self.getObjectChildAddress(obj_number)
    if (self.version > 3):
      return self.getWord(child_addr)
    return self.getByte(child_addr)

  def setObjectParent(self, obj_number, parent):
    parent_addr = self.getObjectParentAddress(obj_number)
    if (self.version > 3):
      p_1, p_2 = self.breakWord(parent)
      self.mem[parent_addr] = p_1
      self.mem[parent_addr+1] = p_2
    else:
      self.mem[parent_addr] = parent

  def setObjectSibling(self, obj_number, sibling):
    sibling_addr = self.getObjectSiblingAddress(obj_number)
    if (self.version > 3):
      s_1, s_2 = self.breakWord(sibling)
      self.mem[sibling_addr] = s_1
      self.mem[sibling_addr+1] = s_2
    else:
      self.mem[sibling_addr] = sibling

  def setObjectChild(self, obj_number, child):
    child_addr = self.getObjectChildAddress(obj_number)
    if (self.version > 3):
      c_1, c_2 = self.breakWord(child)
      self.mem[child_addr] = c_1
      self.mem[child_addr+1] = c_2
    else:
      self.mem[child_addr] = child

  def breakWord(self, word):
    byte_1 = (0xff00 & word) >> 8
    byte_2 = (0x00ff & word)
    return (byte_1, byte_2)

  def getProperty(self, obj_number, prop_number):
    prop_addr = self.getPropertyAddress(obj_number, prop_number)
    if (prop_addr == 0): # No property found
      return self.getPropertyDefault(prop_number)
    prop_bytes, skip_bytes = self.getPropertySize(prop_addr)
    prop_start_addr = prop_addr + skip_bytes
    if (prop_bytes == 2):
      printLog("getProperty: return word: prop num:", prop_number, "val:", hex(self.getWord(prop_start_addr)))
      return self.getWord(prop_start_addr)
    elif (prop_bytes == 1):
      printLog("getProperty: return byte: prop num:", prop_number, "val:", hex(self.getWord(prop_start_addr)))
      return self.getByte(prop_start_addr)
    else:
      raise Exception("Illegal property access")

  def getPropertyTableAddress(self, obj_number):
    obj_addr = self.getObjectAddress(obj_number)
    printLog("obj_addr", hex(obj_addr))
    prop_table_offset = 7 # 4 bytes to attribute, 3 bytes of relationships
    if (self.version > 3):
      prop_table_offset = 12 # 6 bytes of attribute, 3 words of relationships
    prop_table_address = self.getWord(obj_addr + prop_table_offset)
    return prop_table_address

  def getPropertyListAddress(self, obj_number):
    prop_table_address = self.getPropertyTableAddress(obj_number)
    printLog("Prop addr: prop table address:", hex(prop_table_address))
    short_name_length = self.getByte(prop_table_address)
    prop_list_start = prop_table_address + (short_name_length*2) + 1
    return prop_list_start

  def getNextProperty(self, obj_number, prop_number):
    if (prop_number != 0):
      cur_prop_addr = self.getPropertyAddress(obj_number, prop_number)
      prop_bytes, skip_bytes = self.getPropertySize(cur_prop_addr)
      next_prop_addr = cur_prop_addr + skip_bytes + prop_bytes
      next_prop_number = self.getPropertyNumber(next_prop_addr)
      return next_prop_number
    else:
      first_prop_addr = self.getPropertyListAddress(obj_number)
      first_prop_number = self.getPropertyNumber(first_prop_addr)
      return first_prop_number

  def getPropertyAddress(self, obj_number, prop_number):
    prop_list_address = self.getPropertyListAddress(obj_number)
    printLog("Prop addr: prop list addr:", hex(prop_list_address))
    size_byte_addr = prop_list_address
    size_byte = self.getByte(size_byte_addr)
    printLog("Prop addr: size_byte:", size_byte)
    while (size_byte != 0):
      prop_bytes, skip_bytes = self.getPropertySize(size_byte_addr)
      cur_prop_number = self.getPropertyNumber(size_byte_addr)
      printLog("Prop addr: examining prop num:", cur_prop_number)
      if (prop_number == cur_prop_number):
        printLog("Prop addr: found prop at:", hex(size_byte_addr))
        return size_byte_addr
      printLog("Prop addr: wasn't it, skipping bytes:", prop_bytes + skip_bytes)
      # Get the next property
      size_byte_addr += (prop_bytes + skip_bytes) # move past size byte + prop bytes
      size_byte = self.getByte(size_byte_addr)
      printLog("Prop addr: next check at", hex(size_byte_addr))
      printLog("Prop addr: size_byte:", size_byte)
    printLog("Prop addr: prop not found")
    return 0

  def getPropertySize(self, prop_address):
    if self.version < 4:
      return self.getPropertySizeV1(prop_address)
    else:
      return self.getPropertySizeV4(prop_address)

  def getPropertySizeFromOneByte(self, prop_address):
    if self.version < 4:
      return self.getPropertySizeV1(prop_address)[0]
    else:
      size_byte_addr = prop_address
      size_byte = self.getByte(size_byte_addr)
      if ((size_byte & 0b10000000) >> 7) == 1:
        # This is the second size byte, so take the bottom six bits.
        prop_bytes = (size_byte & 0b00111111)
        if prop_bytes == 0:
          prop_bytes = 64
      else:
        # This is the first size byte, so the sixth bit determines the
        # number of bytes.
        if ((size_byte & 0b01000000) >> 6) == 1:
          prop_bytes = 2
        else:
          prop_bytes = 1
    return prop_bytes

  def getPropertySizeV1(self, prop_address):
    size_byte_addr = prop_address
    size_byte = self.getByte(size_byte_addr)
    prop_bytes = ((size_byte & 0b11100000) >> 5) + 1
    skip_bytes = 1
    return prop_bytes, skip_bytes

  def getPropertySizeV4(self, prop_address):
    size_byte_addr = prop_address
    first_size_byte = self.getByte(size_byte_addr)
    if (first_size_byte >> 7) == 1:
      second_size_byte = self.getByte(size_byte_addr+1)
      prop_bytes = (second_size_byte & 0b00111111)
      if prop_bytes == 0:
        # As per spec: A value of 0 as property data length (in the second byte) should be interpreted as a length of 64
        prop_bytes = 64
      skip_bytes = 2
    else:
      skip_bytes = 1
      if ((first_size_byte & 0b01000000) >> 6) == 1:
        prop_bytes = 2
      else:
        prop_bytes = 1
    return prop_bytes, skip_bytes

  def getPropertyNumber(self, prop_address):
    if self.version < 4:
      return self.getPropertyNumberV1(prop_address)
    else:
      return self.getPropertyNumberV4(prop_address)

  def getPropertyNumberV1(self, prop_address):
    size_byte_addr = prop_address
    size_byte = self.getByte(size_byte_addr)
    return (0b00011111 & size_byte)

  def getPropertyNumberV4(self, prop_address):
    size_byte_addr = prop_address
    first_size_byte = self.getByte(size_byte_addr)
    return (first_size_byte & 0b00111111)

  def setProperty(self, obj_number, prop_number, value):
    prop_address = self.getPropertyAddress(obj_number, prop_number)
    prop_bytes, skip_bytes = self.getPropertySize(prop_address)
    top_byte, bottom_byte = self.breakWord(value)
    printLog("set prop", obj_number, prop_number, hex(prop_address), top_byte, bottom_byte)
    if (prop_bytes == 2):
      self.mem[prop_address + skip_bytes] = top_byte
      self.mem[prop_address + skip_bytes + 1] = bottom_byte
    elif (prop_bytes == 1):
      self.mem[prop_address + skip_bytes] = bottom_byte
    else:
      raise Exception("Illegal call to SetProperty")

  def getOperandCount(self, form, opcode_byte):
    if (form == Form.Long):
      opcount = Operand.TwoOP
    elif (form == Form.Short):
      if (opcode_byte & 0b0110000 == 0b0110000):
        opcount = Operand.ZeroOP
      else:
        opcount = Operand.OneOP
    elif (form == Form.Extended):
      opcount = Operand.VAR
    else: # (form == Form.Variable)
      if (opcode_byte & 0b0100000 == 0b0100000):
        opcount = Operand.VAR
      else:
        opcount = Operand.TwoOP
    return opcount

  def getOperandType(self, form, opcode_bytes):
    printLog("getOperandType: " + bin(opcode_bytes))
    if (form == Form.Short):
      if (opcode_bytes & 0b00100000 == 0b00100000):
        return [OperandType.Variable]
      elif (opcode_bytes & 0b00010000 == 0b00010000):
        return [OperandType.Small]
      else:
        return [OperandType.Large]
    elif (form == Form.Long):
      operand_types = []
      if (opcode_bytes & 0b01000000 == 0b01000000):
        operand_types.append(OperandType.Variable)
      else:
        operand_types.append(OperandType.Small)
      if (opcode_bytes & 0b00100000 == 0b00100000):
        operand_types.append(OperandType.Variable)
      else:
        operand_types.append(OperandType.Small)
      return operand_types
    else: # form == Variable or Extended
      operand_types = []
      if (opcode_bytes & 0b11000000 == 0b11000000):
        return operand_types
      else:
        operand_types.append(getOperandTypeFromBytes(opcode_bytes >> 6))
      if (opcode_bytes & 0b00110000 == 0b00110000):
        return operand_types
      else:
        operand_types.append(getOperandTypeFromBytes((opcode_bytes & 0b00110000) >> 4))
      if (opcode_bytes & 0b00001100 == 0b00001100):
        return operand_types
      else:
        operand_types.append(getOperandTypeFromBytes((opcode_bytes & 0b00001100) >> 2))
      if (opcode_bytes & 0b00000011 == 0b00000011):
        return operand_types
      else:
        operand_types.append(getOperandTypeFromBytes(opcode_bytes & 0b00000011))
      return operand_types

  def unpackAddress(self, addr, rcall):
    packedAddress = addr
    if (self.version < 4):
      return 2*packedAddress
    elif (self.version < 6):
      return 4*packedAddress
    elif (self.version < 8 and rcall):
      return 4*packedAddress + (8 * self.routine_offset)
    elif (self.version < 8):
      return 4*packedAddress + (8 * self.string_offset)
    else:
      return 8*packedAddress

  def getOpcode(self, byte, operand_type):
    printLog("getOpcode")
    printLog("last five bits: " + hex(byte & 0b00011111))
    printLog("last four bits: " + hex(byte & 0b00001111))
    key = byte
    if operand_type == Operand.TwoOP:
      key = byte & 0b00011111
    elif operand_type == Operand.OneOP:
      key = byte & 0b00001111
    elif operand_type == Operand.ZeroOP:
      key = byte & 0b00001111
    return self.opcodeMap[operand_type][key]

  def getExtendedOpcode(self, byte):
    printLog("ExtendedOpcode")
    if byte == 0x0:
      return "save4", self.save
    if byte == 0x1:
      return "restore4", self.restore
    if byte == 0x2:
      return "log_shift", self.log_shift
    if byte == 0x3:
      return "art_shift", self.art_shift
    if byte == 0x4:
      return "set_font", self.set_font
    if byte == 0x9:
      return "save_undo", self.save_undo
    if byte == 0xA:
      return "restore_undo", self.restore_undo
    raise Exception("Missing extended opcode: " + hex(byte))

  def generateSaveBlob(self):
    blob = pickle.dumps(self, pickle.HIGHEST_PROTOCOL)
    return blob

  def saveGameForUndo(self):
    blob = self.generateSaveBlob()
    self.undo_buffer.append(blob)
    if len(self.undo_buffer) > 10:
      self.undo_buffer = self.undo_buffer[-10:]
    return 0

  def saveGame(self):
    # Necessary to stream print as we're out of the
    # regular read/input loop
    self.printToStream("Enter filename> ", '')
    self.refreshWindows()
    file_name = self.handleInput(MAX_SAVE_FILE_LENGTH)
    self.printToStream(file_name, '\n')
    file_path = os.path.abspath(file_name)
    printLog("save: file_name: ", file_name)
    printLog("save: file_path: ", file_path)

    # TODO: Don't use pickle, it's dangerous
    try:
      with open(file_name, 'wb') as f:
        blob = self.generateSaveBlob()
        f.write(blob)
        printLog("save: self.pc", self.pc)
        return 1
    except FileNotFoundError:
      pass

    return 0

  def restoreFromBlob(self, blob):
    self.raw = blob.raw
    self.mem = blob.mem
    self.version = blob.mem[0x00]
    self.dynamic = 0
    self.static = blob.mem[0x0e]
    self.high = blob.mem[0x04]
    self.routine_offset = blob.mem[0x28]
    self.string_offset = blob.mem[0x2a]
    self.global_table_start = blob.getWord(0x0c)
    self.object_table_start = blob.getWord(0x0a)
    self.abbreviation_table_start = blob.getWord(0x18)
    self.dictionary_table_start = blob.getWord(0x08)
    self.stack = blob.stack
    self.routine_callstack = blob.routine_callstack
    self.lock_alphabets = blob.lock_alphabets
    self.current_abbrev = blob.current_abbrev
    self.ten_bit_zscii_bytes_needed = blob.ten_bit_zscii_bytes_needed
    self.ten_bit_zscii_bytes = blob.ten_bit_zscii_bytes
    self.word_separators = blob.word_separators
    self.dictionary_mapping = blob.dictionary_mapping
    self.timedGame = blob.timedGame
    self.stream = blob.stream
    self.active_output_streams = blob.active_output_streams
    self.pc = blob.pc
    self.undo_buffer = []
    self.restoring = True

  def restoreFromFile(self):
    self.printToStream("Enter filename> ", '')
    self.refreshWindows()
    file_name = self.handleInput(MAX_SAVE_FILE_LENGTH)
    self.printToStream(file_name, '\n')
    file_path = os.path.abspath(file_name)
    printLog("restore: file_name: ", file_name)
    printLog("restore: file_path: ", file_path)

    try:
      with open(file_name, 'rb') as f:
        printLog("pre-load: self.pc", self.pc)
        loaded_file = pickle.load(f)
        self.restoreFromBlob(loaded_file)
        printLog("post-load:  self.pc", self.pc)
        return 2
    except FileNotFoundError:
      pass

    # Spec: Collapse upper window on restore
    if self.version > 2:
      self.splitWindow(0)

    return 0

  def restoreFromUndo(self):
    # Should not be called unless there's a valid undo available,
    # so let's live DANGEROUSLY.
    last_undo = pickle.loads(self.undo_buffer[-1])
    self.restoreFromBlob(last_undo)
    return 2

  def print_debug(self):
    printLog("-------------")
    printLog("Stack:")
    printLog(self.stack)
    printLog("Routine Stack (if any):")
    printLog(self.getStack())
    if (len(self.routine_callstack) > 0):
      printLog("Current routine state:")
      printLog(self.routine_callstack[-1].print_debug())
    printLog("-------------")

  def getCurrentColourPair(self):
    # Map Z-Machine to Curses
    zmachine_to_curses = dict()
    zmachine_to_curses[2] = curses.COLOR_BLACK
    zmachine_to_curses[3] = curses.COLOR_RED
    zmachine_to_curses[4] = curses.COLOR_GREEN
    zmachine_to_curses[5] = curses.COLOR_YELLOW
    zmachine_to_curses[6] = curses.COLOR_BLUE
    zmachine_to_curses[7] = curses.COLOR_MAGENTA
    zmachine_to_curses[8] = curses.COLOR_CYAN
    zmachine_to_curses[9] = curses.COLOR_WHITE
    cursesFore = zmachine_to_curses[self.currentForeground]
    cursesBack = zmachine_to_curses[self.currentBackground]
    return (cursesFore, cursesBack)

  def getTextAttributes(self):
    flags = 0
    if self.text_reverse_video:
      flags |= curses.A_REVERSE
    if self.text_bold:
      flags |= curses.A_BOLD
    if self.text_italic:
      # Actually only present on Python 3.7 and above...
      # and presumably not windows-curses either, but needs to be tested
      if sys.version_info >= (3,7):
        flags |= curses.A_ITALIC
    if self.text_fixed_pitch:
      pass

    colour_pair = self.getCurrentColourPair()
    flags |= colour_map[colour_pair]

    return flags

  def printBufferedString(self, string):
    # Idea: Split string into words
    # Print each word if it won't off the end of the screen
    # Otherwise print a newline and then print.

    tokens = string.split(' ')
    for i, token in enumerate(tokens):
      if i != len(tokens) - 1:
        token += " "
      y, x = stdscr.getyx()
      maxY, maxX = stdscr.getmaxyx()
      if x + len(token) > maxX:
        stdscr.addstr('\n', self.getTextAttributes())
      stdscr.addstr(token, self.getTextAttributes())

  def dumpRedirectStream(self):
    char_count = len(self.z_memory_buffer)
    char_count_high, char_count_low = self.breakWord(char_count)
    self.mem[self.z_memory_address] = char_count_high
    self.mem[self.z_memory_address+1] = char_count_low
    for i in range(char_count):
      self.mem[self.z_memory_address+2+i] = ord(self.z_memory_buffer[i])
    self.z_memory_address = 0
    self.z_memory_buffer = []

  def setTextStyle(self, textStyle):
    if textStyle == 0:
      self.text_reverse_video = False
      self.text_bold = False
      self.text_italic = False
      self.text_fixed_pitch = False
    if textStyle == 1:
      self.text_reverse_video = True
    if textStyle == 2:
      self.text_bold = True
    if textStyle == 4:
      self.text_italic = True
    if textStyle == 8:
      self.text_fixed_pitch = True

    stdscr.bkgdset(' ', self.getTextAttributes())

  def setColour(self, foreground, background):
    # Change the colours according to the colour table
    if foreground == 0: # Current
      pass
    elif foreground == 1: # Default
      self.currentForeground = 9 # Reset to default
    else:
      self.currentForeground = foreground

    if background == 0: # Current
      pass
    elif background == 1: # Default
      self.currentBackground = 2 # Reset to default
    else:
      self.currentBackground = background

    stdscr.bkgdset(' ', self.getTextAttributes())

  def setFont(self, textStyle):
    # We don't support any fonts in Fic due to terminal limitations
    # so we return zero when asked to do anything fancy.
    if textStyle == 0:
      return self.currentFont
    if textStyle == 1:
      return self.currentFont
    if textStyle == 2:
      return 0
    if textStyle == 3:
      return 0
    if textStyle == 4:
      return 0

  def eraseLine(self, pixels):
    if self.version == 6:
      raise Exception("Not implemented")
    elif pixels == 1: # Only do anything for v4/5 if pixels is one
      stdscr.clrtoeol() # Loving the curses specific code...

  def setCursor(self, line, column):
    if self.targetWindow == 0:
      # Remember there's an offset for the bottom window
      self.bottomWinCursor = (self.topWinRows + line, column)
    elif self.targetWindow == 1:
      # No offset for the top one, we've already
      # converted to Curses co-ordinates
      self.topWinCursor = (line, column)

  def getCursor(self, array):
    currentCursor = (0,0)
    if self.targetWindow == 0:
      currentCursor = self.bottomWinCursor
    elif self.targetWindow == 1:
      currentCursor = self.topWinCursor
    # Curses -> Z-Machine conversion = offset by one
    row = currentCursor[0] + 1
    column = currentCursor[1] + 1
    # Assumption: You can have > 255 rows or columns
    row_byte1, row_byte2 = self.breakWord(row)
    column_byte1, column_byte2 = self.breakWord(column)
    self.mem[array] = row_byte1
    self.mem[array+1] = row_byte2
    self.mem[array+2] = column_byte1
    self.mem[array+3] = column_byte2

  def setInputStream(self, stream):
    self.active_input_stream = stream

  def setOutputStream(self, stream, table):
    if stream == 0:
      return

    state = stream > 0
    stream = abs(stream)

    if state:
      if stream not in self.active_output_streams:
        self.active_output_streams.append(stream)
        if stream == 3:
          self.z_memory_address = table
    if not state:
      if stream in self.active_output_streams:
        self.active_output_streams.remove(stream)
        if stream == 3:
          self.dumpRedirectStream()

  def printToCommandStream(self, string, end):
    if 3 in self.active_output_streams:
      # No printing if 3 is active
      return

    if 4 in self.active_output_streams:
      print(string, end=end, file=commands)

  def printToStream(self, string, end):
    if 3 in self.active_output_streams:
      self.z_memory_buffer += string + end
      # No more printing if 3 is active
      return

    # Print to screen
    if 1 in self.active_output_streams:
      if (self.bufferText and self.targetWindow == 0):
        y, x = self.bottomWinCursor
        stdscr.move(y, x)
        self.printBufferedString(string + end)
        self.bottomWinCursor = stdscr.getyx()
      else:
        if (self.targetWindow == 0):
          y, x = self.bottomWinCursor
          stdscr.move(y, x)
          stdscr.addstr(y, x, string + end, self.getTextAttributes())
          self.bottomWinCursor = stdscr.getyx()
        elif (self.targetWindow == 1):
          y, x = self.topWinCursor
          stdscr.move(y, x)
          stdscr.addstr(y, x, string + end, self.getTextAttributes())
          self.topWinCursor = stdscr.getyx()

    # Print to transcript
    # TODO: Buffering
    if 2 in self.active_output_streams:
      if (self.bufferText and self.targetWindow == 0):
        print(string, end=end, file=transcript)
      else:
        if (self.targetWindow == 0):
          print(string, end=end, file=transcript)

    # Print to private
    if 5 in self.active_output_streams:
      self.stream += string + end

  def refreshWindows(self):
    if (self.targetWindow == 0):
      y, x = self.bottomWinCursor
    elif (self.targetWindow == 1):
      y, x = self.topWinCursor
    if input_win is not None:
      input_win.touchwin()
      input_win.refresh()
    stdscr.touchwin()
    stdscr.refresh()
    stdscr.move(y, x)

  def setScreenDimensions(self):
    y, x = stdscr.getmaxyx()
    # Dimensions of screen
    self.mem[0x20] = y # Lines
    self.mem[0x21] = x # Characters
    # Specifically for fixed-width terminals
    # all dimensions are '1'. So the screen
    # width/height are equal to the 1*height/width.
    # Screen width - 8.4.3 of spec 1.1 states these are words
    x_1, x_2 = self.breakWord(x)
    self.mem[0x22] = x_1
    self.mem[0x23] = x_2
    # Screen height
    y_1, y_2 = self.breakWord(y)
    self.mem[0x24] = y_1
    self.mem[0x25] = y_2
    # Font width/height in 'units' (swapped between v5/v6, but
    # in our case it's the same so we don't care)
    self.mem[0x26] = 1
    self.mem[0x27] = 1

  def drawWindows(self):
    if self.version < 4 and self.readRanOnce:
      self.drawStatusLine()
    self.setScreenDimensions()
    self.refreshWindows()

  def getCurrentWindowCursorPosition(self):
    return stdscr.getyx()

  def getCurrentScreenCursorPosition(self):
    return stdscr.getsyx()

  def drawStatusLine(self):
    # Room name...
    # Use the rubbish print workaround that we have to fix eventually
    self.stream = ""
    active_streams = self.active_output_streams
    self.active_output_streams = [5] # Our private output stream
    self._print_string(self.getEncodedObjectShortName(self.getGlobalVariableValue(0)))
    roomName = " " + self.stream
    self.active_output_streams = active_streams

    roomNameLength = len(roomName)

    # Score or time...
    scoreTimeString = ""
    if self.timedGame:
      hour = self.getGlobalVariableValue(1)
      minute = self.getGlobalVariableValue(2)
      scoreTimeString = "Time: {:02d}:{:02d}".format(hour, minute)
    else:
      score = self.getGlobalVariableValue(1)
      turns = self.getGlobalVariableValue(2)
      scoreTimeString = "Score: {0: >3}  Turns: {1: >4}".format(score, turns)

    # Do the rubbish part
    columns, rows = stdscr.getmaxyx()
    margin = 8
    printScoreStringAt = rows - margin - len(scoreTimeString)
    spaceBetweenRoomNameAndScoreString = printScoreStringAt - roomNameLength

    # Save position, print the status line, come back
    y, x = stdscr.getyx()
    string = roomName
    string += " " * spaceBetweenRoomNameAndScoreString
    string += scoreTimeString
    string += " " * margin
    stdscr.addstr(0, 0, string, curses.A_REVERSE)
    stdscr.move(y, x)

def needsStoreVariable(opcode):
  return opcode in NeedStoreVariable

def needsBranchOffset(opcode):
  return opcode in NeedBranchOffset

def needsTextLiteral(opcode, version):
  return opcode in NeedTextLiteral

def getOperandTypeFromBytes(byte):
  if (byte == 0):
    return OperandType.Large
  elif (byte == 1):
    return OperandType.Small
  else: # (byte == 2)
    return OperandType.Variable

def main():
  # Setup for screen... lots of Curses rubbish
  global stdscr
  global main_memory
  stdscr = curses.initscr()
  curses.start_color()
  curses.noecho()
  curses.cbreak()
  stdscr.keypad(True)
  stdscr.clear()
  stdscr.idlok(True)
  stdscr.scrollok(True)
  y, x = stdscr.getmaxyx()
  buildColourMap()

  # Load up the game
  main_memory = StoryLoader.LoadZFile(sys.argv[1])
  main_memory.readStandardDictionary()

  # Set the initial cursor position
  main_memory.bottomWinCursor = (y-1, 0)
  main_memory.setScreenDimensions()

  try:
    replay = open('replay.txt', 'r', buffering=1)
    main_memory.input_lines = replay.readlines()
  except:
    pass

  # If this is Z-Machine 6, we don't have a 'first instruction',
  # but a 'main routine' instead. So create a call instruction
  # and run it against the address specified in the story file
  # before jumping into the main loop
  if (main_memory.version == 6):
    pass # TODO
  loop(main_memory)

def loop(main_memory):
  while True:
    main_memory.print_debug()
    instr = main_memory.getInstruction(main_memory.pc)
    instr.print_debug()
    instr.run(main_memory)
    if CZECH_MODE:
      # If running in Czech mode, we will flush output after EVERY command
      main_memory.drawWindows()

if __name__ == "__main__":
  try:
    main()
  finally:
    # Try and save the terminal from a hideous fate!
    curses.nocbreak()
    curses.echo()
    stdscr.keypad(False)
    curses.endwin()
