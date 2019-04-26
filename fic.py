import readchar
import sys
import random
import time
import textwrap
import re
import colorama
import os
import ctypes
import struct
from enum import Enum

# Enums
Form = Enum('Form', 'Short Long Variable Extended')
Operand = Enum('Operand', 'ZeroOP OneOP TwoOP VAR')
OperandType = Enum('OperandType', 'Large Small Variable')
Alphabet = Enum('Alphabet', 'A0 A1 A2')

# 'Needs'
NeedBranchOffset = ["jin","jg","jl","je","inc_chk","dec_chk","jz","get_child","get_sibling","test_attr","test", "verify"]
NeedStoreVariable = ["call","and","get_parent","get_child","get_sibling","get_prop","add","sub","mul","div","mod","loadw","loadb", "get_prop_addr", "get_prop_len", "get_next_prop", "random", "load", "and", "or"]
NeedTextLiteral = ["print","print_ret"]

# Alphabet
a0 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y', 'z']))
a1 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y', 'Z']))
a2 = dict(zip([6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
              ['`','\n','0','1','2','3','4','5','6','7','8','9','.',',','!','?','_','#','\'','"','/','\\','-',':','(', ')']))

input_map = dict(zip(['`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y', 'z', '\n','0','1','2','3','4','5','6','7','8','9','.',',','!','?','_','#','\'','"','/','\\','-',':','(', ')'],
                     [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]))


# Logging
tracefile = open('trace.txt', 'w', buffering=1)
logfile = open('full_log.txt', 'w', buffering=1)

TRACEPRINT = False
LOGPRINT = False

def printTrace(*string):
  if TRACEPRINT:
    print(string, file=tracefile)

def printLog(*string):
  if LOGPRINT:
    print(string, file=logfile)

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
               first_opcode_byte):
    self.opcode = opcode
    self.operand_types = operand_types
    self.operands = operands
    self.store_variable = store_variable
    self.branch_on_true = branch_on_true
    self.branch_offset = branch_offset
    self.text_to_print = text_to_print
    self.encoded_string_literal = encoded_string_literal
    self.instr_length = instr_length
    self.my_byte = first_opcode_byte

  def run(self, main_memory):
    printTrace("Running opcode: " + str(self.my_byte) + " " + str(self.opcode))

    if (self.opcode == 'call'):
      main_memory.call(self)
    elif (self.opcode == 'add'):
      main_memory.add(self)
    elif (self.opcode == 'mul'):
      main_memory.mul(self)
    elif (self.opcode == 'and'):
      main_memory.and_1(self)
    elif (self.opcode == 'or'):
      main_memory.or_1(self)
    elif (self.opcode == 'je'):
      main_memory.je(self)
    elif (self.opcode == 'inc_chk'):
      main_memory.inc_chk(self)
    elif (self.opcode == 'dec_chk'):
      main_memory.dec_chk(self)
    elif (self.opcode == 'inc'):
      main_memory.inc(self)
    elif (self.opcode == 'dec'):
      main_memory.dec(self)
    elif (self.opcode == 'get_parent'):
      main_memory.get_parent(self)
    elif (self.opcode == 'get_child'):
      main_memory.get_child(self)
    elif (self.opcode == 'get_sibling'):
      main_memory.get_sibling(self)
    elif (self.opcode == 'jz'):
      main_memory.jz(self)
    elif (self.opcode == 'jg'):
      main_memory.jg(self)
    elif (self.opcode == 'jl'):
      main_memory.jl(self)
    elif (self.opcode == 'ret'):
      main_memory.ret(self)
    elif (self.opcode == 'ret_popped'):
      main_memory.ret_popped(self)
    elif (self.opcode == 'show_status'):
      main_memory.show_status(self)
    elif (self.opcode == 'verify'):
      main_memory.verify(self)
    elif (self.opcode == 'rtrue'):
      main_memory.rtrue(self)
    elif (self.opcode == 'rfalse'):
      main_memory.rfalse(self)
    elif (self.opcode == 'quit'):
      main_memory.quit(self)
    elif (self.opcode == 'load'):
      main_memory.load(self)
    elif (self.opcode == 'loadw'):
      main_memory.loadw(self)
    elif (self.opcode == 'loadb'):
      main_memory.loadb(self)
    elif (self.opcode == 'storew'):
      main_memory.storew(self)
    elif (self.opcode == 'storeb'):
      main_memory.storeb(self)
    elif (self.opcode == 'store'):
      main_memory.store(self)
    elif (self.opcode == 'get_next_prop'):
      main_memory.get_next_prop(self)
    elif (self.opcode == 'get_prop_addr'):
      main_memory.get_prop_addr(self)
    elif (self.opcode == 'get_prop_len'):
      main_memory.get_prop_len(self)
    elif (self.opcode == 'put_prop'):
      main_memory.put_prop(self)
    elif (self.opcode == 'jump'):
      main_memory.jump(self)
    elif (self.opcode == 'insert_obj'):
      main_memory.insert_obj(self)
    elif (self.opcode == 'remove_obj'):
      main_memory.remove_obj(self)
    elif (self.opcode == 'push'):
      main_memory.push(self)
    elif (self.opcode == 'pull'):
      main_memory.pull(self)
    elif (self.opcode == 'print'):
      main_memory.print_1(self)
    elif (self.opcode == 'print_ret'):
      main_memory.print_ret(self)
    elif (self.opcode == 'print_num'):
      main_memory.print_num(self)
    elif (self.opcode == 'print_char'):
      main_memory.print_char(self)
    elif (self.opcode == 'print_obj'):
      main_memory.print_obj(self)
    elif (self.opcode == 'print_addr'):
      main_memory.print_addr(self)
    elif (self.opcode == 'print_paddr'):
      main_memory.print_paddr(self)
    elif (self.opcode == 'set_attr'):
      main_memory.set_attr(self)
    elif (self.opcode == 'clear_attr'):
      main_memory.clear_attr(self)
    elif (self.opcode == 'jin'):
      main_memory.jin(self)
    elif (self.opcode == 'read'):
      main_memory.read(self)
    elif (self.opcode == 'get_prop'):
      main_memory.get_prop(self)
    elif (self.opcode == 'new_line'):
      main_memory.new_line(self)
    elif (self.opcode == 'restart'):
      main_memory.restart(self)
    elif (self.opcode == 'test_attr'):
      main_memory.test_attr(self)
    elif (self.opcode == 'test'):
      main_memory.test(self)
    elif (self.opcode == 'sub'):
      main_memory.sub(self)
    elif (self.opcode == 'div'):
      main_memory.div(self)
    elif (self.opcode == 'mod'):
      main_memory.mod(self)
    elif (self.opcode == 'random'):
      main_memory.random(self)
    else:
      raise Exception("Not implemented")

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
    self.current_alphabet = Alphabet.A0
    self.current_abbrev = None
    self.ten_bit_zscii_bytes_needed = None
    self.ten_bit_zscii_bytes = None
    self.word_separators = []
    self.dictionary_mapping = dict()
    self.timedGame = False
    self.textBuffer = ""
    self.getFirstAddress()
    self.setFlags()
    self.setWidthHeight(80, 20)
    self.setInterpreterNumberVersion(6, ord('I'))
    self.stream = ""
    self.printMode = True # Eventually an enum
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
      flags = setNthBit(flags, 4, True) # No status line
      flags = setNthBit(flags, 5, False) # No split screen
      flags = setNthBit(flags, 6, True) # Fixed width by default
      self.mem[0x01] = flags
      printLog("flags set: " + bin(self.mem[0x01]))
    else:
      pass # TODO, version 4+

    # Flags 2 - specific availability/current status
    # Bit 0: Set when transcripting is enabled (don't care during initialisation)
    # Bit 1: Game requests fixed-pitch printing
    # Bit 2: Interpreter sets to request screen redraw (don't care during initialisation)
    # Bit 3: Game wants to use pictures
    # Bit 4: Game wants to use UNDO opcodes
    # Bit 5: Game wants to use a mouse
    # Bit 6: Game wants to use colours
    # Bit 8: Game wants to use sounds
    # Bit 6: Game wants to use menus
    flags = self.mem[0x10]
    # TODO: When we reach v5+ we need to start doing something with this

  # read dictionary
  def readDictionary(self):
    dict_addr = self.dictionary_table_start
    byte = 0
    # How many separators?
    num_separators = self.getSmallNumber(dict_addr + byte)
    byte += 1
    for i in range(num_separators):
      self.word_separators.append(self.getSmallNumber(dict_addr + byte))
      byte += 1

    # How big is a dictionary entry?
    entry_size = self.getSmallNumber(dict_addr + byte)
    byte += 1

    # How many entries?
    num_entries = self.getWord(dict_addr + byte)
    byte += 2

    # Load 'em up!
    for i in range(num_entries):
      word_1, word_2 = self.getWord(dict_addr + byte), self.getWord(dict_addr + byte + 2)
      self.dictionary_mapping[(word_1 << 16) + word_2] = dict_addr + byte
      byte += entry_size

  # Input shenaningans
  def writeToTextBuffer(self, string, address):
    string = string.lower()
    string = string.strip()
    num_bytes = len(string)
    text_offset = 1
    if (self.version > 4):
      self.mem[address+1] = num_bytes
      text_offset = 2
    for i in range(num_bytes):
      self.mem[address+text_offset+i] = ord(string[i])
    # If version < 5, add a zero terminator
    if (self.version < 5):
      self.mem[address+text_offset+num_bytes] = 0

  def tokeniseString(self, string):
    strip = string.lower()
    string = string.strip()
    for idx in self.word_separators:
      sep = self.getZsciiCharacter(idx)
      string = string.replace(sep, ' ' + sep + ' ') # Force separators to be separate tokens
    tokens = list(filter(None, string.split(' '))) # Split on space, remove empties
    return tokens

  def parseString(self, string, address, text_buffer_address):
    # Lexical parsing! Oh my
    tokens = self.tokeniseString(string)
    # Second byte of addr should store total number of tokens parsed
    self.mem[address+1] = len(tokens)
    # Look up each token in the dictionary
    for idx, token in enumerate(tokens):
      eff_idx = idx*4
      byte_encoding = self.tokenToDictionaryLookup(token)
      key = ((byte_encoding[0] << 24) + (byte_encoding[1] << 16) + (byte_encoding[2] << 8) + (byte_encoding[3]))
      # Give addr of word in dict or 0 if not found (2 bytes)
      if key in self.dictionary_mapping:
        byte_1, byte_2 = self.breakWord(self.dictionary_mapping[key])
        self.mem[address+2+eff_idx] = byte_1
        self.mem[address+2+eff_idx+1] = byte_2
      else:
        self.mem[address+2+eff_idx] = 0
        self.mem[address+2+eff_idx+1] = 0
      # Give length of word in third byte
      self.mem[address+2+eff_idx+2] = len(token)
      # Give position of word in fourth byte
      string_idx = string.find(token)+1
      self.mem[address+2+eff_idx+3] = string_idx

  def tokenToDictionaryLookup(self, string):
    # Truncate to 6 (v3) or 9 (v4+) characters
    trunc_length = 6
    if (self.version > 3):
      trunc_length = 9
    string = string[0:trunc_length]
    # Encode it
    return self.stringToEncodedBytes(string, trunc_length)

  def stringToEncodedBytes(self, string, min_length=0):
    zbytes = []
    cur_zbyte = 0
    characters_left = 3
    # Sanitise...
    string = string.lower()
    # Add `a before the non-alpha characters (A2 switch, 10 character ZSCII)
    # else commands like $ve won't work
    string = re.sub(r'([^0-9a-z])', r'`a\1', string)
    bit_string = ''
    for character in string:
      if character in input_map:
        bit_string += format(self.getFiveBitEncoding(character), '05b')
      else:
        bit_string += format(ord(character), '010b')
    byte_list = [bit_string[i:i+5] for i in range(0, len(bit_string), 5)]

    # Ensure we generate two words by padding if necessary...
    # But not too much padding!
    while len(byte_list) < 4 or (len(byte_list) % 3 != 0):
      byte_list.append('00101') # 5

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

  # print
  def getEncodedAbbreviationString(self, idx):
    abbrev_addr = self.abbreviation_table_start + (idx*2)
    abbrev_addr = self.getWord(abbrev_addr)*2
    return self.getEncodedTextLiteral(abbrev_addr)[0]

  def print_string(self, string):
    current_alphabet = Alphabet.A0
    for characters in string:
      first_char = (characters & 0b0111110000000000) >> 10
      second_char = (characters& 0b0000001111100000) >> 5
      third_char = (characters & 0b0000000000011111)
      # TODO: V1
      current_alphabet = self.printZCharacterV3(first_char, current_alphabet)
      current_alphabet = self.printZCharacterV3(second_char, current_alphabet)
      current_alphabet = self.printZCharacterV3(third_char, current_alphabet)

  def printZCharacterV1(self, key):
    # Handle shift characters
#    print(key, end=' ')
    self.printToStream(key, '')
    if key == 2:
      if (self.current_alphabet == Alphabet.A0):
        self.current_alphabet = Alphabet.A1
      if (self.current_alphabet == Alphabet.A1):
        self.current_alphabet = Alphabet.A2
      if (self.current_alphabet == Alphabet.A2):
        self.current_alphabet = Alphabet.A0
      return
    if key == 3:
      if (self.current_alphabet == Alphabet.A0):
        self.current_alphabet = Alphabet.A2
      if (self.current_alphabet == Alphabet.A2):
        self.current_alphabet = Alphabet.A1
      if (self.current_alphabet == Alphabet.A1):
        self.current_alphabet = Alphabet.A0
      return
    # TODO: Handle shiftlock
    if key == 4:
      self.current_alphabet = Alphabet.A1
      return
    if key == 5:
      self.current_alphabet = Alphabet.A2
      return

    return
    # Handle printing
    if key == 0:
      print(" ", end='')
    if (self.current_alphabet == Alphabet.A0):
      if key in a0:
        print(a0[key], end='')
    if (self.current_alphabet == Alphabet.A1):
      if key in a1:
        print(a1[key], end='')
    if (self.current_alphabet == Alphabet.A2):
      if key in a2:
        print(a2[key], end='')

    # TODO: Handle shiftlock
    self.current_alphabet = Alphabet.A0

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
      self.print_string(self.getEncodedAbbreviationString(abbrev_idx))
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
    table = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'abcdefghijklmnopqrstuvwxyz{|}~"
    target_character = table[idx-0x21] # Offset by 0x21
    return target_character

  def print_zscii_character(self, character):
    target_character = self.getZsciiCharacter(character)
    self.printToStream(target_character, '')
#    print(target_character, end='')

  # opcodes
  def restart(self, instruction):
    printLog("restart")
    # Wipe it all.
    self.__init__(self.raw)
    self.readDictionary()

  def read(self, instruction):
    printLog("read")
    # Flush the buffer - seems like a good time for it?
#    self.flushStream()
    self.drawWindows()

    decoded_opers  = self.decodeOperands(instruction)
    text_buffer_address = decoded_opers[0]
    parse_buffer_address = decoded_opers[1]

    string = input()

    # # I'm a coder, console input is easy
    # string = ""
    # while True:
    #   char = readchar.readchar()
    #   if (ord(char) > 128):
    #     continue
    #   string += char.decode("utf-8")
    #   if char.decode("utf-8") == '\r':
    #     break
    #   else:
    #     print(string, end='')

    self.printToStream(string, '\n')
    self.writeToTextBuffer(string, text_buffer_address)
    self.parseString(string, parse_buffer_address, text_buffer_address)
    self.pc += instruction.instr_length

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
    decoded_opers  = self.decodeOperands(instruction)
    self.ret_helper(instruction, decoded_opers[0])

  def ret_popped(self, instruction):
    # Return bottom of stack
    self.ret_helper(instruction, self.getVariable(0))

  def rtrue(self, instruction):
    # Return true
    self.ret_helper(instruction, 1)

  def rfalse(self, instruction):
    # Return false
    self.ret_helper(instruction, 0)

  def ret_helper(self, instruction, ret_val):
    # Pop the current routine so setVariable is targeting the right set of locals
    current_routine = self.routine_callstack.pop()
    # Return ret_val into store variable and...
    printLog("Returning", ret_val, "into", current_routine.store_variable)
    self.setVariable(current_routine.store_variable, ret_val)
    # ... kick execution home
    self.pc = current_routine.return_address

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
      prop_addr = prop_addr + 1 # Offset for size byte
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
    prop_bytes = 0
    if decoded_opers[0] != 0: # get_prop_len 0 must return zero...
      prop_addr = decoded_opers[0] - 1
      printLog("Prop addr: " + hex(prop_addr))
      if prop_addr != 0:
        prop_bytes = self.getPropertySize(prop_addr)
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
    if (self.getSmallNumber(base_addr + (idx)) != value):
      raise Exception("Error storing word")

    self.pc += instruction.instr_length # Move past the instr

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
    val = decoded_opers[0] // decoded_opers[1]
    val = getHexValue(val)
    self.setVariable(instruction.store_variable, val)

    if (self.peekVariable(instruction.store_variable) != val):
      raise Exception("Error loading value")

    self.pc += instruction.instr_length

  def mod(self, instruction):
    printLog("mod")
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    val = decoded_opers[0] % decoded_opers[1]
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
    new_routine = RoutineCall()
    # Grab the return addr
    new_routine.return_address = self.pc + instruction.instr_length
    new_routine.store_variable = instruction.store_variable
    new_routine.stack_state = list(self.stack)
    routine_address = self.unpackAddress(calling_addr, True)
    printLog("Routine address: " + hex(routine_address))
    # How many local variables?
    local_var_count = self.getSmallNumber(routine_address)
    printLog("Total local variables: " + str(local_var_count))
    # For older versions, we have initial values for these variables
    # Newer versions use zero instead
    for i in range(local_var_count):
      if (self.version < 5):
        variable_value = self.getWord(routine_address + 1 + (2*i))
        new_routine.local_variables.append(variable_value)
      else:
        new_routine.local_variables.append(0)

    printLog("Locals before operand set", new_routine.local_variables)
    # Now set the locals as per the operands
    decoded_opers.pop(0)
    for index, operand in enumerate(decoded_opers):
      new_routine.local_variables[index] = operand

    printLog("Locals after operand set", new_routine.local_variables)

    printLog("Called with these values:")
    printLog(new_routine.local_variables)

    # Now set the pc to the instruction after the header
    new_pc = routine_address + 1
    if (self.version < 5):
      new_pc += 2 * local_var_count
    printLog("Next instruction at: " + hex(new_pc))
    self.pc = new_pc

    # Finally, add the routine to the stack
    self.routine_callstack.append(new_routine)
    printLog(self.routine_callstack)

    new_routine.print_debug()

  def quit(self, instruction):
    printLog("quit")
    quit()

  def decodeOperands(self, instruction):
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
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

  # Most numbers are stored as two adjacent bytes
  def getWord(self, addr):
    return (self.mem[addr] << 8) + self.mem[addr+1]

  # Some are small!
  def getSmallNumber(self, addr):
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
    operand_types = []
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      opcode = self.getExtendedOpcode(self.mem[next_byte])
      form = Forms.Extended
      next_byte += 1

    # Figure out instruction form
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      form = Forms.Extended
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
      opcode = self.getOpcode(first_opcode_byte, opcount)

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
          operands.append(self.getSmallNumber(next_byte))
          next_byte += 1
        if (operand_type == OperandType.Variable):
          operands.append(self.getSmallNumber(next_byte))
          next_byte += 1

    # If this opcode needs a store variable, get it...
    if (needsStoreVariable(opcode, self.version)):
      store_variable = self.getSmallNumber(next_byte)
      next_byte += 1

    # If this opcode needs a branch offset, get that...
    branch_on_true = None
    if (needsBranchOffset(opcode, self.version)):
      branch_byte = self.getSmallNumber(next_byte)
      branch_on_true = (branch_byte & 0b10000000) == 0b10000000
      next_byte += 1
      if ((branch_byte & 0b01000000) == 0b01000000):
        branch_offset = branch_byte & 0b00111111
      else:
        branch_byte_two = self.getSmallNumber(next_byte)
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
    obj_addr = self.getObjectAddress(obj_number)
    attrib_bit = 0x80000000 >> (attrib_number)
    first_two_attribute_bytes = self.getWord(obj_addr)
    last_two_attribute_bytes = self.getWord(obj_addr+2)
    full_flags = (first_two_attribute_bytes << 16) + last_two_attribute_bytes
    return (attrib_bit & full_flags) == attrib_bit

  def setAttribute(self, obj_number, attrib_number, value):
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
    return self.getSmallNumber(parent_addr)

  def getObjectSibling(self, obj_number):
    sibling_addr = self.getObjectSiblingAddress(obj_number)
    if (self.version > 3):
      return self.getWord(sibling_addr)
    return self.getSmallNumber(sibling_addr)

  def getObjectChild(self, obj_number):
    child_addr = self.getObjectChildAddress(obj_number)
    if (self.version > 3):
      return self.getWord(child_addr)
    return self.getSmallNumber(child_addr)

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
    prop_bytes = self.getPropertySize(prop_addr)
    prop_start_addr = prop_addr + 1
    if (prop_bytes == 2):
      printLog("getProperty: return word: prop num:", prop_number, "val:", hex(self.getWord(prop_start_addr)))
      return self.getWord(prop_start_addr)
    elif (prop_bytes == 1):
      printLog("getProperty: return byte: prop num:", prop_number, "val:", hex(self.getWord(prop_start_addr)))
      return self.getSmallNumber(prop_start_addr)
    else:
      raise Exception("Illegal property access")

  def getPropertyTableAddress(self, obj_number):
    obj_addr = self.getObjectAddress(obj_number)
    printLog("obj_addr", hex(obj_addr))
    prop_table_offset = 7
    if (self.version > 3):
      prop_table_offset = 9
    prop_table_address = self.getWord(obj_addr + prop_table_offset)
    return prop_table_address

  def getPropertyListAddress(self, obj_number):
    prop_table_address = self.getPropertyTableAddress(obj_number)
    printLog("Prop addr: prop table address:", hex(prop_table_address))
    short_name_length = self.getSmallNumber(prop_table_address)
    prop_list_start = prop_table_address + (short_name_length*2) + 1
    return prop_list_start

  def getNextProperty(self, obj_number, prop_number):
    if (prop_number != 0):
      cur_prop_addr = self.getPropertyAddress(obj_number, prop_number)
      next_prop_addr = cur_prop_addr + 1 + self.getPropertySize(cur_prop_addr)
      next_prop_number = 0b00011111 & self.getSmallNumber(next_prop_addr)
      return next_prop_number
    else:
      first_prop_addr = self.getPropertyListAddress(obj_number)
      first_prop_number = 0b00011111 & self.getSmallNumber(first_prop_addr)
      return first_prop_number

  def getPropertyAddress(self, obj_number, prop_number):
    if (self.version < 4):
      return self.getPropertyAddressV1(obj_number, prop_number)
    else:
      return self.getPropertyAddressV4(obj_number, prop_number)

  def getPropertyAddressV1(self, obj_number, prop_number):
    prop_list_address = self.getPropertyListAddress(obj_number)
    printLog("Prop addr: prop list addr:", hex(prop_list_address))
    size_byte_addr = prop_list_address
    size_byte = self.getSmallNumber(size_byte_addr)
    printLog("Prop addr: size_byte:", size_byte)
    while (size_byte != 0):
      prop_bytes = self.getPropertySize(size_byte_addr)
      cur_prop_number = 0b00011111 & size_byte
      printLog("Prop addr: examining prop num:", cur_prop_number)
      if (prop_number == cur_prop_number):
        printLog("Prop addr: found prop at:", hex(size_byte_addr))
        return size_byte_addr
      printLog("Prop addr: wasn't it, skipping bytes:", prop_bytes)
      # Get the next property
      size_byte_addr += (prop_bytes + 1) # move past size byte + prop bytes
      size_byte = self.getSmallNumber(size_byte_addr)
      printLog("Prop addr: next check at", hex(size_byte_addr))
      printLog("Prop addr: size_byte:", size_byte)
    printLog("Prop addr: prop not found")
    return 0

  def getPropertySize(self, prop_address):
    size_byte_addr = prop_address
    size_byte = self.getSmallNumber(size_byte_addr)
    prop_bytes = ((size_byte & 0b11100000) >> 5) + 1
    return prop_bytes

  def setProperty(self, obj_number, prop_number, value):
    prop_address = self.getPropertyAddress(obj_number, prop_number)
    prop_bytes = self.getPropertySize(prop_address)
    top_byte, bottom_byte = self.breakWord(value)
    printLog("set prop", obj_number, prop_number, hex(prop_address), top_byte, bottom_byte)
    if (prop_bytes == 2):
      self.mem[prop_address + 1] = top_byte
      self.mem[prop_address + 2] = bottom_byte
    elif (prop_bytes == 1):
      self.mem[prop_address + 1] = bottom_byte
    else:
      raise Exception("Illegal call to SetProperty")


  def getPropertyAddressV4(self, obj_number, prop_number):
    prop_list_address = getPropertyListAddress(obj_number)
    raise Exception("To implement")

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
      elif (opcode_bytes & 0b00000000 == 0b00000000):
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
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x1):
      return "je"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x2):
      return "jl"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x3):
      return "jg"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x4):
      return "dec_chk"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x5):
      return "inc_chk"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x6):
      return "jin"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x7):
      return "test"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x8):
      return "or"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x9):
      return "and"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xa):
      return "test_attr"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xb):
      return "set_attr"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xc):
      return "clear_attr"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xd):
      return "store"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xe):
      return "insert_obj"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0xf):
      return "loadw"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x10):
      return "loadb"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x11):
      return "get_prop"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x12):
      return "get_prop_addr"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x13):
      return "get_next_prop"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x14):
      return "add"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x15):
      return "sub"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x16):
      return "mul"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x17):
      return "div"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 0x18):
      return "mod"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x0):
      return "jz"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x1):
      return "get_sibling"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x2):
      return "get_child"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x3):
      return "get_parent"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x4):
      return "get_prop_len"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x5):
      return "inc"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x6):
      return "dec"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x7):
      return "print_addr"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0x9):
      return "remove_obj"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0xa):
      return "print_obj"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0xb):
      return "ret"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0xc):
      return "jump"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0xd):
      return "print_paddr"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0xe):
      return "load"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x0):
      return "rtrue"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x1):
      return "rfalse"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x2):
      return "print"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x3):
      return "print_ret"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x8):
      return "ret_popped"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0xa):
      return "quit"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0xb):
      return "new_line"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0xc):
      return "show_status"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0xd):
      return "verify"
    if (operand_type == Operand.ZeroOP and byte & 0b00001111 == 0x7):
      return "restart"
    if (operand_type == Operand.VAR and byte == 224):
        return "call" # This is renamed call_vs in >v3, but it's functionally identical
    if (operand_type == Operand.VAR and byte == 230):
      return "print_num"
    if (operand_type == Operand.VAR and byte == 231):
      return "random"
    if (operand_type == Operand.VAR and byte == 225):
      return "storew"
    if (operand_type == Operand.VAR and byte == 226):
      return "storeb"
    if (operand_type == Operand.VAR and byte == 227):
      return "put_prop"
    if (operand_type == Operand.VAR and byte == 229):
      return "print_char"
    if (operand_type == Operand.VAR and byte == 232):
      return "push"
    if (operand_type == Operand.VAR and byte == 233):
      return "pull"
    if (operand_type == Operand.VAR and byte == 228):
      return "read"
    raise Exception("Missing opcode: " + hex(byte))

  def getExtendedOpcode(self, byte):
    printLog("ExtendedOpcode")
    # Do something..!
    raise Exception("Missing extended opcode: " + hex(byte))

  def print_debug(self):
    printLog("-------------")
    printLog("Stack:")
    printLog(self.stack)
    if (len(self.routine_callstack) > 0):
      printLog("Current routine state:")
      printLog(self.routine_callstack[-1].print_debug())
    printLog("Mem at 0x2525:", self.mem[0x2525])

    printLog("-------------")

  def printToStream(self, string, end):
    if self.printMode:
      self.textBuffer += string + end
    else:
      self.stream += string + end

  def flushStream(self):
    toPrint = self.textBuffer
    lines = toPrint.split("\n")
    for i, line in enumerate(lines):
      if i != len(lines) - 1:
        print(textwrap.fill(line, 90))
      else:
        print(textwrap.fill(line, 90), end='')
    self.textBuffer = ""

  def getLowerWindowLines(self):
    columns, rows = os.get_terminal_size()
    # BUG: On terminal resize, the already written text will
    # end up being resized. This approach won't scale.
    toPrint = self.textBuffer
    lines = toPrint.split("\n")
    retLines = []
    for i, line in enumerate(lines):
      retLines.append(textwrap.fill(line, columns - 2))
    return retLines

  def tidyBuffer(self):
    lines = self.getLowerWindowLines()
    columns, rows = os.get_terminal_size()
    if len(lines) > rows:
      lines = lines[len(lines) - rows + 1:]
    self.textBuffer = "\n".join(lines)

  def drawWindows(self):
    # Get current terminal size
    columns, rows = os.get_terminal_size()
    drawString = ""

    # Clear screen
    drawString += '\x1b[2J'

    # Tidy buffer - ie. drop lines that have gone off the top
    self.tidyBuffer()

    # Print the buffer
    lowerLines = self.getLowerWindowLines()

    # Move the cursor back up to the top left of the buffer
    top_row = max(rows - len(lowerLines), 1)
    pos = lambda y, x: '\x1b[%d;%dH' % (y, x)
    drawString += "%s" % (pos(top_row,1))

    for i, line in enumerate(lowerLines):
      if i != len(lowerLines) - 1:
        drawString += line + '\n'
      else:
        drawString += line

    print(drawString, end ='')

    if self.version < 4:
      self.drawStatusLine()

    # TODO: There seems to be an off-by-one error hiding in
    # the draw as the console keeps getting longer over time

  def getCurrentCursorPosition(self):
    # Irritating... This will be platform specific (ANSI vs. Windows...)
    # TODO: Linux...

    # TODO: Understand this code, which was ripped from SO
    hstd = ctypes.windll.kernel32.GetStdHandle(-11)
    csbi = ctypes.create_string_buffer(22)
    res = ctypes.windll.kernel32.GetConsoleScreenBufferInfo(hstd, csbi)
    width, height, curx, cury, wattr, left, top, right, bottom, maxx, maxy = struct.unpack("hhhhHhhhhhh", csbi.raw)
    return cury - top, curx

  def drawStatusLine(self):
    # Get current terminal size
    columns, rows = os.get_terminal_size()

    if os.name != "posix":
      cursorY, cursorX = self.getCurrentCursorPosition()
    else:
      print('\033[s', end='')

    # Room name...
    # Use the rubbish print workaround that we have to fix eventually
    self.stream = ""
    self.printMode = False
    self.print_string(self.getEncodedObjectShortName(self.getGlobalVariableValue(0)))
    roomName = " " + self.stream
    self.printMode = True

    roomNameLength = len(roomName)

    scoreTimeString = ""
    if self.timedGame:
      hour = self.getGlobalVariableValue(1)
      minute = self.getGlobalVariableValue(2)
      scoreTimeString = "Time: {:02d}:{:02d}".format(hour, minute)
    else:
      score = self.getGlobalVariableValue(1)
      turns = self.getGlobalVariableValue(2)
      scoreTimeString = "Score: {0: >3}  Turns: {1: >4}".format(score, turns)

    margin = 8
    printScoreStringAt = columns - margin - len(scoreTimeString)
    spaceBetweenRoomNameAndScoreString = printScoreStringAt - roomNameLength

    # Move to top...
    pos = lambda y, x: '\x1b[%d;%dH' % (y, x)
    print("%s" % (pos(1,1)), end='')
    print(colorama.Fore.BLACK + colorama.Back.WHITE + roomName, end='')
    print(" " * spaceBetweenRoomNameAndScoreString, end='')
    print(scoreTimeString, end='')
    print(" " * margin, end='')
    print(colorama.Style.RESET_ALL, end='')
    # And reset the cursor.
    if os.name != "posix":
      print("%s" % (pos(cursorY+1, cursorX+1)), end='')
    else:
      print('\033[u', end='')

def needsStoreVariable(opcode, version):
  return opcode in NeedStoreVariable

def needsBranchOffset(opcode, version):
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
  main_memory = StoryLoader.LoadZFile(sys.argv[1])
  main_memory.readDictionary()

  colorama.init()

  # If this is Z-Machine 6, we don't have a 'first instruction',
  # but a 'main routine' instead. So create a call instruction
  # and run it against the address specified in the story file
  # before jumping into the main loop
  if (main_memory.version == 6):
    pass # TODO
  while True:
    loop(main_memory)

def loop(main_memory):
  main_memory.print_debug()
  instr = main_memory.getInstruction(main_memory.pc)
  instr.print_debug()
  instr.run(main_memory)

if __name__ == "__main__":
  main()
