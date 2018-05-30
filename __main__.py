import sys
from enum import Enum

# Enums
Form = Enum('Form', 'Short Long Variable Extended')
Operand = Enum('Operand', 'ZeroOP OneOP TwoOP VAR')
OperandType = Enum('OperandType', 'Large Small Variable')

# Logging
tracefile = open('trace.txt', 'w')
logfile = open('full_log.txt', 'w')

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
               instr_length):
    self.opcode = opcode
    self.operand_types = operand_types
    self.operands = operands
    self.store_variable = store_variable
    self.branch_on_true = branch_on_true
    self.branch_offset = branch_offset
    self.text_to_print = text_to_print
    self.instr_length = instr_length

  def run(self, main_memory):
    print("Running opcode: " + str(self.opcode), file=tracefile)
    if (self.opcode == 'call'):
      main_memory.call(self.operand_types, self.operands, self.store_variable, self.instr_length)
    elif (self.opcode == 'add'):
      main_memory.add(self)
    elif (self.opcode == 'je'):
      main_memory.je(self)
    elif (self.opcode == 'jz'):
      main_memory.jz(self)
    elif (self.opcode == 'ret'):
      main_memory.ret(self)
    elif (self.opcode == 'loadw'):
      main_memory.loadw(self)
    elif (self.opcode == 'storew'):
      main_memory.storew(self)
    elif (self.opcode == 'store'):
      main_memory.store(self)
    elif (self.opcode == 'put_prop'):
      main_memory.put_prop(self)
    elif (self.opcode == 'jump'):
      main_memory.jump(self)
    elif (self.opcode == 'test_attr'):
      main_memory.test_attr(self)
    elif (self.opcode == 'sub'):
      main_memory.sub(self)
    else:
      raise Exception("Not implemented")

  def print_debug(self):
    print("Printing instr debug", file=logfile)
    print(self.opcode, file=logfile)
    print(self.operand_types, file=logfile)
    print(self.operands, file=logfile)
    for operand in self.operands:
      print(hex(operand), file=logfile)
    print(self.store_variable, file=logfile)
    print(self.branch_offset, file=logfile)
    print(self.text_to_print, file=logfile)

# StoryLoader returns a memory map
class StoryLoader:
  def LoadZFile(filename):
    f = open(filename, "rb")
    memory = f.read()
    return Memory(memory)

class RoutineCall:
  def __init__(self):
    self.local_variables = []
    self.return_address = 0x0000

  def print_debug(self):
    print("Routine call", file=logfile)
    print(self.local_variables, file=logfile)
    for var in self.local_variables:
      print(var, file=logfile)

# Utility
def getSignedEquivalent(num):
  if num > 0x7FFF:
    num = 0x10000 - num
    num = -num
  return num

# Memory - broken up into dynamic/high/static
class Memory:
  def __init__(self, memory_print):
    self.mem = bytearray(memory_print)
    self.dynamic = 0
    self.static = self.mem[0x0e]
    self.high = self.mem[0x04]
    self.version = self.mem[0x00]
    self.routine_offset = self.mem[0x28]
    self.string_offset = self.mem[0x2a]
    self.global_table_start = self.getNumber(0x0c)
    self.object_table_start = self.getNumber(0x0a)
    self.stack = []
    self.routine_callstack = []
    self.getFirstAddress()
    print(self.version, file=logfile)
    print(self.static, file=logfile)
    print(self.high, file=logfile)

  # opcodes
  def ret(self, instruction):
    # Return value in parameter
    decoded_opers  = self.decodeOperands(instruction)
    # Pop the current routine so setVariable is targeting the right set of locals
    current_routine = self.routine_callstack.pop()
    # Return into store variable and...
    self.setVariable(current_routine.store_variable, decoded_opers[0])
    # ... kick execution home
    self.pc = current_routine.return_address

  def je(self, instruction):
    print("je", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    self.pc += instruction.instr_length # Move past the instr regardless
    if decoded_opers[0] == decoded_opers[1] and instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("je:branch_on_true:jumped to " + hex(self.pc), file=logfile)
    elif decoded_opers[0] != decoded_opers[1] and not instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("je:branch_on_false:jumped to " + hex(self.pc), file=logfile)

  def jz(self, instruction):
    print("jz", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    self.pc += instruction.instr_length # Move past the instr regardless
    if decoded_opers[0] == 0 and instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("jz:branch_on_true:jumped to " + hex(self.pc), file=logfile)
    elif decoded_opers[0] != 0 and not instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("jz:branch_on_false:jumped to " + hex(self.pc), file=logfile)

  def test_attr(self, instruction):
    print("test_attr", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    obj_number = decoded_opers[0]
    attrib_number = decoded_opers[1]
    print("obj_number: " + str(obj_number), file=logfile)
    print("attrib_number: " + str(attrib_number), file=logfile)
    print("jump offset: " + hex(instruction.branch_offset), file=logfile)
    print("jump on true: " + str(instruction.branch_on_true), file=logfile)
    attrib_set = self.isAttributeSet(obj_number, attrib_number)
    self.pc += instruction.instr_length # Move past the instr regardless
    if attrib_set and instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("test_attr:branch_on_true:jumped to " + hex(self.pc), file=logfile)
    elif not attrib_set and not instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("test_attr:branch_on_false:jumped to " + hex(self.pc), file=logfile)

  def jump(self, instruction):
    print("jump", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    print(decoded_opers[0], file=logfile)
    print(getSignedEquivalent(decoded_opers[0]), file=logfile)
    self.pc += instruction.instr_length + getSignedEquivalent(decoded_opers[0]) - 2

  def put_prop(self, instruction):
    print("put_prop", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    print(decoded_opers, file=logfile)
    print("Obj number: " + str(decoded_opers[0]), file=logfile)
    print("Prop number: " + str(decoded_opers[1]), file=logfile)
    print("Value: " + hex(decoded_opers[2]), file=logfile)
    self.setProperty(decoded_opers[0], decoded_opers[1], decoded_opers[2])
    self.pc += instruction.instr_length # Move past the instr

  def store(self, instruction):
    print("store", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    target_var = decoded_opers[0]
    value = decoded_opers[1]
    print("target_var: " + hex(target_var), file=logfile)
    print("value: " + str(value), file=logfile)
    self.setVariable(target_var, value)
    self.pc += instruction.instr_length # Move past the instr

  def loadw(self, instruction):
    print("loadw", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    print("Base addr: " + hex(base_addr), file=logfile)
    print("Idx: " + hex(idx), file=logfile)
    print("Store target: " + hex(instruction.store_variable), file=logfile)
    self.setVariable(instruction.store_variable, self.mem[base_addr + (2*idx)])
    self.pc += instruction.instr_length # Move past the instr

  def storew(self, instruction):
    print("storew", file=logfile)
    decoded_opers  = self.decodeOperands(instruction)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    value = decoded_opers[2]
    print("Base addr: " + hex(base_addr), file=logfile)
    print("Idx: " + hex(idx), file=logfile)
    print("Value to store: " + hex(value), file=logfile)
    # Split value into bytes
    top_byte = (value & 0xff00) >> 8
    bottom_byte = value & 0x00ff
    self.mem[base_addr + (2*idx)] = top_byte
    self.mem[base_addr + (2*idx) + 1] = bottom_byte
    self.pc += instruction.instr_length # Move past the instr

  def add(self, instruction):
    print("add", file=logfile)
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    print(decoded_opers, file=logfile)
    self.setVariable(instruction.store_variable, decoded_opers[0] + decoded_opers[1])
    self.pc += instruction.instr_length

  def sub(self, instruction):
    print("sub", file=logfile)
    decoded_opers = self.decodeOperands(instruction)
    decoded_opers = [getSignedEquivalent(x) for x in decoded_opers]
    print(decoded_opers, file=logfile)
    self.setVariable(instruction.store_variable, decoded_opers[0] - decoded_opers[1])
    self.pc += instruction.instr_length

  def call(self, operand_types, operands, store_variable, instr_length):
    print("Routine call during run", file=logfile)
    # Create a new routine object
    new_routine = RoutineCall()
    # Grab the return addr
    new_routine.return_address = self.pc + instr_length
    new_routine.store_variable = store_variable
    # First operand is calling address
    routine_address = self.unpackAddress(operands[0], True)
    print("Routine address: " + hex(routine_address), file=logfile)
    # How many local variables?
    local_var_count = self.getSmallNumber(routine_address)
    print("Total local variables: " + str(local_var_count), file=logfile)
    # For older versions, we have initial values for these variables
    # Newer versions use zero instead
    for i in range(local_var_count):
      if (self.version < 5):
        variable_value = self.getNumber(routine_address + 1 + (2*i))
        new_routine.local_variables.append(variable_value)
      else:
        new_routine.local_variables.append(0)

    # Now set the locals as per the operands
    oper_zip = list(zip(operand_types, operands))
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])

    decoded_opers.pop(0)
    for index, operand in enumerate(decoded_opers):
      new_routine.local_variables[index] = operand

    print("Called with these values:", file=logfile)
    print(new_routine.local_variables, file=logfile)

    # Now set the pc to the instruction after the header
    new_pc = routine_address + 1
    if (self.version < 5):
      new_pc += 2 * local_var_count
    print("Next instruction at: " + hex(new_pc), file=logfile)
    self.pc = new_pc

    # Finally, add the routine to the stack
    self.routine_callstack.append(new_routine)
    print(self.routine_callstack, file=logfile)

    new_routine.print_debug()

  def decodeOperands(self, instruction):
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers, file=logfile)
    return decoded_opers

  def getVariable(self, variable_number):
    if (variable_number == 0x00):
      return self.popStack()
    if (variable_number > 0x00 and variable_number < 0x10):
      return self.getLocalVariable(variable_number - 0x01)
    else:
      return self.getGlobalVariableValue(variable_number - 0x10)

  def setVariable(self, variable_number, value):
    if (variable_number == 0x00):
      return self.pushStack(value)
    if (variable_number > 0x00 and variable_number < 0x10):
      return self.setLocalVariable(variable_number - 0x01, value)
    else:
      return self.setGlobalVariable(variable_number - 0x10, value)

  def pushStack(self, value):
    self.stack.append(value)

  def popStack(self):
    return self.stack.pop()

  def getLocalVariable(self, variable_number):
    top_routine = self.routine_callstack[-1]
    return top_routine.local_variables[variable_number]

  def setLocalVariable(self, variable_number, value):
    top_routine = self.routine_callstack[-1]
    top_routine.local_variables[variable_number] = value

  def getGlobalVariableAddr(self, variable_number):
    return self.global_table_start + (variable_number * 2)

  def getGlobalVariableValue(self, variable_number):
    return self.getNumber(self.getGlobalVariableAddr(variable_number))

  def setGlobalVariable(self, variable_number, value):
    print("Setting global variable", file=logfile)
    # TODO: If negative, convert to 2's Complement
    # Split value into two bytes
    top_byte = (value & 0xff00) >> 8
    bottom_byte = value & 0x00ff
    top_addr = self.global_table_start + (variable_number * 2)
    self.mem[top_addr] = top_byte
    self.mem[top_addr + 1] = bottom_byte
    print("Top byte:", file=logfile)
    print(hex(self.mem[top_addr]), file=logfile)
    print("Bottom byte:", file=logfile)
    print(hex(self.mem[top_addr+1]), file=logfile)

  # First address depends on version
  def getFirstAddress(self):
    print("getFirstAddress", file=logfile)
    if (self.version != 6):
      self.pc = self.getNumber(0x06)
    else:
      self.pc = self.unpackAddress(self.getNumber(0x06), True)
    print(self.pc, file=logfile)

  # Most numbers are stored as two adjacent bytes
  def getNumber(self, addr):
    return (self.mem[addr] << 8) + self.mem[addr+1]

  # Some are small!
  def getSmallNumber(self, addr):
    return self.mem[addr]

  # Read an instruction (probably at PC)
  # Bit complicated due to versioning...
  def getInstruction(self, addr):
    print("getInstruction at " + hex(addr), file=logfile)
    next_byte = addr
    # First, determine the opcode
    first_opcode_byte = self.mem[addr]
    print("Opcode:" + str(first_opcode_byte) + "(" + hex(first_opcode_byte) + ")", file=logfile)
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

    print("Got form: " + form.name, file=logfile)

    # Figure out the operand count and type(s)
    opcount = self.getOperandCount(form, first_opcode_byte)
    if (not opcode):
      opcode = self.getOpcode(first_opcode_byte, opcount)

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
        operands.append(self.getNumber(next_byte))
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
      if (branch_byte & 0b01000000 == 0b01000000):
        branch_offset = branch_byte & 0b00111111
      else:
        branch_byte_two = self.getSmallNumber(next_byte)
        branch_offset = ((branch_bbyte & 0b00011111) << 5) + branch_byte_two
        next_byte += 1

    instr_length = next_byte - addr

    return Instruction(opcode,
                       operand_types,
                       operands,
                       store_variable,
                       branch_on_true,
                       branch_offset,
                       text_to_print,
                       instr_length)

  def getPropertyDefault(self, prop_number):
    # Prop_number >= 0 < 32 for versions 1-3, < 64 for version 4
    start_addr = self.object_table_start
    prop_addr = self.object_table_start + (prop_number * 2)
    prop_default = getNumber(prop_addr)
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
    obj_address = obj_tree_start_address + (obj_number * self.getObjSize())
    return obj_address

  def isAttributeSet(self, obj_number, attrib_number):
    obj_addr = self.getObjectAddress(obj_number)
    attrib_bit = 1 << (attrib_number % 16)
    first_two_attribute_bytes = self.getNumber(obj_addr)
    last_two_attribute_bytes = self.getNumber(obj_addr+2)
    if (attrib_number < 16):
      return attrib_bit & first_two_attribute_bytes == attrib_bit
    else: # attrib_number >=16 && < 32
      return attrib_bit & last_two_attribute_bytes == attrib_bit

  def getPropertyTableAddress(self, obj_number):
    obj_addr = self.getObjectAddress(obj_number)
    prop_table_offset = 7
    if (self.version > 3):
      prop_table_offset = 9
    prop_table_address = self.getNumber(prop_table_offset)
    return prop_table_address

  def getPropertyListAddress(self, obj_number):
    prop_table_address = self.getPropertyTableAddress(obj_number)
    short_name_length = self.getSmallNumber(prop_table_address)
    prop_list_start = prop_table_address + short_name_length + 1
    return prop_list_start

  def getPropertyAddress(self, obj_number, prop_number):
    if (self.version < 4):
      return self.getPropertyAddressV1(obj_number, prop_number)
    else:
      return self.getPropertyAddressV4(obj_number, prop_number)

  def getPropertyAddressV1(self, obj_number, prop_number):
    prop_list_address = self.getPropertyListAddress(obj_number)
    size_byte_addr = prop_list_address
    size_byte = self.getSmallNumber(size_byte_addr)
    while (size_byte != 0):
      cur_prop_number = 0b00011111 & size_byte
      if (prop_number == cur_prop_number):
        return size_byte_addr
      # Get the next property
      prop_bytes = ((size_byte - cur_prop_number) / 32) + 1
      size_byte_addr += prop_bytes
      size_byte = self.getSmallNumber(size_byte_addr)
    return 0

  def setProperty(self, obj_number, prop_number, value):
    prop_address = self.getPropertyAddress(obj_number, prop_number)
    size_byte_addr = prop_address
    size_byte = self.getSmallNumber(size_byte_addr)
    cur_prop_number = 0b00011111 & size_byte
    prop_bytes = ((size_byte - cur_prop_number) / 32) + 1
    top_byte = (value & 0xff00) >> 8
    bottom_byte = value & 0x00ff
    if (prop_bytes == 2):
      self.mem[prop_address + 1] = top_byte
      self.mem[prop_address + 2] = bottom_byte
    elif (prop_bytes == 1):
      self.mem[prop_address + 1] = bottom_byte

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
    print("getOperandType: " + bin(opcode_bytes), file=logfile)
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
    print("getOpcode", file=logfile)
    print("last five bits: " + hex(byte & 0b00011111), file=logfile)
    print("last four bits: " + hex(byte & 0b00011111), file=logfile)
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 1):
      return "je"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 10):
      return "test_attr"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 13):
      return "store"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 15):
      return "loadw"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 20):
      return "add"
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 21):
      return "sub"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 12):
      return "jump"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 0):
      return "jz"
    if (operand_type == Operand.OneOP and byte & 0b00001111 == 11):
      return "ret"
    if (operand_type == Operand.VAR and byte == 224):
      if (self.version > 3):
        return "call_vs"
      else:
        return "call"
    if (operand_type == Operand.VAR and byte == 225):
      return "storew"
    if (operand_type == Operand.VAR and byte == 227):
      return "put_prop"
    pass

  def getExtendedOpcode(self, byte):
    print("ExtendedOpcode", file=logfile)
    pass

  def print_debug(self):
    print("-------------", file=logfile)
    print("Stack:", file=logfile)
    print(self.stack, file=logfile)
    if (len(self.routine_callstack) > 0):
      print("Current routine state:", file=logfile)
      print(self.routine_callstack[-1].print_debug(), file=logfile)
    print("-------------", file=logfile)

def needsStoreVariable(opcode, version):
  if (opcode == "call" and version < 4):
    return True
  if (opcode == "add"):
    return True
  if (opcode == "sub"):
    return True
  if (opcode == "loadw"):
    return True
  return False

def needsBranchOffset(opcode, version):
  if (opcode == "je"):
    return True
  if (opcode == "jz"):
    return True
  if (opcode == "test_attr"):
    return True
  return False

def getOperandTypeFromBytes(byte):
  if (byte == 0):
    return OperandType.Large
  elif (byte == 1):
    return OperandType.Small
  else: # (byte == 2)
    return OperandType.Variable

def main():
  main_memory = StoryLoader.LoadZFile(sys.argv[1])

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
