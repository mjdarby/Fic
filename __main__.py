import sys
from enum import Enum

# Enums
Form = Enum('Form', 'Short Long Variable Extended')
Operand = Enum('Operand', 'ZeroOP OneOP TwoOP VAR')
OperandType = Enum('OperandType', 'Large Small Variable')
# Main

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
    print("Running opcode: " + str(self.opcode))
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
    elif (self.opcode == 'jump'):
      main_memory.jump(self)
    elif (self.opcode == 'sub'):
      main_memory.sub(self)
    else:
      raise Exception("Not implemented")

  def print_debug(self):
    print("Printing instr debug")
    print(self.opcode)
    print(self.operand_types)
    print(self.operands)
    for operand in self.operands:
      print(hex(operand))
    print(self.store_variable)
    print(self.branch_offset)
    print(self.text_to_print)


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
    print("Routine call")
    print(self.local_variables)
    for var in self.local_variables:
      print(var)

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
    self.stack = []
    self.routine_callstack = []
    self.getFirstAddress()
    print(self.version)
    print(self.static)
    print(self.high)

  # opcodes
  def ret(self, instruction):
    # Return value in parameter
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers)
    # Pop the current routine so setVariable is targeting the right set of locals
    current_routine = self.routine_callstack.pop()
    # Return into store variable and...
    self.setVariable(current_routine.store_variable, decoded_opers[0])
    # ... kick execution home
    self.pc = current_routine.return_address

  def je(self, instruction):
    print("je")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers)
    self.pc += instruction.instr_length # Move past the instr regardless
    if decoded_opers[0] == decoded_opers[1] and instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("je:branch_on_true:jumped to " + hex(self.pc))
    elif decoded_opers[0] != decoded_opers[1] and not instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("je:branch_on_false:jumped to " + hex(self.pc))

  def jz(self, instruction):
    print("jz")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers)
    self.pc += instruction.instr_length # Move past the instr regardless
    if decoded_opers[0] == 0 and instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("jz:branch_on_true:jumped to " + hex(self.pc))
    elif decoded_opers[0] != 0 and not instruction.branch_on_true:
      self.pc += instruction.branch_offset - 2
      print("jz:branch_on_false:jumped to " + hex(self.pc))

  def jump(self, instruction):
    print("jump")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers[0])
    print(getSignedEquivalent(decoded_opers[0]))
    self.pc += instruction.instr_length + getSignedEquivalent(decoded_opers[0]) - 2

  def loadw(self, instruction):
    print("loadw")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    print("Base addr: " + hex(base_addr))
    print("Idx: " + hex(idx))
    print("Store target: " + hex(instruction.store_variable))
    self.setVariable(instruction.store_variable, self.mem[base_addr + (2*idx)])
    self.pc += instruction.instr_length # Move past the instr

  def storew(self, instruction):
    print("storew")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    print(decoded_opers)
    base_addr = decoded_opers[0]
    idx = decoded_opers[1]
    value = decoded_opers[2]
    print("Base addr: " + hex(base_addr))
    print("Idx: " + hex(idx))
    print("Value to store: " + hex(value))
    # Split value into bytes
    top_byte = (value & 0xff00) >> 8
    bottom_byte = value & 0x00ff
    self.mem[base_addr + (2*idx)] = top_byte
    self.mem[base_addr + (2*idx) + 1] = bottom_byte
    self.pc += instruction.instr_length # Move past the instr

  def add(self, instruction):
      the_sum = 0
      oper_zip = zip(instruction.operand_types, instruction.operands)
      for operand_pair in oper_zip:
        if (operand_pair[0] == OperandType.Variable):
          print("add: variable op val: " + str(self.getVariable(operand_pair[1])))
          the_sum += getSignedEquivalent(self.getVariable(operand_pair[1]))
        else:
          the_sum += getSignedEquivalent(operand_pair[1])
      print("add: sum: " + str(the_sum))
      self.setVariable(instruction.store_variable, the_sum)
      self.pc += instruction.instr_length

  def sub(self, instruction):
    print("sub")
    oper_zip = zip(instruction.operand_types, instruction.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(getSignedEquivalent(self.getVariable(operand_pair[1])))
      else:
        decoded_opers.append(getSignedEquivalent(operand_pair[1]))
    print(decoded_opers)
    self.setVariable(instruction.store_variable, decoded_opers[0] - decoded_opers[1])
    self.pc += instruction.instr_length

  def call(self, operand_types, operands, store_variable, instr_length):
    print("Routine call during run")
    # Create a new routine object
    new_routine = RoutineCall()
    # Grab the return addr
    new_routine.return_address = self.pc + instr_length
    new_routine.store_variable = store_variable
    # First operand is calling address
    routine_address = self.unpackAddress(operands[0], True)
    print("Routine address: " + hex(routine_address))
    # How many local variables?
    local_var_count = self.getSmallNumber(routine_address)
    print("Total local variables: " + str(local_var_count))
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
    oper_zip.pop(0)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    for index, operand in enumerate(decoded_opers):
      new_routine.local_variables[index] = operand

    print("Called with these values:")
    print(new_routine.local_variables)

    # Now set the pc to the instruction after the header
    new_pc = routine_address + 1
    if (self.version < 5):
      new_pc += 2 * local_var_count
    print("Next instruction at: " + hex(new_pc))
    self.pc = new_pc

    # Finally, add the routine to the stack
    self.routine_callstack.append(new_routine)
    print(self.routine_callstack)

    new_routine.print_debug()

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
    print("Setting global variable")
    # TODO: If negative, convert to 2's Complement
    # Split value into two bytes
    top_byte = (value & 0xff00) >> 8
    bottom_byte = value & 0x00ff
    top_addr = self.global_table_start + (variable_number * 2)
    self.mem[top_addr] = top_byte
    self.mem[top_addr + 1] = bottom_byte
    print("Top byte:")
    print(hex(self.mem[top_addr]))
    print("Bottom byte:")
    print(hex(self.mem[top_addr+1]))

  # First address depends on version
  def getFirstAddress(self):
    print("getFirstAddress")
    if (self.version != 6):
      self.pc = self.getNumber(0x06)
    else:
      self.pc = self.unpackAddress(self.getNumber(0x06), True)
    print(self.pc)

  # Most numbers are stored as two adjacent bytes
  def getNumber(self, addr):
    return (self.mem[addr] << 8) + self.mem[addr+1]

  # Some are small!
  def getSmallNumber(self, addr):
    return self.mem[addr]

  # Read an instruction (probably at PC)
  # Bit complicated due to versioning...
  def getInstruction(self, addr):
    print("getInstruction at " + hex(addr))
    next_byte = addr
    # First, determine the opcode
    first_opcode_byte = self.mem[addr]
    print("Opcode:" + str(first_opcode_byte) + "(" + hex(first_opcode_byte) + ")")
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

    print("Got form: " + form.name)

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
    print("getOperandType: " + bin(opcode_bytes))
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
    print("getOpcode")
    print("last five bits: " + hex(byte & 0b00011111))
    print("last four bits: " + hex(byte & 0b00011111))
    if (operand_type == Operand.TwoOP and byte & 0b00011111 == 1):
        return "je"
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
    pass

  def getExtendedOpcode(self, byte):
    print("ExtendedOpcode")
    pass

  def print_debug(self):
    print("-------------")
    print("Stack:")
    print(self.stack)
    if (len(self.routine_callstack) > 0):
      print("Current routine state:")
      print(self.routine_callstack[-1].print_debug())
    print("-------------")

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
