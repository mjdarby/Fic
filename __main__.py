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
               branch_offset,
               text_to_print):
    self.opcode = opcode
    self.operand_types = operand_types
    self.operands = operands
    self.store_variable = store_variable
    self.branch_offset = branch_offset
    self.text_to_print = text_to_print

  def run(self, main_memory):
    main_memory.pc += 1
    raise Exception("Not implemented")

  def print_debug(self):
    print("Printing instr debug")
    print(self.opcode)
    print(self.operand_types)
    print(self.operands)
    print(self.store_variable)
    print(self.branch_offset)
    print(self.text_to_print)


# StoryLoader returns a memory map
class StoryLoader:
  def LoadZFile(filename):
    f = open(filename, "rb")
    memory = f.read()
    return Memory(memory)

# Memory - broken up into dynamic/high/static
class Memory:
  def __init__(self, memory_print):
    self.mem = memory_print
    self.dynamic = 0
    self.static = self.mem[0x0e]
    self.high = self.mem[0x04]
    self.version = self.mem[0x00]
    self.routine_offset = self.mem[0x28]
    self.string_offset = self.mem[0x2a]
    self.getFirstAddress()
    print(self.version)
    print(self.static)
    print(self.high)

  # First address depends on version
  def getFirstAddress(self):
    print("getFirstAddress")
    if (self.version != 6):
      self.pc = self.getNumber(0x06)
    else:
      self.pc = self.unpackAddress(0x06, True)
    print(self.pc)

  # Numbers are stored as two adjacent bytes
  def getNumber(self, addr):
    return (self.mem[addr] << 8) + self.mem[addr+1]

  # Read an instruction (probably at PC)
  # Bit complicated due to versioning...
  def getInstruction(self, addr):
    print("GetInstr")
    next_byte = addr
    # First, determine the opcode
    first_opcode_byte = self.mem[next_byte]
    print("Opcode:")
    print(first_opcode_byte)
    next_byte += 1
    opcode = None
    form = None
    opcount = None
    operands = None
    store_variable = None
    branch_offset = None
    text_to_print = None
    operand_types = []
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      opcode = self.getExtendedOpcode(next_byte)
      form = Forms.Extended
      next_byte += 1
    else:
      opcode = self.getOpcode(first_opcode_byte)

    # Figure out instruction form
    if (self.version >= 5 and (first_opcode_byte == 0xbe)):
      form = Forms.Extended
    elif (first_opcode_byte & 0b1100000 == 0b1100000):
      form = Form.Variable
    elif (first_opcode_byte & 0b1000000 == 0b1000000):
      form = Form.Short
    else:
      form = Form.Long

    print("Got form: " + form.name)

    # Figure out the operand count and type(s)
    opcount = self.getOperandCount(form, first_opcode_byte)
    if (form == Form.Extended or form == Form.Variable):
      operand_types = self.getOperandType(form, next_byte)
      next_byte += 1
      # Special case: call_vs2 and call_vn2 can have 4 more args
      if (opcode == 'call_vs2' or opcode == 'call_vn2'):
        operand_types += self.getOperandType(form, next_byte)
        next_byte += 1
    else:
      operand_types = self.getOperandType(form, first_opcode_byte)

    return Instruction(opcode,
                       operand_types,
                       operands,
                       store_variable,
                       branch_offset,
                       text_to_print)

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
    if (form == Form.Short):
      if (opcode_bytes & 0b0100000 == 0b0100000):
        return [Operand.Variable]
      elif (opcode_bytes & 0b0000000 == 0b0000000):
        return [Operand.Large]
      elif (opcode_bytes & 0b0010000 == 0b0010000):
        return [Operand.Small]
    elif (form == Form.Long):
      operand_types = []
      if (opcode_bytes & 0b0100000 == 0b0100000):
        operand_types.append(OperandType.Variable)
      else:
        operand_types.append(OperandType.Small)
      if (opcode_bytes & 0b0010000 == 0b0010000):
        operand_types.append(OperandType.Variable)
      else:
        operand_types.append(OperandType.Small)
      return operand_types
    else: # form == Variable or Extended
      operand_types = []
      operand_types.append("")

  def unpackAddress(self, addr, rcall):
    packedAddress = getNumber(addr)
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

  def getOpcode(self, byte):
    print("getOpcode")
    if (byte == 224):
      if (self.version > 3):
        return "call_vs"
      else:
        return "call"
    pass

  def getExtendedOpcode(self, byte):
    print("ExtendedOpcode")
    pass

def main():
  main_memory = StoryLoader.LoadZFile(sys.argv[1])
  while True:
    loop(main_memory)

def loop(main_memory):
  instr = main_memory.getInstruction(main_memory.pc)
  instr.print_debug()
  main_memory.pc = instr.run(main_memory)

if __name__ == "__main__":
  main()
