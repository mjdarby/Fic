import sys

if __name__ == '__main__':
  f = open(sys.argv[1], "rb")
  memory = f.read()
  print(memory[int(sys.argv[2])])
