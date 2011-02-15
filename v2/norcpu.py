import sys, re, time, string, binascii

verbose = False
verbose_cpu = False
scrumble = True

secret_password = "h1cKmE1fUsAn"
secret_password_xor_mask = 0x3401
secret_password_add = 29

secret_code = "R0und2 D0ne!"
secret_code_xor_mask = 0x730A
secret_code_add = 37

guess = "123456789012"
guess = secret_password

code_segment = []
data_segment = []

label_count = 0

def dump(data, length = 8):
  result = []
  for i in xrange(0, len(data), length):
    line = data[i:i + length]
    hex_line = ' '.join(["%04X" % x for x in line])
    result.append("%04X: %-*s\n" % (i, length*5, hex_line))
  return ''.join(result)

def dump_js(data, length = 8):
  result = []
  for i in xrange(0, len(data), length):
    line = data[i:i + length]
    hex_line = ' '.join(["0x%04X," % x for x in line])
    result.append("%-*s\n" % (length*5, hex_line))
  return ''.join(result)

def encode_string(data, name, mask, coef_add):
  global mem, names
  offset = names[name]
  offset_sz = names[name + "_sz"]
  for i in range(0, len(data)):
    mem[offset + i] = ord(data[i]) ^ mask
    mask = (mask * 3 + coef_add) & 0xffff
  mem[offset_sz] = len(data)

def put_string(data, name):
  global mem, names
  offset = names[name]
  offset_sz = names[name + "_sz"]
  for i in range(0, len(data)):
    mem[offset + i] = ord(data[i])
  mem[offset_sz] = len(data)

def save_mem(name, size = -1):
  f = open(name, "w")
  if size == -1: size = len(mem)
  for i in (mem[0:size]):
    hex = "%04X" % i
    bin = binascii.a2b_hex(hex)
    f.write(bin)
  f.close()

def next_label():
  global label_count
  label_count = label_count + 1
  return "label_%04d" % label_count

def code_rem(comment):
  code_segment.append('; ' + comment)

def data_rem(comment):
  data_segment.append('; ' + comment)

def data_label(name):
  data_segment.append(name + ":")

def code_label(name):
  code_segment.append(name + ":")

def code(value):
  printed = value
  if type(value).__name__ == 'int':
    printed = "%d" % value
  code_segment.append("  dw %s" % printed)
 
scrumble_counter = 0x2743

def next_scrumble_counter():
  global scrumble_counter
  scrumble_counter = scrumble_counter * 3 + 7
  return scrumble_counter & 0xffff

def word(value):
  if value == -1: 
    if scrumble:
      value = next_scrumble_counter()
    else:
      value = 0
  printed = value
  if type(value).__name__ == 'int':
    printed = "%d" % value
  data_segment.append("  dw %s" % printed)
  
def buffer(length, value = -1):
  for i in range(0, length):
    word(value)

def var(name, value = -1):
  data_label(name);
  word(value);

# Macros
  
def NOR(a, b, r):
  code_rem('NOR ' + str(a) + ' ' + str(b) + ' ' + str(r))
  code(a)
  code(b)
  code(r)

def NOT(a, r):
  NOR(a, a, r);

def OR(a, b, r):
  NOR(a, b, "or_reg")
  NOT("or_reg", r)
var("or_reg")
                
def AND(a, b, r):
  NOT(a, "and_reg_a")
  NOT(b, "and_reg_b")
  OR("and_reg_a", "and_reg_b", "and_reg_a")
  NOT("and_reg_a", r)
var("and_reg_a")
var("and_reg_b")

def ANDi(a, imm, r):
  MOVi(imm, "and_i_reg")
  AND(a, "and_i_reg", r)
var("and_i_reg")  
  
def XOR(a, b, r):
  NOT(a, "xor_reg_a")
  NOT(b, "xor_reg_b")
  AND(a, "xor_reg_b", "xor_reg_b")
  AND(b, "xor_reg_a", "xor_reg_a")
  OR("xor_reg_a", "xor_reg_b", r)
var("xor_reg_a")
var("xor_reg_b")

def XORi(a, imm, r):
  MOVi(imm, "xor_i_reg")
  XOR(a, "xor_i_reg", r)
var("xor_i_reg")  

def MOV(a, b):
  code_rem('MOV ' + str(a) + ' ' + str(b))
  NOT(a, "move_reg")
  NOT("move_reg", b)
  code_rem('MOV END')
var("move_reg")

def JMP(a):
  code_rem('JMP ' + str(a))
  MOV(a, "ip")

def JMPi(a):
  code_rem('JMPi ' + str(a))
  label = next_label()
  JMP(label)
  code_label(label)
  code(a)

def MOVi(imm, a):
  code_rem('MOVi #' + str(imm) + ' ' + str(a))
  label_data = next_label()
  label_jump = next_label()
  MOV(label_data, a)
  JMPi(label_jump)
  code_label(label_data)
  code(imm)
  code_label(label_jump)

# [a] -> b
def PEEK(a, b):
  label1 = next_label()
  label2 = next_label()
  MOV(a, label1)
  MOV(a, label2)
  code_label(label1)  # NOT(0, 0, move_reg)
  code(0)             # <- a
  code_label(label2)  #
  code(0)             # <- a
  code("move_reg")    #
  NOT("move_reg", b)

# a -> [b]
def POKE(a, b):
  code_rem('POKE ' + str(a) + ' [' + str(b) + ']')
  label = next_label()
  MOV(b, label)
  NOT(a, "move_reg")  # +3 (three operations)
  code("move_reg")    # +4
  code("move_reg")    # +5
  code_label(label)     
  code(0)             # <- b

# imm -> [a]
def POKEi(imm, a):
  MOVi(imm, "poke_i_reg")
  POKE("poke_i_reg", a)
var("poke_i_reg")

def EXIT(a):
  MOV(a, "exit_reg")
  
def EXITi(a):
  MOVi(a, "exit_reg")

def FADD(mask, carry, a, b, r):
  AND(a, mask, "fadd_reg_a")  # zero bits in 'a' except mask'ed
  AND(b, mask, "fadd_reg_b")  # zero bits in 'b' except mask'ed
  AND(carry, mask, carry)     # zero bits in 'carry' except mask'ed

  # SUM = (a ^ b) ^ carry
  XOR(a, b, "fadd_reg_t1")    
  XOR("fadd_reg_t1", carry, "fadd_reg_bit_r")

  # Leave only 'mask'ed bit in bit_r.
  AND("fadd_reg_bit_r", mask, "fadd_reg_bit_r")

  # Add current added bit to the result.
  OR("fadd_reg_bit_r", r, r)

  # CARRY = (a & b) | (carry & (a ^ b))
  AND(a, b, "fadd_reg_t2")
  AND(carry, "fadd_reg_t1", "fadd_reg_t1")

  # CARRY is calculated, and 'shift_reg' contains the same value
  # but shifted the left by 1 bit.
  OR("fadd_reg_t2", "fadd_reg_t1", carry)

  # CARRY is shifted the left by 1 bit to be used on the next round.
  MOV("shift_reg", carry)

  # shift_reg = mask << 1
  MOV(mask, mask)
  # mask = shift (effectively "mask = mask << 1")
  MOV("shift_reg", mask)

  AND(carry, mask, carry)

var("fadd_reg_a")
var("fadd_reg_b")
var("fadd_reg_bit_r")
var("fadd_reg_t1")
var("fadd_reg_t2")

def ZERO(a):
  XOR(a, a, a)

def FADC(a, b, r):
  ZERO("fadc_reg_t")
  MOV("const_1", "fadc_reg_mask")
  for i in range(0, 16):
    FADD("fadc_reg_mask", "carry_reg", a, b, "fadc_reg_t")
  MOV("fadc_reg_t", r)

  ZERO("fadc_reg_t")

  for i in range(0, 16):
    OR("fadc_reg_t", "carry_reg", "fadc_reg_t")
    MOV("carry_reg", "carry_reg")
    MOV("shift_reg", "carry_reg")

  MOV("fadc_reg_t", "carry_reg")

var("fadc_reg_mask")
var("fadc_reg_t")

def ADD(a, b, r):
  ZERO("carry_reg")
  FADC(a, b, r)

def ADDi(a, imm, r):
  MOVi(imm, "add_i_reg")
  ADD(a, "add_i_reg", r)
var("add_i_reg")

def PUSH(a):
  ADD("stack_reg", "const_minus_1", "stack_reg")
  POKE(a, "stack_reg")

def PUSHi(imm):
  MOVi(imm, "push_i_reg")
  PUSH("push_i_reg")
var("push_i_reg")

def POP(a):
  PEEK("stack_reg", a)
  ADD("stack_reg", "const_1", "stack_reg")

def CALL(a):
  label = next_label()
  PUSHi(label)
  JMP(a)
  code_label(label)

def CALLi(a):
  label = next_label()
  PUSHi(label)
  JMPi(a)
  code_label(label)

def RET():
  POP("ip")

# Jump 'a', if cond = FFFF, and 'b' if conf = 0000
def BRANCH(a, b, cond):
  AND(a, cond, "branch_reg_a")              # reg_a = a & cond
  NOT(cond, "branch_reg_b")                 # reg_b = !cond
  AND(b, "branch_reg_b", "branch_reg_b")    # reg_b = b & reg_b = b & !cond
  OR("branch_reg_a", "branch_reg_b", "ip")  # ip = (a & cond) | (b & !cond)
var("branch_reg_a")
var("branch_reg_b")

# Jump 'a', if cond = FFFF, and 'b' if conf = 0000
def BRANCHi(a, b, cond):
  MOVi(a, "branch_i_reg_a")
  MOVi(b, "branch_i_reg_b")
  BRANCH("branch_i_reg_a", "branch_i_reg_b", cond)
var("branch_i_reg_a")
var("branch_i_reg_b")

# if a != 0 -> carry = FFFF else carry = 0000
def IS_0(a):
  ZERO("carry_reg")
  FADC(a, "const_minus_1", "is_0_reg")
  NOT("carry_reg", "zero_reg")
var("is_0_reg")
var("zero_reg")

# ip = (zero_reg == FFFF ? a : ip)
def JZi(a):
  label = next_label()
  BRANCHi(a, label, "zero_reg")
  code_label(label)

# ip = (zero_reg == FFFF ? a : ip)
def JNZi(a):
  label = next_label()
  BRANCHi(label, a, "zero_reg")
  code_label(label)

def ROL(a, b):
  MOV(a, a)            # shift_reg = a << 1
  MOV("shift_reg", b)
  
def ROR(a, b):
  MOV(a, "ror_reg")
  for i in range(0, 15):
    ROL("ror_reg", "ror_reg")
  MOV("ror_reg", b)
var("ror_reg")    

def SHL(a, b):
  ROL(a, b)
  ANDi(b, 0x0001, b)
  
def SHR(a, b):
  ROR(a, b)
  ANDi(b, 0x7FFF, b)

def MUL3(a, b):
  ADD(a, a, "mul3_reg")    # mul3_reg = a + a
  ADD("mul3_reg", a, b)    # b = mul3_reg + a
var("mul3_reg")         

# NORCPU code

var("ip", "start")
var("shift_reg")
var("carry_reg")
var("const_1", 1)
var("const_minus_1", 0xFFFF)
var("exit_reg")

var("stack_reg", "stack")

code_label("start")

var("ch")
var("t")
var("xor_mask")
var("cmp_flag")

var("ptr")
var("ptr2")
var("i")

MOVi("exchange", "ptr")
MOVi("secret_password", "ptr2")
MOVi(secret_password_xor_mask, "xor_mask")
MOVi(0, "cmp_flag")
MOVi(len(secret_password), "i")

cmp_loop = next_label()
code_label(cmp_loop)               # cmp_loop:
PEEK("ptr", "ch")                                      # ch = *ptr
XOR("ch", "xor_mask", "ch")                            # ch ^= xor_mask
PEEK("ptr2", "t")                                      # t = *ptr2
XOR("ch", "t", "ch")                                   # ch = ch ^ t
OR("cmp_flag", "ch", "cmp_flag")                       # cmp_flag |= ch
ADD("ptr", "const_1", "ptr")                           # ptr += 1
ADD("ptr2", "const_1", "ptr2")                         # ptr2 += 1
MUL3("xor_mask", "xor_mask")                           # xor_mask *= 3
ADDi("xor_mask", secret_password_add, "xor_mask")      # xor_mask += add_const
ADD("i", "const_minus_1", "i")                         # i -= 1
IS_0("i")
JNZi(cmp_loop)

MOVi(0, "exchange_sz")

ok_label = next_label()
IS_0("cmp_flag")
JZi(ok_label)

exit_label = next_label()
JMPi(exit_label)

code_label(ok_label)

MOVi("secret_code", "ptr")
MOV("secret_code_sz", "i")
MOVi(secret_code_xor_mask, "xor_mask")

MOVi("exchange", "ptr2")

MOV("i", "exchange_sz")

loop = next_label()
code_label(loop)                   # loop:
PEEK("ptr", "ch")                             # ch = *ptr
XOR("ch", "xor_mask", "ch")                   # ch ^= xor_mask
POKE("ch", "ptr2")                            # *ptr2 = ch
MUL3("xor_mask", "xor_mask")                  # xor_mask *= 3
ADDi("xor_mask", secret_code_add, "xor_mask") # xor_mask += add_const
ADD("ptr", "const_1", "ptr")                  # ptr += 1
ADD("ptr2", "const_1", "ptr2")                # ptr2 += 1
ADD("i", "const_minus_1", "i")                # i = i - 1
IS_0("i")
JNZi(loop)

code_label(exit_label)             # exit_label:
EXITi(0x00)

buffer(8)
data_label("stack")

var("secret_code_sz", len(secret_code))
data_label("secret_code")
buffer(len(secret_code))

var("secret_password_sz")
data_label("secret_password")
buffer(16)

var("exchange_sz", 0)
data_label("exchange")
buffer(32)

# Compiler

text = code_segment
text.extend(data_segment)

if verbose:
  print "\n".join(text)

# Phase 1. Calculate names.

addr = 0
names = {}
for line in text:
  if line[0] == ';': continue
  if line[0] != ' ':
    name = line.partition(':')[0]
    names[name] = addr
  else:
    addr = addr + 1

if verbose:
  print names

raw_text = "\n".join(text)

# Resolve names.

for name in names:
  if verbose:
    print name, names[name], type(names[name])
  name_re = re.compile(r'dw ' + name + '$', re.M)
  value = "%d" % names[name]
  raw_text = name_re.sub('dw ' + value, raw_text)

text = raw_text.split("\n")

if verbose:
  print "\n".join(text)

# Phase 2. Compilation.

addr = 0
comment = ""
mem = []
for line in text:
  if line[0] == ';' or line[0] != ' ':
    comment = comment + line + ' '
  else:
    value = int(line.strip().partition(" ")[2])
    if verbose:
      print "%04X: %04X ; %s" % (addr, value, comment)
    mem.append(value)
    addr = addr + 1
    comment = ""

# Interpretation

ip = names["ip"]
exit_reg = names["exit_reg"]
shift_reg = names["shift_reg"]
carry_reg = names["carry_reg"]

def nor(a, b):
  r = a | b
  r = r ^ 0xFFFF
  return r & 0xFFFF

def norcpu():
  while 1:
    i = mem[ip];
    a = mem[i + 0]
    b = mem[i + 1]
    r = mem[i + 2]
    mem[ip] = i + 3
    f = nor(mem[a], mem[b])
    mem[r] = f
    mem[shift_reg] = ((f >> 15) & 1) | ((f & 0x7FFF) << 1)

    if verbose_cpu:
      print "%04X: %04X [%04X] %04X [%04X] -> %04X [%04X]" % \
            (i, a, mem[a], b, mem[b], r, mem[r])
    if r == exit_reg:
      break

print "Starting from [%04X]" % mem[ip]

encode_string(secret_code, "secret_code", secret_code_xor_mask, secret_code_add);
encode_string(secret_password, "secret_password", secret_password_xor_mask, secret_password_add);

mem_js = dump_js(mem)
save_mem("norcpu-1-before.bin")
mem_sz = len(mem)

if len(mem) >= 0x10000:
  print "Too much code (%08X, %04X)" % (len(mem), len(mem) - 0x10000)
  sys.exit()

# Inject plain password in the last moment (for testing).
put_string(guess, "exchange")
  
save_mem("norcpu-2-before-with-password.bin")

if verbose:
  print "Original memory:"
  print dump(mem)

start_time = time.time()

norcpu()

end_time = time.time()  

save_mem("norcpu-3-after.bin", mem_sz)

if verbose:
  print "Memory after:"
  dump(mem)

print
print "Size: %X" % len(mem)
print "Time: %d" % (end_time - start_time)
print "Exit: %04X" % mem[exit_reg]

exchange = names["exchange"]
result_value = ""
for i in range(0, mem[names["exchange_sz"]]):
  result_value = result_value + chr(mem[exchange + i] & 0xff)
  
print "Result: [%s]" % result_value

if len(result_value) == 0:
  print "ERROR: Wrong password"

js = string.Template(open('template.html', 'r').read())

js = js.substitute( \
  ip = names["ip"],
  exit_reg = names["exit_reg"],
  shift_reg = names["shift_reg"],
  exchange = names["exchange"],
  exchange_sz = names["exchange_sz"],
  mem_js = mem_js
)

f = open("norcpu2.html", "w")
f.write(js)
f.close()
