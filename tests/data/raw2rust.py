import sys
sys.stdout.write('let packet = vec![')
with open(sys.argv[1],'rb') as f:
  while True:
     in_byte = f.read(1)
     if not in_byte: break
     sys.stdout.write(hex(ord(in_byte)))
     sys.stdout.write(',')
sys.stdout.write('];')


