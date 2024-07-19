import sys

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <string>\n" % (sys.argv[0]))
		sys.exit(1)
	val = sys.argv[1];
	n = int(len(val)/4)+1
	c = n-1
	if (len(val)-c*4)==3:
		print("xor   eax, eax")
		print("mov   al, 0x", end='')
		print(hex(ord(val[c*4+2]))[2:])
		print("shl   eax, 0x10")
		print("add   ax, 0x", end='')
		print(hex(ord(val[c*4+1]))[2:], end='')
		print(hex(ord(val[c*4]))[2:])
	if (len(val)-c*4)==2:
		print("xor   eax, eax")
		print("mov   ax, 0x", end='')
		print(hex(ord(val[c*4+1]))[2:], end='')
		print(hex(ord(val[c*4]))[2:])
	if (len(val)-c*4)==1:
		print("xor   eax, eax")
		print("mov   al, 0x", end='')
		print(hex(ord(val[c*4]))[2:])
	if (len(val)-c*4)==0:
		print("xor   eax, eax")
	print("push  eax")
	c = c -1
	while c >= 0:
		print("push  0x", end='')
		print(hex(ord(val[c*4+3]))[2:], end='')
		print(hex(ord(val[c*4+2]))[2:], end='')
		print(hex(ord(val[c*4+1]))[2:], end='')
		print(hex(ord(val[c*4]))[2:])
		c = c -1
	print("push  esp")
	sys.exit(0)

if __name__ == "__main__":
 	main()