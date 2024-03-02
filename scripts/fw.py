#!/usr/bin/env python

import sys

# (name, offset, size)
fwp = (("uboot", 0, 0x40000), ("header1", 0x40000, 0x140), ("uImage1", 0x40140, 0x12fec0), ("squashfs1", 0x170000, 0x270000), ("header2", 0x3E0000, 0x140), ("uImage2", 0x3E0140, 0x12fec0), ("squashfs2", 0x510000, 0x270000), ("bootcfg", 0x780000, 0x10000), ("unk1", 0x790000, 0x10000), ("jffs2", 0x7A0000, 393216))

def exfw(fw_name):
	ifile = open(fw_name, 'rb')
	for component in fwp:
		ofile = open(component[0], 'wb')
		ifile.seek(component[1])
		data = ifile.read(component[2])
		ofile.write(data)
		ofile.close()
	ifile.close()

def pkfw(new_fw_name):
	ofile = open(new_fw_name, 'wb')
	count = 0
	for component in fwp:
		ifile = open(component[0], 'rb')
		data = ifile.read()
		ofile.write(data)
		count += len(data)
		padlen = component[2]-len(data)
		if padlen > 0:
			ofile.write(b'\xff'*padlen)
			count += padlen
		ifile.close()
	ofile.close()
	if count > 0x800000:
		print('Warning: size of the new firmware is greater than the flashsize (0x800000)')
		exit(-1)


if sys.argv[1] == '-u' or sys.argv[1] == '--unpack':
    exfw(sys.argv[2])
elif sys.argv[1] == '-r' or sys.argv[1] == '--repack':
	pkfw(sys.argv[2])