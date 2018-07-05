import hashlib, binascii
import sys, subprocess, os

# NXO64 Stuff here
#
#
#--------------------------------------------------
# Copyright 2017 Reswitched Team
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or
# without fee is hereby granted, provided that the above copyright notice and this permission
# notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
# OR PERFORMANCE OF THIS SOFTWARE.

# nxo64.py: IDA loader (and library for reading nso/nro files)

import struct

import lz4.block

uncompress = lz4.block.decompress

def kip1_blz_decompress(compressed):
    compressed_size, init_index, uncompressed_addl_size = struct.unpack('<III', compressed[-0xC:])
    decompressed = compressed[:] + '\x00' * uncompressed_addl_size
    decompressed_size = len(decompressed)
    if len(compressed) != compressed_size:
        assert len(compressed) > compressed_size
        compressed = compressed[len(compressed) - compressed_size:]
    if not (compressed_size + uncompressed_addl_size):
        return ''
    compressed = map(ord, compressed)
    decompressed = map(ord, decompressed)
    index = compressed_size - init_index
    outindex = decompressed_size
    while outindex > 0:
        index -= 1
        control = compressed[index]
        for i in xrange(8):
            if control & 0x80:
                if index < 2:
                    raise ValueError('Compression out of bounds!')
                index -= 2
                segmentoffset = compressed[index] | (compressed[index+1] << 8)
                segmentsize = ((segmentoffset >> 12) & 0xF) + 3
                segmentoffset &= 0x0FFF
                segmentoffset += 2
                if outindex < segmentsize:
                    raise ValueError('Compression out of bounds!')
                for j in xrange(segmentsize):
                    if outindex + segmentoffset >= decompressed_size:
                        raise ValueError('Compression out of bounds!')
                    data = decompressed[outindex+segmentoffset]
                    outindex -= 1
                    decompressed[outindex] = data
            else:
                if outindex < 1:
                    raise ValueError('Compression out of bounds!')
                outindex -= 1
                index -= 1
                decompressed[outindex] = compressed[index]
            control <<= 1
            control &= 0xFF
            if not outindex:
                break
    return ''.join(map(chr, decompressed))

class BinFile(object):
    def __init__(self, li):
        self._f = li

    def read(self, arg):
        if isinstance(arg, str):
            fmt = '<' + arg
            size = struct.calcsize(fmt)
            raw = self._f.read(size)
            out = struct.unpack(fmt, raw)
            if len(out) == 1:
                return out[0]
            return out
        elif arg is None:
            return self._f.read()
        else:
            out = self._f.read(arg)
            return out

    def read_from(self, arg, offset):
        old = self.tell()
        try:
            self.seek(offset)
            out = self.read(arg)
        finally:
            self.seek(old)
        return out

    def seek(self, off):
        self._f.seek(off)

    def close(self):
        self._f.close()

    def tell(self):
        return self._f.tell()



def kip_get_full(fileobj):
	f = BinFile(fileobj)

	if f.read_from('4s', 0) != 'KIP1':
		raise NxoException('Invalid KIP magic')

	tloc, tsize, tfilesize = f.read_from('III', 0x20)
	rloc, rsize, rfilesize = f.read_from('III', 0x30)
	dloc, dsize, dfilesize = f.read_from('III', 0x40)
	
	toff = 0x100
	roff = toff + tfilesize
	doff = roff + rfilesize

	
	bsssize = f.read_from('I', 0x18)

	#print 'load text: ' 
	text = kip1_blz_decompress(str(f.read_from(tfilesize, toff)))
	ro   = kip1_blz_decompress(str(f.read_from(rfilesize, roff)))
	data = kip1_blz_decompress(str(f.read_from(dfilesize, doff)))
	
	
	full = text
	if rloc >= len(full):
		full += '\0' * (rloc - len(full))
	else:
		#print 'truncating?'
		full = full[:rloc]
	full += ro
	if dloc >= len(full):
		full += '\0' * (dloc - len(full))
	else:
		#print 'truncating?'
		full = full[:dloc]
	full += data

	return full
# -------------------------------------------------------------------------

# Constants (Check out http://switchbrew.org/index.php?title=Flash_Filesystem and https://gist.github.com/roblabla/d8358ab058bbe3b00614740dcba4f208)
PKG11_REALBEGIN = 0x100000
PKG11_LENGTH = 0x40000

PKG21_BEGIN = 0x4000

FNULL = open(os.devnull, "wb")

HACTOOL_PATH = "hactool"


KEY_HASHES = {
	"keyblob_mac_key_source" : "B24BD293259DBC7AC5D63F88E60C59792498E6FC5443402C7FFE87EE8B61A3F0",

	
	"keyblob_key_source_00" : "8A06FE274AC491436791FDB388BCDD3AB9943BD4DEF8094418CDAC150FD73786",
	
	"keyblob_key_sources" : 
	{
		"keyblob_key_source_01" : "2D5CAEB2521FEF70B47E17D6D0F11F8CE2C1E442A979AD8035832C4E9FBCCC4B",
		"keyblob_key_source_02" : "61C5005E713BAE780641683AF43E5F5C0E03671117F702F401282847D2FC6064",
		"keyblob_key_source_03" : "8E9795928E1C4428E1B78F0BE724D7294D6934689C11B190943923B9D5B85903",
		"keyblob_key_source_04" : "95FA33AF95AFF9D9B61D164655B32710ED8D615D46C7D6CC3CC70481B686B402"
	},
	

	"master_key_source" : "7944862A3A5C31C6720595EFD302245ABD1B54CCDCF33000557681E65C5664A4",
	"master_key_00" : "0EE359BE3C864BB0782E1D70A718A0342C551EED28C369754F9C4F691BECF7CA",

	"master_keys" : 
	{
		"master_key_01" : "4FE707B7E4ABDAF727C894AAF13B1351BFE2AC90D875F73B2E20FA94B9CC661E",
		"master_key_02" : "79277C0237A2252EC3DFAC1F7C359C2B3D121E9DB15BB9AB4C2B4408D2F3AE09",
		"master_key_03" : "4F36C565D13325F65EE134073C6A578FFCB0008E02D69400836844EAB7432754",
		"master_key_04" : "75FF1D95D26113550EE6FCC20ACB58E97EDEB3A2FF52543ED5AEC63BDCC3DA50"
	},

	
	"package1_key_00" : "4543CD1B7CAD7EE0466A3DE2086A0EF923805DCEA6C741541CDDB14F54F97B40",
	
	"package1_keys" :
	{
		"package1_key_01" : "984F1916834540FF3037D65133F374BD9E715DC3B162AAC77C8387F9B22CF909",
		"package1_key_02" : "9E7510E4141AD89D0FB697E817326D3C80F96156DCE7B6903049AC033E95F612",
		"package1_key_03" : "E65C383CDF526DFFAA77682868EBFA9535EE60D8075C961BBC1EDE5FBF7E3C5F",
		"package1_key_04" : "28AE73D6AE8F7206FCA549E27097714E599DF1208E57099416FF429B71370162"
	},

	
	"package2_key_source" : "21E2DF100FC9E094DB51B47B9B1D6E94ED379DB8B547955BEF8FE08D8DD35603",

	"aes_kek_generation_source" : "FC02B9D37B42D7A1452E71444F1F700311D1132E301A83B16062E72A78175085",
	"aes_key_generation_source" : "FBD10056999EDC7ACDB96098E47E2C3606230270D23281E671F0F389FC5BC585",
	"titlekek_source" : "C48B619827986C7F4E3081D59DB2B460C84312650E9A8E6B458E53E8CBCA4E87",

	"key_area_key_application_source" : "04AD66143C726B2A139FB6B21128B46F56C553B2B3887110304298D8D0092D9E",
	"key_area_key_ocean_source" : "FD434000C8FF2B26F8E9A9D2D2C12F6BE5773CBB9DC86300E1BD99F8EA33A417",
	"key_area_key_system_source" : "1F17B1FD51AD1C2379B58F152CA4912EC2106441E51722F38700D5937A1162F7",
	"header_kek_source" : "1888CAED5551B3EDE01499E87CE0D86827F80820EFB275921055AA4E2ABDFFC2",
	"header_key_source" : "8F783E46852DF6BE0BA4E19273C4ADBAEE16380043E1B8C418C4089A8BD64AA6",

	"sd_card_kek_source" : "6B2ED877C2C52334AC51E59ABFA7EC457F4A7D01E46291E9F2EAA45F011D24B7",
	"sd_card_save_key_source" : "D482743563D3EA5DCDC3B74E97C9AC8A342164FA041A1DC80F17F6D31E4BC01C",
	"sd_card_nca_key_source" : "2E751CECF7D93A2B957BD5FFCB082FD038CC2853219DD3092C6DAB9838F5A7CC"
}

KEY_SIZES = {
	"keyblob_mac_key_source" : 0x10,

	
	"keyblob_key_source_00" : 0x10,
	"keyblob_key_sources" : 0x10,
	

	"master_key_source" : 0x10,
	"master_key_00" : 0x10,

	"master_keys" : 0x10,

	
	"package1_key_00" : 0x10,
	"package1_keys" : 0x10,

	
	"package2_key_source" : 0x10,

	"aes_kek_generation_source" : 0x10,
	"aes_key_generation_source" : 0x10,
	"titlekek_source" : 0x10,

	"key_area_key_application_source" : 0x10,
	"key_area_key_ocean_source" : 0x10,
	"key_area_key_system_source" : 0x10,
	"header_kek_source" : 0x10,
	"header_key_source" : 0x20,

	"sd_card_kek_source" : 0x10,
	"sd_card_save_key_source" : 0x20,
	"sd_card_nca_key_source" : 0x20
}

keyz = {}


# Utilities
def quit_with_errormsg(message):
	print message
	sys.exit(1)


def find_via_hash(data, hash, size):
	#print hash
	for i in range(len(data) - size):
		m = hashlib.sha256()
		m.update(data[i : i + size])
		if m.hexdigest() == hash.lower():
			#print "key found"
			return binascii.hexlify(data[i : i + size]).upper()
			#print binascii.hexlify(data[i : i + len(hash)]).upper()
			#print m.hexdigest()
			#break
	
	return ""

def find_via_hashset(data, hashset, size):
	for name, hash in hashset.iteritems():
		result = find_via_hash(data, hashset[name], size)
		if result != "":
			return name, result
	
	return ""

def checkfound(possibleblank, name):
	if possibleblank == "":
		quit_with_errormsg("Could not find " + name + "! Please check the integrity of the data used in the current stage!")
	
	return possibleblank

def parse_hactool(output):
	output = output.replace(" ", "")
	for line in output.splitlines():
		if "=" not in line:
			continue
		keyname, hactoolkey = line.split("=")
		#print keyname
		if keyname not in keyz and "encrypted_keyblob" not in keyname:
			keyz[keyname] = hactoolkey

			
def update_keyfile():
	#Overwrite keys.txt if it already exists
	keys_f = open("keys.txt", "wb+")
	
	for keyname, key in keyz.iteritems():
		keys_f.write(keyname + " = " + key + "\n")
	
	keys_f.flush()
	keys_f.close()
	
def find_and_add_key(data, keyname):
	key = checkfound(find_via_hash(data, KEY_HASHES[keyname], KEY_SIZES[keyname]), keyname)
	keyz[keyname] = key

# Real code
if len(sys.argv) == 1:
	print "kezplez.py : a badly written way to get all of your switch keys, legally!"
	print "made by: tesnos6921"
	print ""
	print "All this awesome scene development wouldn't be happening without the ReSwitched team. Thanks to them for nxo64.py, rajkosto for HacDiskMount and biskeydump (+hints for .kip1s), and to roblada for the original keybingo gist!"
	print ""
	print "Usage: "
	print "Place hactool, BOOT0.bin (can be dumped from hekate) and BCPKG2-1-Normal-Main.bin (use HacDiskMount on your RawNand.bin) in the same folder and run"
	print "python kezplez.py your-sbk-here your-tsec-key-here"
	print ""
	print "This process is very inefficient and can take a few minutes."
	sys.exit(1)


keyz["secure_boot_key"] = sys.argv[1]
keyz["tsec_key"] = sys.argv[2]


BOOT0_f = open("BOOT0.bin", "rb")
BOOT0_data = BOOT0_f.read()
BOOT0_f.close()

PKG21PART_f = open("BCPKG2-1-Normal-Main.bin", "rb")
PKG21PART_data = PKG21PART_f.read()
PKG21PART_f.close()

PKG21_f = open("package2.bin", "wb+")
PKG21_data = PKG21PART_data[PKG21_BEGIN : len(PKG21PART_data)]
PKG21_f.write(PKG21_data)
PKG21_f.close()

# Stage 0 : Extract package1 from BOOT0.bin and get keyblob_mac_key_source, master_key_source, and keyblob_key_source_xx from it
PKG11_f = open("package1.bin", "wb+")
if "PK11" not in BOOT0_data:
	quit_with_errormsg("package1 was not found.  Please check the integrity of your BOOT0.bin")

print "Using BOOT0.bin to get keys from package1..."

PKG11_begin = BOOT0_data.find("PK11")
PKG11_data = BOOT0_data[PKG11_begin : PKG11_begin + PKG11_LENGTH]
PKG11_f.write(PKG11_data)
PKG11_f.close()

#print len(PKG11_data)

find_and_add_key(PKG11_data, "keyblob_mac_key_source")
find_and_add_key(PKG11_data, "master_key_source")
find_and_add_key(PKG11_data, "keyblob_key_source_00")
# Firmware dependent, so it varies
keyblob_key_source_id, keyblob_key_source_xx = checkfound(find_via_hashset(PKG11_data, KEY_HASHES["keyblob_key_sources"], KEY_SIZES["keyblob_key_sources"]), "keyblob_key_source_xx")
keyz[keyblob_key_source_id] = keyblob_key_source_xx

update_keyfile()

# Now with these keys, we can run hactool to derive package1_key_00/package1_key_xx and master_key_00/master_key_xx
print "Deriving keys..."

stage0_results = subprocess.check_output([HACTOOL_PATH, "--keyset=keys.txt", "--intype=keygen", "BOOT0.bin"])
parse_hactool(stage0_results)
update_keyfile()

# Decrypt package1 with our newly derived keys
print "Decrypting package1..."
# Impostor!
PKG11_f = open("package1.bin", "wb+")
PKG11_data = BOOT0_data[PKG11_REALBEGIN : PKG11_REALBEGIN + PKG11_LENGTH]
PKG11_f.write(PKG11_data)
PKG11_f.close()
subprocess.call([HACTOOL_PATH, "--keyset=keys.txt", "--package1dir=package1", "--intype=pk11", "package1.bin"], stdout=FNULL)
# After package1 is decrypted, we move on to...

# Stage 1 : Extract titlekek_source, aes_kek_generation_source, and package2_key_source from Secure_Monitor.bin (TrustZone code)
print "Using Secure_Monitor.bin to get keys to decrypt package2..."

TZ_f = open("package1/Secure_Monitor.bin", "rb")
TZ_data = TZ_f.read()
TZ_f.close()

find_and_add_key(TZ_data, "titlekek_source")
find_and_add_key(TZ_data, "aes_kek_generation_source")
find_and_add_key(TZ_data, "package2_key_source")

update_keyfile()


# About halfway there, now to decrypt package2
print "Decrypting package2..."
subprocess.call([HACTOOL_PATH, "--keyset=keys.txt", "--package2dir=package2", "--ini1dir=ini1", "--intype=pk21", "package2.bin"], stdout=FNULL)

# Stage 2 : All kip1s from package2 are compressed via lz4 somehow.  I don't care enough to understand how, but thanks again to reswitched, this time for their IDA "nxo64.py" loader (I just stripped everything but the kip bits)
print "Decompressing spl.kip1 and FS.kip1..."

SPL_KIP1_f = open("ini1/spl.kip1", "rb")
FS_KIP1_f = open("ini1/FS.kip1", "rb")

SPL_KIP1_data = kip_get_full(SPL_KIP1_f)
FS_KIP1_data = kip_get_full(FS_KIP1_f)

SPL_KIP1_f.close()
FS_KIP1_f.close()

# Now for the final keys...
print "Getting keys from spl..."

find_and_add_key(SPL_KIP1_data, "aes_key_generation_source")

print "Getting keys from FS..."

find_and_add_key(FS_KIP1_data, "key_area_key_application_source")
find_and_add_key(FS_KIP1_data, "key_area_key_ocean_source")
find_and_add_key(FS_KIP1_data, "key_area_key_system_source")
find_and_add_key(FS_KIP1_data, "header_kek_source")
find_and_add_key(FS_KIP1_data, "header_key_source")
find_and_add_key(FS_KIP1_data, "sd_card_kek_source")
find_and_add_key(FS_KIP1_data, "sd_card_save_key_source")
find_and_add_key(FS_KIP1_data, "sd_card_nca_key_source")

update_keyfile()

# Stage 3 : a bit of extra derivation can never hurt, right?
print "Doing final key derivation..."

stage3_results = subprocess.check_output([HACTOOL_PATH, "--keyset=keys.txt", "--intype=keygen", "BOOT0.bin"])
parse_hactool(stage3_results)
update_keyfile()

print "If there were no warnings, we found all the keys!"
print "Now you can do hactool --keyset=keys.txt to use them!"