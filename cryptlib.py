#!/usr/bin/python
# coding=utf8
# author robipolli@gmail.com
# License AGPLv3 - http://www.gnu.org/licenses/agpl.html
#
# TODO use unittest

from Crypto.Cipher import AES
import binascii
import re,os,sys
from random import randint
import unicodedata as ud



class Cifratore:
	"""
		class to encrypt/decrypt with AES
		file and directories, name included
	"""
	key = None
	encryptor = None
	mode = AES.MODE_ECB
	re_encrypted = re.compile('[A-Z0-9]+$')
	pads = 16

	def __init__(self,key,mode=AES.MODE_ECB, pads=16):
		self.key = key + '\0'*(32-len(key))
		self.encryptor = AES.new(self.key, self.mode)

	def encrypt_raw(self,s):
		"""
			encrypt s, previously padding it
		"""
		return self.encryptor.encrypt(self.pad(s))

	def decrypt_raw(self,s):
		"""
			decrypt s and unpad it
		"""
		return self.unpad(self.encryptor.decrypt(s))

	def encrypt(self, s):
		"""
			encrypt a string (simple or unicode)
			after mangling it a bit to be compatible
			with java.crypto encoder/decoder
		"""
		if isinstance(s,unicode):
			s=s.encode("utf-8")
		ps = self.s2us(s)
		ps = self.encrypt_raw(ps)
		return binascii.hexlify(ps).upper()
		
	def decrypt(self, c):
		"""
			encrypt a string (simple or unicode)
			after mangling it a bit to be compatible
			with java.crypto encoder/decoder
		"""
		cleartext = self.decrypt_raw(binascii.unhexlify(c))
		return self.us2s(cleartext)
	
	def pad(self,s):
		l = len(s) % self.pads
		a = chr(self.pads-l) * (self.pads-l)
		return s+a

	def unpad(self,s):
		return s[0:-ord(s[-1])]
	
	def us2s(self,s):
		"""
			convert a string containing unicode data to an unicode string
		"""
		return s.decode("utf-8").encode("unicode-escape").decode("string-escape")	

	def s2us(self,s):
		"""
			convert a string containig special chars to a string 
			containing unicode chars
		"""
		return s.encode("string-escape").decode("unicode-escape").encode("utf-8")



class CryptFile(file):
	__write = file.write
	__read = file.read

	def __init__(self, *args, **kwargs):
		print "args: %s" % [args]
		print "kwargs: %s" % [kwargs]
		name = args[0]
		if "enc" in kwargs:
			self.cifratore = kwargs["enc"]
			name = self.cifratore.encrypt(args[0])
			
        	file.__init__(self, name=name, mode=args[1] )

	def write(self, buff):
		if not self.cifratore:
			return self.__write(buff)	
		
		return self.__write(self.cifratore.encrypt_raw(buff))

	def read(self, size):
		if not self.cifratore:
			return self.__read(size)	
		
		return self.cifratore.decrypt_raw(self.__read(size+self.cifratore.pads-size%self.cifratore.pads))

key = 'secret'
filename = "test.dat"
dest = "test.dat.aes"
def testCryptFile_init():
	e = Cifratore(key=key)
	cfile = CryptFile(dest, "w+", enc=e)
	assert cfile
	cfile.close()

def testCryptFile_read_from_encrypted():
	e = Cifratore(key=key)
	dest=u"però"
	cfile = CryptFile(dest, "w+", enc=e)
	assert cfile
	cfile.write("123456789")
	cfile.close()

	
	rfile = CryptFile(dest, "r", enc=e)
	assert rfile
	buff = rfile.read(10) 
	print "buff: [%s]" % buff
	rfile.close()

def testCryptFile_read_existing():
	e = Cifratore(key=key)
	rfile = CryptFile("LICENSE.txt", "r")
	rfile.cifratore = e
	buff = rfile.read(16*1<<13)
	print "buff: [%s]" % buff
	rfile.close()

def testCryptFile():
	"""
	Encryption is now transparent
	"""
	data = open(filename, "r").read()
	e = Cifratore(key=key)

	# create an encrypted file
	cfile = CryptFile(dest, "w+")
	cfile.cifratore = e
	cfile.write(data)
	cfile.close()

	# check by hand
	data1 = e.decrypt_raw(open(dest,"r").read())
	assert (data1==data)
	os.unlink(dest)
	
def testCryptFile_unencrypted():
	"""
	Encryption is now transparent
	"""
	data = open(filename, "r").read()
	e = None

	# create an encrypted file
	cfile = CryptFile(dest, "w+")
	cfile.cifratore = e
	cfile.write(data)
	cfile.close()

	# check by hand
	data1 = open(dest,"r").read()
	assert (data1==data)
	os.unlink(dest)

def testEncryptFile():
	"""
	Use this test as usage manual
	"""
	e = Cifratore(key=key)

	data = open(filename,"r").read()
	cdata = e.encrypt_raw(data)

	ofd = open(dest,"w")
	ofd.write(cdata)
	ofd.close()

	data1 = e.decrypt_raw(open(dest,"r").read())
	assert (data1==data)
	os.unlink(dest)

def testCryptString():
	for s in ["", "pippo", "Pluto123", "a\nbc" ]:
		e = Cifratore(key=key)
		assert(s == e.decrypt(e.encrypt(s)))
		
def testCryptUnicodeString():
	for s in [u"òàè", "pòàòippo", "Pllòàuto123", "a\òàlnbc" ]:
		e = Cifratore(key=key)
		dec = e.decrypt(e.encrypt(s))
		if isinstance(s,unicode):
			assert(ud.normalize('NFC',s) == ud.normalize('NFC',dec.decode("utf-8")))
		else:
			assert(s==dec)
		
def setUp():
	print "running tests"
	f = open(filename, "w+")
	f.write("a secret message\nfrom ioggstream\n")
	f.close()
def teardown():
	os.unlink(filename)
	print "tests ok"

