#!/usr/bin/python
# coding=utf8
# author robipolli@gmail.com
# License AGPLv3 - http://www.gnu.org/licenses/agpl.html
# This class provides an
# extension of file supporting encryption 
# based on Cifratore
from cryptlib import Cifratore

class CryptFile(file):
    """Prima di sovrascrivere self.read e self.write, li salvo."""
    __write = file.write
    __read = file.read
    __close = file.close

    def __init__(self, *args, **kwargs):
        self.left_byte_buffer = "" 
        print "CryptFile: args: %s" % [args]
        print "kwargs: %s" % [kwargs]
        self.name_cleartext = name = args[0]
        if "enc" in kwargs:
            self.cifratore = kwargs["enc"]
            # encrypt unencrypted filenames
            if self.cifratore and not CryptFile.is_encrypted(args[0]):
              name = self.encrypt_filename(self.name_cleartext, self.cifratore)
                  
        print "file(%s, %s)" % (name, args[1])
        file.__init__(self, name=name, mode=args[1] )

    @staticmethod
    def is_encrypted(filename):
        return Cifratore.re_encrypted.match(filename.split("/")[-1]) != None

    @staticmethod
    def encrypt_filename(filename, cifratore, recur = False):
      """Separately encrypt each part of a filename if recur == True. 
	     encrypt only the last part if recur == False.
	     
	     Before encrypting checks if the filename matches the encrypted pattern.
	     In that case it won't re-encrypt it.
      """
      path = filename.split("/")
      if recur:
          path = [cifratore.encrypt(x) if not CryptFile.is_encrypted(x) else x for x in path]
      else:
          path[-1] = cifratore.encrypt(path[-1])
      return "/".join(path)
          
    @staticmethod
    def decrypt_filename(filename, cifratore, recur = False):
        """Separately decrypt each part of filename if recur == True.
           decrypt only the last part if recur == False """
        try:
            path = filename.split("/")
            if recur:
                path = [cifratore.decrypt(x) if CryptFile.is_encrypted(x) else x for x in path]
            else:
                path[-1] = cifratore.decrypt(path[-1])
            return "/".join(path)
        except Exception as e:
            raise Exception("Error decrypting filename: %s" % filename, e)
        
    def write(self, buff):
        """Write a buffer to the filesystem.
           The buffer must be a multiple of the pad size, otherwise
           the remnant is stored in a buffer and 
           attached to the next write call.
           The last remnant is flushed by the close() call
        """
        if not self.cifratore:
                return self.__write(buff)

        # append the remnant and clean the  buffer
        buff = self.left_byte_buffer + buff
        self.left_byte_buffer = ""
        
        offset = len(buff) % self.cifratore.pads
        # if there's a remnant, put it in self.left_byte_buffer
        if offset:
            (buff, self.left_byte_buffer) = (buff[:-offset], buff[-offset:])

        return self.__write(self.cifratore.encrypt_raw(buff))

    def read(self, size):
        if not self.cifratore:
            return self.__read(size)

        # I have to unpad ONLY if I am at the end of the file!
        # so I could use file.tell()
        offset = (self.cifratore.pads-size%self.cifratore.pads) % self.cifratore.pads
        print "read: %s, offset: %s" % (size,offset)
        data = self.__read(size+offset)

        # am I at EOF?
        eof = 0
        if self.tell() == os.fstat(self.fileno()).st_size:
            eof = 1
        try:
          return self.cifratore.decrypt_raw(data, eof = eof)
        except ValueError:
          return data
    def close(self):
        if len(self.left_byte_buffer):
            print >> sys.stderr, "flushing remnant to file"
            self.__write(self.cifratore.encrypt_raw(self.left_byte_buffer))
            self.left_byte_buffer = ""
        return self.__close()



class TestCryptFile:
  def test_init(self):
    cf = CryptFile("/tmp/unencrypted", "w+")
    assert cf.name_cleartext == "/tmp/unencrypted"
  def test_encrypt_filename_1(self):
    cf = Cifratore(key="secret")
    filename = "simple.txt"
    assert cf.re_encrypted.match(CryptFile.encrypt_filename(filename, cf))
  def test_encrypt_filename_2(self):
    cf = Cifratore(key="secret")
    for filename in ["/one/path/simple.txt", "/path/simple.txt"]:
      ret = CryptFile.encrypt_filename(filename, cf).split("/")
      assert "path" in ret
      assert Cifratore.re_encrypted.match(ret[-1])
  def test_encrypt_filename_1(self):
    cf = Cifratore(key="secret")
    for filename in ["/one/path/simple.txt", "/path/simple.txt"]:
      ret = CryptFile.encrypt_filename(filename, cf, recur = True)
      assert "/" in ret, "ret: %s" % ret
      assert Cifratore.re_encrypted.match(ret.split("/")[1])
  def test_decrypt_filename_1(self):
    cf = Cifratore(key="secret")
    for filename in ["/2619C028E9CDCAFA2249A6CF46D9E6F1/2619C028E9CDCAFA2249A6CF46D9E6F1"]:
      ret = CryptFile.decrypt_filename(filename, cf, recur = True)
      assert "/" in ret, "ret: %s" % ret
      assert not Cifratore.re_encrypted.match(ret.split("/")[1])
