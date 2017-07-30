import sys

class OutLogger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")
 
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stderr
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)




#===============================================================================
# sys.stdout = Logger("output_file2.txt")
# print "Hello world !" # this is should be saved in yourlogfilename.txt
# 
# sys.stdout = sys.__stdout__
# 
# sys.stdout = Logger("output_file3.txt" )
# print "Hello world !" # this is should be saved in yourlogfilename.txt
#===============================================================================