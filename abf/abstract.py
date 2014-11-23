#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-11-23
## 
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.
##


from abf.elf        import *
from abf.exception  import *
from abf.macho      import *
from abf.pe         import *



class Abstract(object):

    def __init__(self, binary):
        self.__fileName  = binary
        self.__rawBinary = None
        self.__binary    = None
        
        try:
            fd = open(self.__fileName, 'rb')
            self.__rawBinary = fd.read()
            fd.close()
        except:
            raise AbfException('Can\'t open the binary or binary not found')

        if self.__rawBinary[:4] == '7f454c46'.decode('hex'):
             self.__binary = ELF(self.__rawBinary)

        elif self.__rawBinary[:2] == '4d5a'.decode('hex'):
             self.__binary = PE(self.__rawBinary)

        #elif self.__rawBinary[:4] == 'cafebabe'.decode('hex'):
        #     self.__binary = UNIVERSAL(self.__rawBinary)

        elif self.__rawBinary[:4] == 'cefaedfe'.decode('hex') or self.__rawBinary[:4] == 'cffaedfe'.decode('hex'):
             self.__binary = MACHO(self.__rawBinary)

        else:
            raise AbfException('Binary format not supported')


    def getFileName(self):
        return self.__fileName


    def getRawBinary(self):
        return self.__rawBinary


    def getBinary(self):
        return self.__binary


    def getEntryPoint(self):
        return self.__binary.getEntryPoint()


    def getDataSections(self):
        return self.__binary.getDataSections()


    def getExecSections(self):
        return self.__binary.getExecSections()


    def getArch(self):
        return self.__binary.getArch()


    def getArchMode(self):
        return self.__binary.getArchMode()


    def getFormat(self):
        return self.__binary.getFormat()


