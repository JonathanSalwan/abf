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
##
##  $ ./helpers/abstract.py ./binaries/MachO-OSX-x86-ls
##  == Format ==
##    Format : Mach-O
##    Arch   : 0
##    Mode   : 0
##  == Header ==
##    Entry point : 0x1708
##  == Exec sections ==
##    vaddr   : 0x1708
##    size    : 0x3e74
##    offset  : 0x708
##    opcodes : ['j', '\x00', '\x89', '\xe5', '\x83', '\xe4'] ...
##    vaddr   : 0x557c
##    size    : 0x1d4
##    offset  : 0x457c
##    opcodes : ['\xff', '%', '\xec', '`', '\x00', '\x00'] ...
##    vaddr   : 0x5750
##    size    : 0x318
##    offset  : 0x4750
##    opcodes : ['h', '\x00', '\x00', '\x00', '\x00', '\xe9'] ...
##  
##  == Data sections ==
##  
##    vaddr   : 0x5a68
##    size    : 0x550
##    offset  : 0x4a68
##    data    : ['$', 'F', 'r', 'e', 'e', 'B'] ...
##  
##    vaddr   : 0x5fb8
##    size    : 0x48
##    offset  : 0x4fb8
##    data    : ['\x01', '\x00', '\x00', '\x00', '\x1c', '\x00'] ...
##  
##    vaddr   : 0x6000
##    size    : 0x14
##    offset  : 0x5000
##    data    : ['\x00', '\x10', '\x00', '\x00', '\\', 'c'] ...
##  
##    vaddr   : 0x6014
##    size    : 0xd8
##    offset  : 0x5014
##    data    : ['\x00', '\x00', '\x00', '\x00', '\x00', '\x00'] ...
##  
##    vaddr   : 0x60ec
##    size    : 0x138
##    offset  : 0x50ec
##    data    : ['P', 'W', '\x00', '\x00', 'Z', 'W'] ...
##  
##    vaddr   : 0x6224
##    size    : 0x18
##    offset  : 0x5224
##    data    : ['P', '\x00', '\x00', '\x00', '0', 'b'] ...
##  
##    vaddr   : 0x6240
##    size    : 0x11c
##    offset  : 0x5240
##    data    : ['\x02', '\x00', '\x00', '\x00', '\x9f', ']'] ...
##  
##    vaddr   : 0x635c
##    size    : 0x84
##    offset  : 0x0
##    data    : ['\xce', '\xfa', '\xed', '\xfe', '\x07', '\x00'] ...
##  
##    vaddr   : 0x63e0
##    size    : 0xac
##    offset  : 0x0
##    data    : ['\xce', '\xfa', '\xed', '\xfe', '\x07', '\x00'] ...
##
##

from    abf.abstract import *
import  sys



if __name__  == '__main__':

    if len(sys.argv) < 2:
        print 'Syntax: %s <binary path>' %(sys.argv[0])
        sys.exit(-1)

    binary = Abstract(sys.argv[1])

    print '== Format ==\n'

    print '  Format : %s' %(binary.getFormat())
    print '  Arch   : %s' %(binary.getArch())
    print '  Mode   : %s' %(binary.getArchMode())

    print '\n== Header ==\n'

    print '  Entry point : %#x' %(binary.getEntryPoint())

    print '\n== Exec sections ==\n'

    for sect in binary.getExecSections():
        print '  vaddr   : %#x' %(sect['vaddr'])
        print '  size    : %#x' %(sect['size'])
        print '  offset  : %#x' %(sect['offset'])
        print '  opcodes : %s ...' %(list(sect['opcodes'][0:6]))
        print

    print '\n== Data sections ==\n'

    for sect in binary.getDataSections():
        print '  vaddr   : %#x' %(sect['vaddr'])
        print '  size    : %#x' %(sect['size'])
        print '  offset  : %#x' %(sect['offset'])
        print '  data    : %s ...' %(list(sect['data'][0:6]))
        print

    sys.exit(0)


