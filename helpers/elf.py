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
##  $ ./helpers/elf.py ./binaries/elf-Linux-ARMv7-ls
##  Entry: 0xc268
##  
##  sh_addr: 0x0
##  sh_addr: 0x8134
##  sh_addr: 0x8148
##  sh_addr: 0x8168
##  sh_addr: 0x818c
##  sh_addr: 0x85a0
##  sh_addr: 0x8e00
##  sh_addr: 0x93e8
##  sh_addr: 0x94f4
##  sh_addr: 0x9584
##  sh_addr: 0x95c4
##  sh_addr: 0x993c
##  sh_addr: 0x9948
##  sh_addr: 0x9e90
##  sh_addr: 0x1a4d0
##  sh_addr: 0x1a4d8
##  sh_addr: 0x1d8c0
##  sh_addr: 0x1d8d8
##  sh_addr: 0x258dc
##  sh_addr: 0x258e0
##  sh_addr: 0x258e4
##  sh_addr: 0x258e8
##  sh_addr: 0x259f0
##  sh_addr: 0x25bc0
##  sh_addr: 0x25cf8
##  sh_addr: 0x0
##  sh_addr: 0x0
##  sh_addr: 0x0
##  
##  p_vaddr: 0x1d8c0
##  p_vaddr: 0x8034
##  p_vaddr: 0x8134
##  p_vaddr: 0x8000
##  p_vaddr: 0x258dc
##  p_vaddr: 0x258e8
##  p_vaddr: 0x8148
##  p_vaddr: 0x0
##  $
##

from    abf.abstract import *
import  sys



if __name__  == '__main__':

    if len(sys.argv) < 2:
        print 'Syntax: %s <binary path>' %(sys.argv[0])
        sys.exit(-1)


    binary = Abstract(sys.argv[1])
    elf = binary.getBinary()

    print 'Entry: %#x\n' %(elf.header.e_entry)

    for shdr in elf.shdrs:
        print 'sh_addr: %#x' %(shdr.sh_addr)

    print 

    for phdr in elf.phdrs:
        print 'p_vaddr: %#x' %(phdr.p_vaddr)


