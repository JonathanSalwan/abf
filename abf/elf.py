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

from abf.cpu        import *
from abf.elfFlags   import *
from abf.exception  import *
from ctypes         import *
from struct         import unpack_from



class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('e_ident',         c_ubyte * 16),
                    ('e_type',          c_ushort),
                    ('e_machine',       c_ushort),
                    ('e_version',       c_uint),
                    ('e_entry',         c_uint),
                    ('e_phoff',         c_uint),
                    ('e_shoff',         c_uint),
                    ('e_flags',         c_uint),
                    ('e_ehsize',        c_ushort),
                    ('e_phentsize',     c_ushort),
                    ('e_phnum',         c_ushort),
                    ('e_shentsize',     c_ushort),
                    ('e_shnum',         c_ushort),
                    ('e_shstrndx',      c_ushort)
                ]




class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('e_ident',         c_ubyte * 16),
                    ('e_type',          c_ushort),
                    ('e_machine',       c_ushort),
                    ('e_version',       c_uint),
                    ('e_entry',         c_ulonglong),
                    ('e_phoff',         c_ulonglong),
                    ('e_shoff',         c_ulonglong),
                    ('e_flags',         c_uint),
                    ('e_ehsize',        c_ushort),
                    ('e_phentsize',     c_ushort),
                    ('e_phnum',         c_ushort),
                    ('e_shentsize',     c_ushort),
                    ('e_shnum',         c_ushort),
                    ('e_shstrndx',      c_ushort)
                ]




class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('p_type',          c_uint),
                    ('p_offset',        c_uint),
                    ('p_vaddr',         c_uint),
                    ('p_paddr',         c_uint),
                    ('p_filesz',        c_uint),
                    ('p_memsz',         c_uint),
                    ('p_flags',         c_uint),
                    ('p_align',         c_uint)
                ]




class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('p_type',          c_uint),
                    ('p_flags',         c_uint),
                    ('p_offset',        c_ulonglong),
                    ('p_vaddr',         c_ulonglong),
                    ('p_paddr',         c_ulonglong),
                    ('p_filesz',        c_ulonglong),
                    ('p_memsz',         c_ulonglong),
                    ('p_align',         c_ulonglong)
                ]




class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('sh_name',         c_uint),
                    ('sh_type',         c_uint),
                    ('sh_flags',        c_uint),
                    ('sh_addr',         c_uint),
                    ('sh_offset',       c_uint),
                    ('sh_size',         c_uint),
                    ('sh_link',         c_uint),
                    ('sh_info',         c_uint),
                    ('sh_addralign',    c_uint),
                    ('sh_entsize',      c_uint)
                ]




class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ('sh_name',         c_uint),
                    ('sh_type',         c_uint),
                    ('sh_flags',        c_ulonglong),
                    ('sh_addr',         c_ulonglong),
                    ('sh_offset',       c_ulonglong),
                    ('sh_size',         c_ulonglong),
                    ('sh_link',         c_uint),
                    ('sh_info',         c_uint),
                    ('sh_addralign',    c_ulonglong),
                    ('sh_entsize',      c_ulonglong)
                ]




class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('e_ident',         c_ubyte * 16),
                    ('e_type',          c_ushort),
                    ('e_machine',       c_ushort),
                    ('e_version',       c_uint),
                    ('e_entry',         c_uint),
                    ('e_phoff',         c_uint),
                    ('e_shoff',         c_uint),
                    ('e_flags',         c_uint),
                    ('e_ehsize',        c_ushort),
                    ('e_phentsize',     c_ushort),
                    ('e_phnum',         c_ushort),
                    ('e_shentsize',     c_ushort),
                    ('e_shnum',         c_ushort),
                    ('e_shstrndx',      c_ushort)
                ]




class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('e_ident',         c_ubyte * 16),
                    ('e_type',          c_ushort),
                    ('e_machine',       c_ushort),
                    ('e_version',       c_uint),
                    ('e_entry',         c_ulonglong),
                    ('e_phoff',         c_ulonglong),
                    ('e_shoff',         c_ulonglong),
                    ('e_flags',         c_uint),
                    ('e_ehsize',        c_ushort),
                    ('e_phentsize',     c_ushort),
                    ('e_phnum',         c_ushort),
                    ('e_shentsize',     c_ushort),
                    ('e_shnum',         c_ushort),
                    ('e_shstrndx',      c_ushort)
                ]




class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('p_type',          c_uint),
                    ('p_offset',        c_uint),
                    ('p_vaddr',         c_uint),
                    ('p_paddr',         c_uint),
                    ('p_filesz',        c_uint),
                    ('p_memsz',         c_uint),
                    ('p_flags',         c_uint),
                    ('p_align',         c_uint)
                ]




class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('p_type',          c_uint),
                    ('p_flags',         c_uint),
                    ('p_offset',        c_ulonglong),
                    ('p_vaddr',         c_ulonglong),
                    ('p_paddr',         c_ulonglong),
                    ('p_filesz',        c_ulonglong),
                    ('p_memsz',         c_ulonglong),
                    ('p_align',         c_ulonglong)
                ]




class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('sh_name',         c_uint),
                    ('sh_type',         c_uint),
                    ('sh_flags',        c_uint),
                    ('sh_addr',         c_uint),
                    ('sh_offset',       c_uint),
                    ('sh_size',         c_uint),
                    ('sh_link',         c_uint),
                    ('sh_info',         c_uint),
                    ('sh_addralign',    c_uint),
                    ('sh_entsize',      c_uint)
                ]




class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ('sh_name',         c_uint),
                    ('sh_type',         c_uint),
                    ('sh_flags',        c_ulonglong),
                    ('sh_addr',         c_ulonglong),
                    ('sh_offset',       c_ulonglong),
                    ('sh_size',         c_ulonglong),
                    ('sh_link',         c_uint),
                    ('sh_info',         c_uint),
                    ('sh_addralign',    c_ulonglong),
                    ('sh_entsize',      c_ulonglong)
                ]




''' This class parses the ELF '''
class ELF:
    def __init__(self, binary):
        self.__binary    = bytearray(binary)
        self.__ElfHeader = None
        self.__shdr_l    = []
        self.__phdr_l    = []

        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()


    ''' Parse ELF header '''
    def __setHeaderElf(self):
        e_ident = self.__binary[:15]

        ei_class = unpack_from('<B', e_ident[ELFFlags.EI_CLASS:])[0]
        ei_data  = unpack_from('<B', e_ident[ELFFlags.EI_DATA:])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            raise AbfException('ELF.__setHeaderElf() - Bad Arch size')

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            raise AbfException('ELF.__setHeaderElf() - Bad architecture endian')

        if ei_class == ELFFlags.ELFCLASS32:
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.__binary)
        elif ei_class == ELFFlags.ELFCLASS64:
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.__binary)

        self.getArch() # Check if architecture is supported


    ''' Parse Section header '''
    def __setShdr(self):
        shdr_num = self.__ElfHeader.e_shnum
        base = self.__binary[self.__ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = self.__binary[:15]
        ei_data = unpack_from('<B', e_ident[ELFFlags.EI_DATA:])[0]

        for i in range(shdr_num):

            if self.getArchMode() == CpuMode.MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == CpuMode.MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.__shdr_l.append(shdr)
            base = base[self.__ElfHeader.e_shentsize:]

        # setup name from the strings table
        string_table = self.__binary[(self.__shdr_l[self.__ElfHeader.e_shstrndx].sh_offset):]
        for i in range(shdr_num):
            self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split(b'\0')[0]


    ''' Parse Program header '''
    def __setPhdr(self):
        pdhr_num = self.__ElfHeader.e_phnum
        base = self.__binary[self.__ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = self.__binary[:15]
        ei_data = unpack_from('<B', e_ident[ELFFlags.EI_DATA:])[0]

        for i in range(pdhr_num):
            if self.getArchMode() == CpuMode.MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == CpuMode.MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

            self.__phdr_l.append(phdr)
            base = base[self.__ElfHeader.e_phentsize:]


    def getEntryPoint(self):
        return self.__ElfHeader.e_entry


    def getExecSections(self):
        ret = []
        for segment in self.__phdr_l:
            if segment.p_flags & 0x1:
                ret +=  [{
                            'offset'  : segment.p_offset,
                            'size'    : segment.p_memsz,
                            'vaddr'   : segment.p_vaddr,
                            'opcodes' : self.__binary[segment.p_offset:segment.p_offset+segment.p_memsz]
                        }]
        return ret


    def getDataSections(self):
        ret = []
        for section in self.__shdr_l:
            if not (section.sh_flags & 0x4) and (section.sh_flags & 0x2):
                ret +=  [{
                            'name'    : section.str_name,
                            'offset'  : section.sh_offset,
                            'size'    : section.sh_size,
                            'vaddr'   : section.sh_addr,
                            'data'    : self.__binary[section.sh_offset:section.sh_offset+section.sh_size]
                        }]
        return ret


    def getArch(self):
        if self.__ElfHeader.e_machine == ELFFlags.EM_386 or self.__ElfHeader.e_machine == ELFFlags.EM_X86_64:
            return CpuArch.CPU_X86
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
            return CpuArch.CPU_ARM
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
            return CpuArch.CPU_ARM64
        elif self.__ElfHeader.e_machine == ELFFlags.EM_MIPS:
            return CpuArch.CPU_MIPS
        elif self.__ElfHeader.e_machine == ELFFlags.EM_PowerPC:
            return CpuArch.CPU_PPC
        elif self.__ElfHeader.e_machine == ELFFlags.EM_SPARCv8p:
            return CpuArch.CPU_SPARC
        else:
            return CpuArch.CPU_UNKNOWN


    def getArchMode(self):
        if self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32:
            return CpuMode.MODE_32
        elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64:
            return CpuMode.MODE_64
        else:
            return CpuMode.MODE_UNKNOWN


    def getFormat(self):
        return 'ELF'


    @property
    def phdrs(self):
        return self.__phdr_l


    @property
    def shdrs(self):
        return self.__shdr_l


    @property
    def header(self):
        return self.__ElfHeader


