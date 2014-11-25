Abstract Binary Format 
=======================

Manage your **ELF**, **PE** or **Mach-O** format as an abstraction or more specifically.

Install
-------

    $ sudo ./setup.py install

Example
-------

Via the abstraction :

    >>> from abf.abstract import *                                                                                                                                            
    >>> binary = Abstract('/usr/bin/id')                                                                                                                                      

    >>> binary.getFormat()
    'ELF'
    >>> hex(binary.getEntryPoint())
    '0x4022bcL'

    >>> binary = Abstract('./binaries/pe-Windows-x86-cmd')                                                                                                                    
    >>> binary.getFormat()
    'PE'
    >>> hex(binary.getEntryPoint())
    '0x4ad060dcL'

    >>> binary = Abstract('./binaries/MachO-OSX-x86-ls')                                                                                                                      
    >>> binary.getFormat()
    'Mach-O'
    >>> hex(binary.getEntryPoint())
    '0x1708L'

    >>> sectionsExec = binary.getExecSections()
    >>> len(sectionsExec)
    3
    >>> for sect in sectionsExec:                                                                                                                                             
    ...     print hex(sect['vaddr'])                                                                                                                                          
    ... 
    0x1708L
    0x557cL
    0x5750L

Or more specifically :

    >>> binary = Abstract('/usr/bin/id')                                                                                                                                      
    >>> elf = binary.getBinary()

    >>> elf
    <abf.elf.ELF instance at 0x7ff55c24c290>

    >>> hex(elf.header.e_entry)
    '0x4022bcL'
    
    >>> shdrs = elf.shdrs
    >>> for shdr in shdrs:                                                                                                                                                    
    ...     print hex(shdr.sh_addr)
    ... 
    0x0L
    0x400270L
    0x40028cL
    0x4002b0L
    0x400570L
    0x4005d0L
    0x400c18L
    0x400ebeL
    0x400f48L
    0x400f98L
    0x401028L
    0x4015b0L
    0x4015d0L
    0x401990L
    0x40536cL
    0x405380L
    0x40648cL
    0x4066f8L
    0x607df8L
    0x607e00L
    0x607e08L
    0x607e10L
    0x607ff0L
    0x608000L
    0x608200L
    0x6082a0L
    0x0L

    >>> binary = Abstract('./binaries/MachO-OSX-x86-ls')                                                                                                                      
    >>> macho = binary.getBinary()
    >>> macho
    <abf.macho.MACHO instance at 0x7ff55c27bef0>
    >>> macho.header.cpusubtype                                                                                                                                               
    3L
    >>> hex(macho.header.flags)                                                                                                                                               
    '0x1200085L'
    >>> 

Special thanks
--------------

- Wannes Rombouts (wapiflapi) for python3 compatible.

