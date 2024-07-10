from elftools.elf import elffile
from elftools.elf.elffile import ELFFile
import sys


with open("sample_exe64.elf",'rb') as f:
    elf = ELFFile(f)
    for section in elf.iter_sections():
        if section.name.startswith('.debug'):
            print('  ' + section.name)
