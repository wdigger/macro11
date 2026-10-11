#ifndef ELFOBJ_H
#define ELFOBJ_H

/* ELF debug output, beside the object module.

   -o goes on writing the ordinary RT-11 or RSX object module, which is
   what carries the code; -elf FILE writes, as well, an ELF object that
   holds only what the object module has no room for -- a DWARF line
   table saying which source line each address came from, and an entry
   per symbol of the module saying where it is and where it was written
   down.  Link the two together and the GNU tools have what they need:
   addr2line and gdb read DWARF, and gdb can then step a MACRO-11 source
   line at a time.

   The addresses in that DWARF cannot be written down when the module is
   assembled, since nobody knows yet where the linker will put the
   p-sects.  They are relocations instead, each against a global symbol
   that marks the start of a p-sect -- which is why -elf also makes the
   object module export a global per p-sect.  Where a p-sect already has
   a global of the module's own, that one is used and nothing is
   added.  */

#include <stdio.h>

#include "symbols.h"

/* -elf was given: the object module gains the anchors described below,
   and the ELF file is written at the end.  */
extern int      elf_symbols;

/* The global symbol the DWARF for SECT measures its addresses from, or
   NULL if SECT cannot have one (the blank p-sect, or a name already
   taken by something else).  *BIAS is that symbol's offset in the
   p-sect, and *DEFINE says whether the object module has to define it
   (it does, unless the symbol was the module's own already).  */
const char     *elfobj_anchor(
    SECTION *sect,
    unsigned *bias,
    int *define);

/* Note that SYM was defined at LINE of FILE.  Called as the second
   pass defines it; a symbol defined more than once keeps the last.  */
void            elfobj_sym(
    SYMBOL *sym,
    const char *file,
    int line);

/* Note that the bytes about to be stored at OFFSET in SECT came from
   LINE of FILE.  Called as the second pass stores them.  */
void            elfobj_line(
    SECTION *sect,
    unsigned offset,
    const char *file,
    int line);

/* Write it all out: the symbols, and the DWARF for the lines noted.
   Returns 0 and reports if the file cannot be written.  */
int             elfobj_write(
    FILE *fp);

#endif /* ELFOBJ_H */
