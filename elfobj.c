/* elfobj.c -- write the module's symbols and line numbers as an ELF
   object, beside the object module itself.

   -o writes the RT-11 or RSX object module as it always did, and that
   is what carries the code; -elf FILE writes this as well, holding what
   the object module has no room for: a DWARF line table saying which
   source line each address came from, and an entry per symbol of the
   module saying where it is and where it was written down.  Link the
   two together and addr2line and gdb have what they need -- gdb can
   step the MACRO-11 source a line at a time, and name and print what
   the module declared.

   The symbols are DWARF entries and not ELF symbols because an ELF
   symbol's value is an offset into a section of the file that defines
   it, and the sections of this file are empty -- the object module's
   p-sects are the real ones.  A DWARF address, on the other hand, is a
   relocation like any other, and the linker fills it in.

   None of those addresses can be written down when the module is
   assembled, since nobody knows yet where the p-sects will go.  Each is
   a relocation against a global symbol at the start of its p-sect,
   which is what the extra globals in the object module are for; see
   elfobj_anchor.

   The file is written byte by byte through buffers of its own rather
   than by dumping structs, so that nothing depends on this host's idea
   of struct padding or byte order; the assembler itself runs on
   anything from a VAX to a PC.  */

#include <stdlib.h>
#include <string.h>

#include "elfobj.h"
#include "assemble_globals.h"
#include "object.h"
#include "listing.h"
#include "util.h"

int             elf_symbols = 0;

/* ELF, as much of it as this needs.  */

#define EI_NIDENT	16
#define ELFCLASS32	1
#define ELFDATA2LSB	1
#define EV_CURRENT	1
#define ET_REL		1
#define EM_PDP11	65
#define EHDR_SIZE	52
#define SHDR_SIZE	40
#define SYM_SIZE	16
#define RELA_SIZE	12

#define SHN_UNDEF	0
#define SHN_ABS		0xfff1

#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_NOBITS	8

#define STB_LOCAL	0
#define STB_GLOBAL	1
#define STB_WEAK	2

#define STT_NOTYPE	0
#define STT_SECTION	3
#define STT_FILE	4

#define ELF_ST_INFO(bind, type)	(((bind) << 4) | ((type) & 0xf))
#define ELF32_R_INFO(sym, type)	(((unsigned long) (sym) << 8) | ((type) & 0xff))

/* The one relocation this writes: a 32-bit address, taken from the
   symbol plus the addend in the entry (the field itself is left at
   zero -- R_PDP11_32 is not partial_inplace).  */
#define R_PDP11_32	4

/* DWARF, likewise.  The line table is version 2, which is the simplest
   form every reader still understands, and the compilation unit is
   version 4, which is the last one whose address ranges are a list in
   .debug_ranges -- a form that needs nothing but the relocations this
   can write.  */

#define DW_TAG_compile_unit	0x11
#define DW_TAG_base_type	0x24
#define DW_TAG_variable		0x34

#define DW_AT_location		0x02
#define DW_AT_name		0x03
#define DW_AT_byte_size		0x0b
#define DW_AT_stmt_list		0x10
#define DW_AT_low_pc		0x11
#define DW_AT_high_pc		0x12
#define DW_AT_comp_dir		0x1b
#define DW_AT_const_value	0x1c
#define DW_AT_producer		0x25
#define DW_AT_decl_file		0x3a
#define DW_AT_decl_line		0x3b
#define DW_AT_encoding		0x3e
#define DW_AT_external		0x3f
#define DW_AT_type		0x49
#define DW_AT_ranges		0x55

#define DW_FORM_addr		0x01
#define DW_FORM_data1		0x0b
#define DW_FORM_flag		0x0c
#define DW_FORM_sdata		0x0d
#define DW_FORM_udata		0x0f
#define DW_FORM_ref4		0x13
#define DW_FORM_string		0x08
#define DW_FORM_exprloc		0x18
#define DW_FORM_sec_offset	0x17

#define DW_ATE_signed		0x05

#define DW_OP_addr		0x03

/* The abbreviation codes this writes, in the order .debug_abbrev
   defines them.  */
#define ABBREV_CU		1
#define ABBREV_WORD		2
#define ABBREV_VARIABLE		3
#define ABBREV_CONSTANT		4

#define DW_LNS_copy		0x01
#define DW_LNS_advance_pc	0x02
#define DW_LNS_advance_line	0x03
#define DW_LNS_set_file		0x04
#define DW_LNE_end_sequence	0x01
#define DW_LNE_set_address	0x02

#define DWARF_LINE_BASE		(-5)
#define DWARF_LINE_RANGE	14
#define DWARF_OPCODE_BASE	13

/* Room for one more item in a growing array of COUNT items of SIZE,
   *ALLOCATED of which are there already.  Everything this writes is of
   a length the source decides, and a limit of its own would be a limit
   on the program being assembled.  */

static void *grow(
    void *data,
    unsigned count,
    unsigned *allocated,
    size_t size)
{
    if (count < *allocated)
        return data;

    *allocated = *allocated != 0 ? *allocated * 2 : 64;
    return memcheck(realloc(data, *allocated * size));
}

/* A growing buffer of bytes, with the relocations that belong to what
   is in it.  */

struct reloc {
    unsigned        offset;     /* Where in the buffer */
    unsigned        sym;        /* Symbol index, filled in later */
    unsigned long   addend;
    int             anchor;     /* Which anchor, or -1 for a section */
    int             section;    /* Which section symbol, or -1 */
};

struct buf {
    unsigned char  *data;
    unsigned        allocated;
    unsigned        size;
    struct reloc   *relocs;
    unsigned        nrelocs;
    unsigned        allocrelocs;
};

static void buf_init(
    struct buf *b)
{
    b->allocated = 256;
    b->data = memcheck(malloc(b->allocated));
    b->size = 0;
    b->relocs = NULL;
    b->nrelocs = 0;
    b->allocrelocs = 0;
}

static void buf_free(
    struct buf *b)
{
    free(b->data);
    b->data = NULL;
    free(b->relocs);
    b->relocs = NULL;
}

static void buf_u8(
    struct buf *b,
    unsigned v)
{
    if (b->size + 1 > b->allocated) {
        b->allocated *= 2;
        b->data = memcheck(realloc(b->data, b->allocated));
    }
    b->data[b->size++] = (unsigned char) (v & 0xff);
}

static void buf_u16(
    struct buf *b,
    unsigned v)
{
    buf_u8(b, v);
    buf_u8(b, v >> 8);
}

static void buf_u32(
    struct buf *b,
    unsigned long v)
{
    buf_u8(b, (unsigned) v);
    buf_u8(b, (unsigned) (v >> 8));
    buf_u8(b, (unsigned) (v >> 16));
    buf_u8(b, (unsigned) (v >> 24));
}

static void buf_uleb(
    struct buf *b,
    unsigned long v)
{
    do {
        unsigned        byte = (unsigned) (v & 0x7f);

        v >>= 7;
        buf_u8(b, v != 0 ? (byte | 0x80) : byte);
    } while (v != 0);
}

static void buf_sleb(
    struct buf *b,
    long v)
{
    int             more = 1;

    while (more) {
        unsigned        byte = (unsigned) (v & 0x7f);

        v >>= 7;                /* Arithmetic, so the sign comes along */
        if ((v == 0 && !(byte & 0x40)) || (v == -1 && (byte & 0x40)))
            more = 0;
        else
            byte |= 0x80;
        buf_u8(b, byte);
    }
}

static void buf_str(
    struct buf *b,
    const char *s)
{
    while (*s != '\0')
        buf_u8(b, (unsigned char) *s++);
    buf_u8(b, 0);
}

/* Note that the four bytes about to be written are an address the
   linker has to fill in.  ANCHOR is the p-sect anchor it is measured
   from, or -1 when SECTION names a section symbol instead (for the
   offsets inside the debug sections themselves).  */

static void buf_reloc32(
    struct buf *b,
    int anchor,
    int section,
    long addend)
{
    b->relocs = grow(b->relocs, b->nrelocs, &b->allocrelocs,
                     sizeof(*b->relocs));
    b->relocs[b->nrelocs].offset = b->size;
    b->relocs[b->nrelocs].anchor = anchor;
    b->relocs[b->nrelocs].section = section;
    b->relocs[b->nrelocs].addend = (unsigned long) addend;
    b->nrelocs++;
    buf_u32(b, 0);              /* R_PDP11_32 takes the value from the
                                   relocation, not from here */
}

/* A halfword or word at a fixed place in a buffer already written.  */

static void put16_at(
    unsigned char *p,
    unsigned at,
    unsigned v)
{
    p[at] = (unsigned char) (v & 0xff);
    p[at + 1] = (unsigned char) ((v >> 8) & 0xff);
}

static void put32_at(
    unsigned char *p,
    unsigned at,
    unsigned long v)
{
    p[at] = (unsigned char) (v & 0xff);
    p[at + 1] = (unsigned char) ((v >> 8) & 0xff);
    p[at + 2] = (unsigned char) ((v >> 16) & 0xff);
    p[at + 3] = (unsigned char) ((v >> 24) & 0xff);
}

/* A string table being built.  */

struct strtab {
    char           *data;
    unsigned        allocated;
    unsigned        size;
};

static void strtab_init(
    struct strtab *st)
{
    st->allocated = 256;
    st->data = memcheck(malloc(st->allocated));
    st->data[0] = '\0';
    st->size = 1;               /* Index 0 is the empty name */
}

static unsigned strtab_add(
    struct strtab *st,
    const char *name)
{
    unsigned        len = (unsigned) strlen(name) + 1;
    unsigned        at = st->size;

    while (st->size + len > st->allocated) {
        st->allocated *= 2;
        st->data = memcheck(realloc(st->data, st->allocated));
    }
    memcpy(st->data + at, name, len);
    st->size += len;
    return at;
}

static void strtab_free(
    struct strtab *st)
{
    free(st->data);
    st->data = NULL;
}

/* The p-sects this file will mention, in the order the module declared
   them, and for each the global its addresses are measured from.  */

/* As many as macro11 itself can have; see sections[] there.  */
#define MAX_SECTS	256

struct elf_sect {
    SECTION        *sect;
    int             shndx;      /* Its section header's index */
    unsigned        nameoff;    /* Its name in .shstrtab */
    const char     *anchor;     /* The global, or NULL */
    int             anchordef;  /* Whether it is one this added */
    unsigned        bias;       /* The anchor's offset in the p-sect */
    int             anchorsym;  /* The anchor's symbol index */
    int             haslines;   /* Any line of the source stored here */
    int             hassyms;    /* Any symbol of the module defined here */
};

static struct elf_sect sects[MAX_SECTS];
static int      nsects = 0;

/* One line the second pass stored bytes for.  */

struct dbg_row {
    SECTION        *sect;
    unsigned        offset;
    int             file;       /* Index into files below, from 1 */
    int             line;
};

static struct dbg_row *rows = NULL;
static unsigned nrows = 0;
static unsigned allocrows = 0;

static const char **files = NULL;
static unsigned nfiles = 0;
static unsigned allocfiles = 0;

/* Where a symbol was defined.  Kept here rather than in the symbol
   table, which has no room for it, and by pointer, since that is what
   the symbol table hands out and what elfobj_write walks.  */

struct symplace {
    SYMBOL         *sym;
    int             file;
    int             line;
};

static struct symplace *symplaces = NULL;
static unsigned nsymplaces = 0;
static unsigned allocsymplaces = 0;

static int file_index(
    const char *name)
{
    unsigned        i;

    if (name == NULL)
        name = "?";

    for (i = 0; i < nfiles; i++)
        if (strcmp(files[i], name) == 0)
            return (int) i + 1; /* DWARF 2 counts file names from one */

    files = grow(files, nfiles, &allocfiles, sizeof(*files));
    files[nfiles++] = memcheck(strdup(name));
    return (int) nfiles;
}

/* A name for a p-sect's anchor that nothing else is likely to have.
   The p-sect's own name would be the obvious choice and is the wrong
   one: two modules with a .PSECT DATA apiece would both define DATA,
   and the linker would refuse the pair.  So the name is made from this
   module's name and the p-sect's, which together are unique in a
   program, squeezed into the six characters an object module's symbol
   has room for.  The leading dollar says it is none of the programmer's
   doing.  */

static const char *anchor_name(
    SECTION *sect)
{
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char            name[8];
    int             tries;

    for (tries = 0; tries < 36; tries++) {
        unsigned long   hash = 2166136261UL;
        const char     *cp;
        int             i;

        for (cp = module_name; cp != NULL && *cp != '\0'; cp++)
            hash = (hash ^ (unsigned char) *cp) * 16777619UL;
        for (cp = sect->label; cp != NULL && *cp != '\0'; cp++)
            hash = (hash ^ (unsigned char) *cp) * 16777619UL;
        hash = (hash ^ (unsigned) tries) * 16777619UL;

        name[0] = '$';
        for (i = 1; i <= 5; i++) {
            name[i] = chars[hash % (sizeof(chars) - 1)];
            hash /= sizeof(chars) - 1;
        }
        name[6] = '\0';

        /* A name the module itself uses would be this module's own
           symbol, not an anchor; try the next one along.  */
        if (lookup_sym(name, &symbol_st) == NULL)
            return memcheck(strdup(name));
    }

    return NULL;
}

const char *elfobj_anchor(
    SECTION *sect,
    unsigned *bias,
    int *define)
{
    SYMBOL_ITER     iter;
    SYMBOL         *sym;
    SYMBOL         *best = NULL;

    *bias = 0;
    *define = 0;

    if (sect == NULL || sect == &absolute_section)
        return NULL;

    /* A p-sect with nothing in it has no addresses to describe, and
       wants no symbol of its own in the object module.  */
    if (sect->size == 0)
        return NULL;

    /* A global of this module defined in this p-sect does the job
       without any symbol being added: the linker knows where it ends up
       and so, from it, where the p-sect does.  The lowest one, and of
       several at the same place the first by name, so that both passes
       pick the same symbol.  */
    for (sym = first_sym(&symbol_st, &iter); sym != NULL;
         sym = next_sym(&symbol_st, &iter)) {
        if (sym->section != sect)
            continue;
        if ((sym->flags & (SYMBOLFLAG_GLOBAL | SYMBOLFLAG_DEFINITION))
            != (SYMBOLFLAG_GLOBAL | SYMBOLFLAG_DEFINITION))
            continue;
        if (best == NULL
            || sym->value < best->value
            || (sym->value == best->value
                && strcmp(sym->label, best->label) < 0))
            best = sym;
    }

    if (best != NULL) {
        *bias = best->value;
        return best->label;
    }

    /* None, so the object module defines one at the p-sect's start.  */
    *define = 1;
    return anchor_name(sect);
}

void elfobj_sym(
    SYMBOL *sym,
    const char *file,
    int line)
{
    unsigned        i;

    /* As with the lines, the second pass is the one to believe.  */
    if (pass != PASS2)
        return;
    if (sym == NULL || line <= 0)
        return;

    for (i = 0; i < nsymplaces; i++)
        if (symplaces[i].sym == sym)
            break;

    if (i == nsymplaces) {
        symplaces = grow(symplaces, nsymplaces, &allocsymplaces,
                         sizeof(*symplaces));
        symplaces[nsymplaces++].sym = sym;
    }

    symplaces[i].file = file_index(file);
    symplaces[i].line = line;
}

void elfobj_line(
    SECTION *sect,
    unsigned offset,
    const char *file,
    int line)
{
    static SECTION *last_sect = NULL;
    static int      last_line = -1;
    static int      last_file = -1;
    int             fileidx;

    /* The storing helpers run on both passes; the second is the one
       whose addresses are final.  */
    if (pass != PASS2)
        return;
    if (sect == NULL || sect == &absolute_section || line <= 0)
        return;

    fileidx = file_index(file);

    /* One row per statement that stored anything: the same line storing
       word after word needs saying once.  */
    if (sect == last_sect && line == last_line && fileidx == last_file)
        return;

    rows = grow(rows, nrows, &allocrows, sizeof(*rows));
    rows[nrows].sect = sect;
    rows[nrows].offset = offset;
    rows[nrows].file = fileidx;
    rows[nrows].line = line;
    nrows++;

    last_sect = sect;
    last_line = line;
    last_file = fileidx;
}

/* A p-sect's name as a section name.  */

static const char *sect_name(
    SECTION *sect)
{
    if (sect->label == NULL || sect->label[0] == '\0')
        return ". BLANK.";
    return sect->label;
}

/* Does this symbol belong in the table?

   Only the ones the object module does not already carry.  A global is
   in the module's GSD, and the linker takes it from there; writing it
   here as well would be a second definition of the same name, which the
   linker reports and stops on.  What the object module has no room for
   is everything else -- every label that was never .GLOBL'd and every
   symbol defined with `=' -- and that is what this file is for.

   Left out as well: local labels (10$), which are per-block
   scaffolding, DOT, which is the assembler's own, and anything living
   in one of the assembler's internal sections (instructions,
   pseudo-ops, registers, macros), which is nothing an object file
   describes.  */

/* The symbols worth describing: what the module defined itself, in a
   p-sect or as a plain value.  A local label (10$) is left out -- there
   is one of those per block and the name says nothing on its own -- and
   so is anything the module only referred to, or that belongs to the
   assembler rather than the program (a register, a macro, ".").  */

static int symbol_wanted(
    SYMBOL *sym)
{
    if (sym->section == NULL)
        return 0;
    if (sym->flags & (SYMBOLFLAG_LOCAL | SYMBOLFLAG_UNDEFINED))
        return 0;
    if (SYM_IS_IMPORTED(sym))
        return 0;
    if (sym->section->type != SECTION_USER
        && sym->section != &blank_section
        && sym->section != &absolute_section)
        return 0;
    if (strcmp(sym->label, ".") == 0)
        return 0;

    return 1;
}

/* Which of the p-sects above SECT is, or -1 if it is not one of them
   (the absolute section, or one left out for want of an anchor).  */

static int sect_index(
    SECTION *sect)
{
    int             i;

    for (i = 0; i < nsects; i++)
        if (sects[i].sect == sect)
            return i;

    return -1;
}

/* Where SYM was written down, as a file and a line for the DWARF to
   carry.  Where the definition was seen, if that was noted; otherwise
   the line whose bytes start where the symbol points, since a label
   stands in front of what it labels, falling back to the line before
   that and then to the first line of the module.  */

static void symbol_where(
    SYMBOL *sym,
    unsigned long *file,
    unsigned long *line)
{
    unsigned        i;
    long            best = -1;

    *file = 1;
    *line = 0;

    for (i = 0; i < nsymplaces; i++)
        if (symplaces[i].sym == sym) {
            *file = (unsigned long) symplaces[i].file;
            *line = (unsigned long) symplaces[i].line;
            return;
        }

    for (i = 0; i < nrows; i++) {
        if (rows[i].sect != sym->section)
            continue;
        if (rows[i].offset == sym->value) {
            best = (long) i;
            break;
        }
        if (rows[i].offset < sym->value
            && (best < 0 || rows[i].offset > rows[best].offset))
            best = (long) i;
    }

    if (best < 0 && nrows > 0)
        best = 0;

    if (best >= 0) {
        *file = (unsigned long) rows[best].file;
        *line = (unsigned long) rows[best].line;
    }
}

/* The DWARF line table: one unit for the module, holding a sequence of
   rows per p-sect that any line was stored in.  One unit, because the
   module is one source file and a reader expects a file's lines in one
   place; separate sequences, because the p-sects end up wherever the
   linker puts them and a sequence covers one stretch of addresses.  */

static void build_line_table(
    struct buf *line)
{
    unsigned        unit_start,
                    header_start;
    int             i;
    unsigned        j;

    unit_start = line->size;
    buf_u32(line, 0);           /* unit_length, filled in below */
    buf_u16(line, 2);           /* version */
    header_start = line->size;
    buf_u32(line, 0);           /* header_length, likewise */
    buf_u8(line, 1);            /* minimum_instruction_length */
    buf_u8(line, 1);            /* default_is_stmt */
    buf_u8(line, (unsigned) (DWARF_LINE_BASE & 0xff));
    buf_u8(line, DWARF_LINE_RANGE);
    buf_u8(line, DWARF_OPCODE_BASE);
    buf_u8(line, 0);            /* The twelve standard opcodes' operand */
    buf_u8(line, 1);            /* counts, in order */
    buf_u8(line, 1);
    buf_u8(line, 1);
    buf_u8(line, 1);
    buf_u8(line, 0);
    buf_u8(line, 0);
    buf_u8(line, 0);
    buf_u8(line, 1);
    buf_u8(line, 0);
    buf_u8(line, 0);
    buf_u8(line, 1);
    buf_u8(line, 0);            /* No include directories */
    for (j = 0; j < nfiles; j++) {
        buf_str(line, files[j]);
        buf_uleb(line, 0);      /* In no directory */
        buf_uleb(line, 0);      /* Of no date */
        buf_uleb(line, 0);      /* And no length */
    }
    buf_u8(line, 0);            /* End of the file names */

    /* header_length counts from after its own field.  */
    put32_at(line->data, header_start, line->size - header_start - 4);

    for (i = 0; i < nsects; i++) {
        unsigned        addr = 0;
        int             cur_line = 1,
                        cur_file = 1,
                        first = 1;

        if (!sects[i].haslines)
            continue;

        for (j = 0; j < nrows; j++) {
            if (rows[j].sect != sects[i].sect)
                continue;

            if (first) {
                /* The one address in the sequence the linker has to
                   supply: everything after it is a step from here.  */
                buf_u8(line, 0);        /* An extended opcode */
                buf_uleb(line, 5);      /* of five bytes */
                buf_u8(line, DW_LNE_set_address);
                buf_reloc32(line, i, -1,
                            (long) rows[j].offset - (long) sects[i].bias);
                addr = rows[j].offset;
                first = 0;
            } else if (rows[j].offset != addr) {
                buf_u8(line, DW_LNS_advance_pc);
                buf_uleb(line, rows[j].offset - addr);
                addr = rows[j].offset;
            }

            if (rows[j].file != cur_file) {
                buf_u8(line, DW_LNS_set_file);
                buf_uleb(line, (unsigned long) rows[j].file);
                cur_file = rows[j].file;
            }
            if (rows[j].line != cur_line) {
                buf_u8(line, DW_LNS_advance_line);
                buf_sleb(line, rows[j].line - cur_line);
                cur_line = rows[j].line;
            }
            buf_u8(line, DW_LNS_copy);
        }

        /* The end of the sequence sits at the end of the p-sect, so
           that the last row covers the bytes it belongs to.  */
        if (sects[i].sect->size > addr) {
            buf_u8(line, DW_LNS_advance_pc);
            buf_uleb(line, sects[i].sect->size - addr);
        }
        buf_u8(line, 0);
        buf_uleb(line, 1);
        buf_u8(line, DW_LNE_end_sequence);
    }

    /* unit_length counts from after its own field.  */
    put32_at(line->data, unit_start, line->size - unit_start - 4);
}

/* .debug_ranges: the stretches of address the compilation unit covers,
   one per p-sect with lines in it.  The unit needs them because its
   p-sects are scattered by the linker and a single low_pc and high_pc
   could not describe that; they are relative to the unit's DW_AT_low_pc,
   which is why that is written as a plain zero.  */

static void build_ranges(
    struct buf *ranges)
{
    int             i;

    for (i = 0; i < nsects; i++) {
        if (!sects[i].haslines)
            continue;
        buf_reloc32(ranges, i, -1, -(long) sects[i].bias);
        buf_reloc32(ranges, i, -1,
                    (long) sects[i].sect->size - (long) sects[i].bias);
    }

    buf_u32(ranges, 0);         /* The pair of zeroes that ends a list */
    buf_u32(ranges, 0);
}

/* .debug_abbrev: the shapes of the entries .debug_info writes -- the
   compilation unit, the one type the module's values have, a symbol
   that stands at an address and a symbol that is just a number.

   A symbol in an instruction p-sect is written like any other, and not
   as the DW_TAG_label it names: a label outside a subprogram is one gdb
   reads and then drops, and MACRO-11 has no subprograms to put them in.
   So every symbol of the module is a word in storage, which is all the
   object module ever says about one.  */

static void build_abbrev(
    struct buf *abbrev)
{
    buf_uleb(abbrev, ABBREV_CU);
    buf_uleb(abbrev, DW_TAG_compile_unit);
    buf_u8(abbrev, 1);          /* With children: the symbols */
    buf_uleb(abbrev, DW_AT_name);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_producer);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_comp_dir);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_low_pc);
    buf_uleb(abbrev, DW_FORM_addr);
    buf_uleb(abbrev, DW_AT_ranges);
    buf_uleb(abbrev, DW_FORM_sec_offset);
    buf_uleb(abbrev, DW_AT_stmt_list);
    buf_uleb(abbrev, DW_FORM_sec_offset);
    buf_uleb(abbrev, 0);
    buf_uleb(abbrev, 0);

    /* The one type: a PDP-11 word.  Every symbol of the module is one,
       there being nothing in the object module to say otherwise, and a
       reader that wants to print a value has to be told its size.  */
    buf_uleb(abbrev, ABBREV_WORD);
    buf_uleb(abbrev, DW_TAG_base_type);
    buf_u8(abbrev, 0);
    buf_uleb(abbrev, DW_AT_name);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_byte_size);
    buf_uleb(abbrev, DW_FORM_data1);
    buf_uleb(abbrev, DW_AT_encoding);
    buf_uleb(abbrev, DW_FORM_data1);
    buf_uleb(abbrev, 0);
    buf_uleb(abbrev, 0);

    buf_uleb(abbrev, ABBREV_VARIABLE);
    buf_uleb(abbrev, DW_TAG_variable);
    buf_u8(abbrev, 0);
    buf_uleb(abbrev, DW_AT_name);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_decl_file);
    buf_uleb(abbrev, DW_FORM_udata);
    buf_uleb(abbrev, DW_AT_decl_line);
    buf_uleb(abbrev, DW_FORM_udata);
    buf_uleb(abbrev, DW_AT_type);
    buf_uleb(abbrev, DW_FORM_ref4);
    buf_uleb(abbrev, DW_AT_external);
    buf_uleb(abbrev, DW_FORM_flag);
    buf_uleb(abbrev, DW_AT_location);
    buf_uleb(abbrev, DW_FORM_exprloc);
    buf_uleb(abbrev, 0);
    buf_uleb(abbrev, 0);

    buf_uleb(abbrev, ABBREV_CONSTANT);
    buf_uleb(abbrev, DW_TAG_variable);
    buf_u8(abbrev, 0);
    buf_uleb(abbrev, DW_AT_name);
    buf_uleb(abbrev, DW_FORM_string);
    buf_uleb(abbrev, DW_AT_decl_file);
    buf_uleb(abbrev, DW_FORM_udata);
    buf_uleb(abbrev, DW_AT_decl_line);
    buf_uleb(abbrev, DW_FORM_udata);
    buf_uleb(abbrev, DW_AT_type);
    buf_uleb(abbrev, DW_FORM_ref4);
    buf_uleb(abbrev, DW_AT_external);
    buf_uleb(abbrev, DW_FORM_flag);
    buf_uleb(abbrev, DW_AT_const_value);
    buf_uleb(abbrev, DW_FORM_sdata);
    buf_uleb(abbrev, 0);
    buf_uleb(abbrev, 0);

    buf_uleb(abbrev, 0);        /* End of the abbreviations */
}

/* .debug_info: the compilation unit, naming the source file and
   pointing at the line table and the ranges above, and under it the
   module's own symbols.

   The symbols are here, and not in the ELF symbol table, because a
   symbol's value there is an offset into one of this file's sections
   and this file's sections hold nothing -- the object module's p-sects
   are the real ones, and a linker has no reason to believe the two are
   the same.  An address in DWARF is a relocation like any other, so
   this way the linker fills them in.  */

static void build_info(
    struct buf *info,
    int abbrev_sect,
    int line_sect,
    int ranges_sect)
{
    unsigned        unit_start,
                    word_off;
    SYMBOL_ITER     iter;
    SYMBOL         *sym;
    int             i;

    unit_start = info->size;
    buf_u32(info, 0);           /* unit_length, filled in below */
    buf_u16(info, 4);           /* version */
    buf_reloc32(info, -1, abbrev_sect, 0);      /* debug_abbrev_offset */
    buf_u8(info, 4);            /* address_size */

    buf_uleb(info, ABBREV_CU);
    buf_str(info, nfiles > 0 ? files[0] : "?");
    buf_str(info, "macro11");
    buf_str(info, ".");
    buf_u32(info, 0);           /* low_pc: the ranges are absolute */
    buf_reloc32(info, -1, ranges_sect, 0);
    buf_reloc32(info, -1, line_sect, 0);

    word_off = info->size - unit_start;
    buf_uleb(info, ABBREV_WORD);
    buf_str(info, "word");
    buf_u8(info, 2);
    buf_u8(info, DW_ATE_signed);

    /* An anchor this put in the object module is a symbol of the
       program like any other now, and the only one at the start of its
       p-sect; without an entry of its own, an address there would be
       named after it and then found nowhere.  It is given the place of
       whatever the module itself has there.  */
    for (i = 0; i < nsects; i++) {
        unsigned long   file = 1,
                        line = 0;
        unsigned        j;

        if (!sects[i].anchordef || sects[i].anchor == NULL)
            continue;
        if (!sects[i].haslines && !sects[i].hassyms)
            continue;

        for (sym = first_sym(&symbol_st, &iter); sym != NULL;
             sym = next_sym(&symbol_st, &iter))
            if (sym->section == sects[i].sect && sym->value == sects[i].bias
                && symbol_wanted(sym)) {
                symbol_where(sym, &file, &line);
                break;
            }

        if (line == 0)
            for (j = 0; j < nrows; j++)
                if (rows[j].sect == sects[i].sect) {
                    file = (unsigned long) rows[j].file;
                    line = (unsigned long) rows[j].line;
                    break;
                }

        buf_uleb(info, ABBREV_VARIABLE);
        buf_str(info, sects[i].anchor);
        buf_uleb(info, file);
        buf_uleb(info, line);
        buf_u32(info, word_off);
        buf_u8(info, 1);
        buf_uleb(info, 5);
        buf_u8(info, DW_OP_addr);
        buf_reloc32(info, i, -1, 0);
    }

    for (sym = first_sym(&symbol_st, &iter); sym != NULL;
         sym = next_sym(&symbol_st, &iter)) {
        unsigned long   file,
                        line;
        int             external;
        int             which;

        if (!symbol_wanted(sym))
            continue;

        which = sect_index(sym->section);
        if (which >= 0 && sects[which].anchor == NULL)
            continue;           /* Nothing to measure it from */

        symbol_where(sym, &file, &line);
        external = (sym->flags & SYMBOLFLAG_GLOBAL) != 0;

        if (which < 0) {
            /* A symbol that is a number rather than a place.  */
            buf_uleb(info, ABBREV_CONSTANT);
            buf_str(info, sym->label);
            buf_uleb(info, file);
            buf_uleb(info, line);
            buf_u32(info, word_off);
            buf_u8(info, (unsigned) external);
            buf_sleb(info, (long) (short) sym->value);
        } else {
            buf_uleb(info, ABBREV_VARIABLE);
            buf_str(info, sym->label);
            buf_uleb(info, file);
            buf_uleb(info, line);
            buf_u32(info, word_off);
            buf_u8(info, (unsigned) external);
            buf_uleb(info, 5);  /* The length of what follows */
            buf_u8(info, DW_OP_addr);
            buf_reloc32(info, which, -1,
                        (long) sym->value - (long) sects[which].bias);
        }
    }

    buf_uleb(info, 0);          /* End of the unit's children */

    put32_at(info->data, unit_start, info->size - unit_start - 4);
}

/* The relocations collected in BODY, as a .rela section.  */

static void build_rela(
    struct buf *rela,
    const struct buf *body,
    const int *section_syms)
{
    unsigned        i;

    for (i = 0; i < body->nrelocs; i++) {
        unsigned        sym;

        if (body->relocs[i].anchor >= 0)
            sym = (unsigned) sects[body->relocs[i].anchor].anchorsym;
        else
            sym = (unsigned) section_syms[body->relocs[i].section];

        buf_u32(rela, body->relocs[i].offset);
        buf_u32(rela, ELF32_R_INFO(sym, R_PDP11_32));
        buf_u32(rela, body->relocs[i].addend);
    }
}

int elfobj_write(
    FILE *fp)
{
    struct buf      line,
                    info,
                    abbrev,
                    ranges,
                    rela_line,
                    rela_info,
                    rela_ranges,
                    symtab;
    struct strtab   shstr,
                    str;
    int             section_syms[MAX_SECTS + 16];
    unsigned        nameoff[MAX_SECTS + 16];
    unsigned        offsets[MAX_SECTS + 16];
    unsigned        shnum,
                    shoff,
                    at;
    unsigned        first_global,
                    nsyms;
    int             line_sect,
                    info_sect,
                    abbrev_sect,
                    ranges_sect,
                    rela_line_sect,
                    rela_info_sect,
                    rela_ranges_sect,
                    symtab_sect,
                    strtab_sect,
                    shstrtab_sect;
    unsigned char   hdr[EHDR_SIZE];
    struct buf      shdrs;
    int             i;

    /* The p-sects worth mentioning, in the order the module declared
       them, each with the global its addresses are measured from.  */
    nsects = 0;
    for (i = 0; i < sector && nsects < MAX_SECTS; i++) {
        SECTION        *sect = sections[i];
        unsigned        bias;
        int             define;
        unsigned        j;

        if (sect == &absolute_section)
            continue;

        sects[nsects].sect = sect;
        sects[nsects].anchor = elfobj_anchor(sect, &bias, &define);
        sects[nsects].anchordef = define;
        sects[nsects].bias = bias;
        sects[nsects].anchorsym = 0;
        sects[nsects].haslines = 0;
        sects[nsects].hassyms = 0;

        for (j = 0; j < nrows; j++)
            if (rows[j].sect == sect) {
                sects[nsects].haslines = 1;
                break;
            }

        {
            SYMBOL_ITER     iter;
            SYMBOL         *sym;

            for (sym = first_sym(&symbol_st, &iter); sym != NULL;
                 sym = next_sym(&symbol_st, &iter))
                if (sym->section == sect && symbol_wanted(sym)) {
                    sects[nsects].hassyms = 1;
                    break;
                }
        }

        /* An address needs something to be measured from, and without
           an anchor there is nothing.  */
        if (sects[nsects].anchor == NULL
            && (sects[nsects].haslines || sects[nsects].hassyms)) {
            report_warn(NULL, "No symbol to measure %s from: "
                        "what is in it is left out of the ELF file\n",
                        sect_name(sect));
            sects[nsects].haslines = 0;
            sects[nsects].hassyms = 0;
        }

        nsects++;
    }

    /* Section header indices, and every section name, before any offset
       is worked out.  */
    strtab_init(&shstr);
    strtab_init(&str);

    shnum = 1;
    for (i = 0; i < nsects; i++) {
        sects[i].shndx = (int) shnum++;
        sects[i].nameoff = strtab_add(&shstr, sect_name(sects[i].sect));
    }
    line_sect = (int) shnum++;
    info_sect = (int) shnum++;
    abbrev_sect = (int) shnum++;
    ranges_sect = (int) shnum++;
    rela_line_sect = (int) shnum++;
    rela_info_sect = (int) shnum++;
    rela_ranges_sect = (int) shnum++;
    symtab_sect = (int) shnum++;
    strtab_sect = (int) shnum++;
    shstrtab_sect = (int) shnum++;

    nameoff[line_sect] = strtab_add(&shstr, ".debug_line");
    nameoff[info_sect] = strtab_add(&shstr, ".debug_info");
    nameoff[abbrev_sect] = strtab_add(&shstr, ".debug_abbrev");
    nameoff[ranges_sect] = strtab_add(&shstr, ".debug_ranges");
    nameoff[rela_line_sect] = strtab_add(&shstr, ".rela.debug_line");
    nameoff[rela_info_sect] = strtab_add(&shstr, ".rela.debug_info");
    nameoff[rela_ranges_sect] = strtab_add(&shstr, ".rela.debug_ranges");
    nameoff[symtab_sect] = strtab_add(&shstr, ".symtab");
    nameoff[strtab_sect] = strtab_add(&shstr, ".strtab");
    nameoff[shstrtab_sect] = strtab_add(&shstr, ".shstrtab");

    /* The symbol table: the file, then a symbol per section, then the
       module's own symbols, and the anchors last -- they are the only
       globals here, being defined in the object module and merely
       referred to from this file.  */
    buf_init(&symtab);
    memset(section_syms, 0, sizeof(section_syms));
    nsyms = 0;

#define SYM_ENTRY(name, value, bind, type, shndx)	\
    do {						\
	buf_u32(&symtab, (name));			\
	buf_u32(&symtab, (value));			\
	buf_u32(&symtab, 0);				\
	buf_u8(&symtab, ELF_ST_INFO((bind), (type)));	\
	buf_u8(&symtab, 0);				\
	buf_u16(&symtab, (shndx));			\
	nsyms++;					\
    } while (0)

    SYM_ENTRY(0, 0, STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    SYM_ENTRY(strtab_add(&str, module_name), 0, STB_LOCAL, STT_FILE, SHN_ABS);

    for (i = 0; i < nsects; i++) {
        section_syms[sects[i].shndx] = (int) nsyms;
        SYM_ENTRY(0, 0, STB_LOCAL, STT_SECTION, (unsigned) sects[i].shndx);
    }
    section_syms[line_sect] = (int) nsyms;
    SYM_ENTRY(0, 0, STB_LOCAL, STT_SECTION, (unsigned) line_sect);
    section_syms[info_sect] = (int) nsyms;
    SYM_ENTRY(0, 0, STB_LOCAL, STT_SECTION, (unsigned) info_sect);
    section_syms[abbrev_sect] = (int) nsyms;
    SYM_ENTRY(0, 0, STB_LOCAL, STT_SECTION, (unsigned) abbrev_sect);
    section_syms[ranges_sect] = (int) nsyms;
    SYM_ENTRY(0, 0, STB_LOCAL, STT_SECTION, (unsigned) ranges_sect);

    first_global = nsyms;

    for (i = 0; i < nsects; i++) {
        if ((!sects[i].haslines && !sects[i].hassyms)
            || sects[i].anchor == NULL)
            continue;
        sects[i].anchorsym = (int) nsyms;
        SYM_ENTRY(strtab_add(&str, sects[i].anchor), 0,
                  STB_GLOBAL, STT_NOTYPE, SHN_UNDEF);
    }

#undef SYM_ENTRY

    /* The DWARF itself, and the relocations that go with it.  */
    buf_init(&line);
    buf_init(&info);
    buf_init(&abbrev);
    buf_init(&ranges);
    buf_init(&rela_line);
    buf_init(&rela_info);
    buf_init(&rela_ranges);

    build_line_table(&line);
    build_abbrev(&abbrev);
    build_ranges(&ranges);
    build_info(&info, abbrev_sect, line_sect, ranges_sect);
    build_rela(&rela_line, &line, section_syms);
    build_rela(&rela_info, &info, section_syms);
    build_rela(&rela_ranges, &ranges, section_syms);

    /* Where everything lands.  The p-sect sections hold nothing, so
       they take up no room; the rest follows the header in order, and
       the section headers come last.  */
    at = EHDR_SIZE;
    for (i = 0; i < nsects; i++)
        offsets[sects[i].shndx] = at;
    offsets[line_sect] = at;
    at += line.size;
    offsets[info_sect] = at;
    at += info.size;
    offsets[abbrev_sect] = at;
    at += abbrev.size;
    at = (at + 3) & ~3u;
    offsets[ranges_sect] = at;
    at += ranges.size;
    offsets[rela_line_sect] = at;
    at += rela_line.size;
    offsets[rela_info_sect] = at;
    at += rela_info.size;
    offsets[rela_ranges_sect] = at;
    at += rela_ranges.size;
    at = (at + 3) & ~3u;
    offsets[symtab_sect] = at;
    at += symtab.size;
    offsets[strtab_sect] = at;
    at += str.size;
    offsets[shstrtab_sect] = at;
    at += shstr.size;
    shoff = (at + 3) & ~3u;

    /* The section headers.  */
    buf_init(&shdrs);

#define SHDR(name, type, flags, off, size, link, inf, align, entsize)	\
    do {								\
	buf_u32(&shdrs, (name));					\
	buf_u32(&shdrs, (type));					\
	buf_u32(&shdrs, (flags));					\
	buf_u32(&shdrs, 0);		/* No address */		\
	buf_u32(&shdrs, (off));						\
	buf_u32(&shdrs, (size));					\
	buf_u32(&shdrs, (link));					\
	buf_u32(&shdrs, (inf));						\
	buf_u32(&shdrs, (align));					\
	buf_u32(&shdrs, (entsize));					\
    } while (0)

    SHDR(0, 0, 0, 0, 0, 0, 0, 0, 0);

    /* One per p-sect: a name for this file's own symbols to belong to,
       and the p-sect's length for anyone reading.  No flags, so that a
       linker leaves it alone -- the object module is what carries the
       content, and the DWARF above is what carries the addresses.  */
    for (i = 0; i < nsects; i++)
        SHDR(sects[i].nameoff, SHT_NOBITS, 0, offsets[sects[i].shndx],
             sects[i].sect->size, 0, 0, 2, 0);

    SHDR(nameoff[line_sect], SHT_PROGBITS, 0, offsets[line_sect],
         line.size, 0, 0, 1, 0);
    SHDR(nameoff[info_sect], SHT_PROGBITS, 0, offsets[info_sect],
         info.size, 0, 0, 1, 0);
    SHDR(nameoff[abbrev_sect], SHT_PROGBITS, 0, offsets[abbrev_sect],
         abbrev.size, 0, 0, 1, 0);
    SHDR(nameoff[ranges_sect], SHT_PROGBITS, 0, offsets[ranges_sect],
         ranges.size, 0, 0, 4, 0);
    SHDR(nameoff[rela_line_sect], SHT_RELA, 0, offsets[rela_line_sect],
         rela_line.size, (unsigned) symtab_sect, (unsigned) line_sect,
         4, RELA_SIZE);
    SHDR(nameoff[rela_info_sect], SHT_RELA, 0, offsets[rela_info_sect],
         rela_info.size, (unsigned) symtab_sect, (unsigned) info_sect,
         4, RELA_SIZE);
    SHDR(nameoff[rela_ranges_sect], SHT_RELA, 0, offsets[rela_ranges_sect],
         rela_ranges.size, (unsigned) symtab_sect, (unsigned) ranges_sect,
         4, RELA_SIZE);
    SHDR(nameoff[symtab_sect], SHT_SYMTAB, 0, offsets[symtab_sect],
         symtab.size, (unsigned) strtab_sect, first_global, 4, SYM_SIZE);
    SHDR(nameoff[strtab_sect], SHT_STRTAB, 0, offsets[strtab_sect],
         str.size, 0, 0, 1, 0);
    SHDR(nameoff[shstrtab_sect], SHT_STRTAB, 0, offsets[shstrtab_sect],
         shstr.size, 0, 0, 1, 0);

#undef SHDR

    /* And the ELF header, now that the shape is known.  Written by
       offset rather than by walking a pointer: the fields of an ELF
       header are at fixed places, and saying so is less work to check
       than counting along.  */
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = 0x7f;
    hdr[1] = 'E';
    hdr[2] = 'L';
    hdr[3] = 'F';
    hdr[4] = ELFCLASS32;
    hdr[5] = ELFDATA2LSB;
    hdr[6] = EV_CURRENT;
    put16_at(hdr, 16, ET_REL);          /* e_type */
    put16_at(hdr, 18, EM_PDP11);        /* e_machine */
    put32_at(hdr, 20, EV_CURRENT);      /* e_version */
    put32_at(hdr, 24, 0);               /* e_entry: none in a relocatable */
    put32_at(hdr, 28, 0);               /* e_phoff: no program headers */
    put32_at(hdr, 32, shoff);           /* e_shoff */
    put32_at(hdr, 36, 0);               /* e_flags */
    put16_at(hdr, 40, EHDR_SIZE);       /* e_ehsize */
    put16_at(hdr, 42, 0);               /* e_phentsize */
    put16_at(hdr, 44, 0);               /* e_phnum */
    put16_at(hdr, 46, SHDR_SIZE);       /* e_shentsize */
    put16_at(hdr, 48, shnum);           /* e_shnum */
    put16_at(hdr, 50, (unsigned) shstrtab_sect);        /* e_shstrndx */

    if (fwrite(hdr, 1, EHDR_SIZE, fp) != EHDR_SIZE)
        goto write_error;

#define PUT(buf, want)							\
    do {								\
	while ((unsigned) ftell(fp) < (want))				\
	    if (fputc(0, fp) == EOF)					\
		goto write_error;					\
	if ((buf).size != 0						\
	    && fwrite((buf).data, 1, (buf).size, fp) != (buf).size)	\
	    goto write_error;						\
    } while (0)

    PUT(line, offsets[line_sect]);
    PUT(info, offsets[info_sect]);
    PUT(abbrev, offsets[abbrev_sect]);
    PUT(ranges, offsets[ranges_sect]);
    PUT(rela_line, offsets[rela_line_sect]);
    PUT(rela_info, offsets[rela_info_sect]);
    PUT(rela_ranges, offsets[rela_ranges_sect]);
    PUT(symtab, offsets[symtab_sect]);

    while ((unsigned) ftell(fp) < offsets[strtab_sect])
        if (fputc(0, fp) == EOF)
            goto write_error;
    if (fwrite(str.data, 1, str.size, fp) != str.size)
        goto write_error;
    if (fwrite(shstr.data, 1, shstr.size, fp) != shstr.size)
        goto write_error;

    PUT(shdrs, shoff);

#undef PUT

    buf_free(&line);
    buf_free(&info);
    buf_free(&abbrev);
    buf_free(&ranges);
    buf_free(&rela_line);
    buf_free(&rela_info);
    buf_free(&rela_ranges);
    buf_free(&symtab);
    buf_free(&shdrs);
    strtab_free(&str);
    strtab_free(&shstr);
    return 1;

 write_error:
    report_fatal(NULL, "Unable to write the ELF debug file\n");
    buf_free(&line);
    buf_free(&info);
    buf_free(&abbrev);
    buf_free(&ranges);
    buf_free(&rela_line);
    buf_free(&rela_info);
    buf_free(&rela_ranges);
    buf_free(&symtab);
    buf_free(&shdrs);
    strtab_free(&str);
    strtab_free(&shstr);
    return 0;
}
