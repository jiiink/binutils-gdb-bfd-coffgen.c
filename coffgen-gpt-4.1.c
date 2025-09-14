/* Support for the generic parts of COFF, for BFD.
   Copyright (C) 1990-2025 Free Software Foundation, Inc.
   Written by Cygnus Support.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* Most of this hacked by  Steve Chamberlain, sac@cygnus.com.
   Split out of coffcode.h by Ian Taylor, ian@cygnus.com.  */

/* This file contains COFF code that is not dependent on any
   particular COFF target.  There is only one version of this file in
   libbfd.a, so no target specific code may be put in here.  Or, to
   put it another way,

   ********** DO NOT PUT TARGET SPECIFIC CODE IN THIS FILE **********

   If you need to add some target specific behaviour, add a new hook
   function to bfd_coff_backend_data.

   Some of these functions are also called by the ECOFF routines.
   Those functions may not use any COFF specific information, such as
   coff_data (abfd).  */

#include "sysdep.h"
#include <limits.h>
#include "bfd.h"
#include "libbfd.h"
#include "coff/internal.h"
#include "libcoff.h"
#include "elf-bfd.h"
#include "hashtab.h"
#include "safe-ctype.h"

/* Extract a long section name at STRINDEX and copy it to the bfd objstack.
   Return NULL in case of error.  */

static char *extract_long_section_name(bfd *abfd, unsigned long strindex)
{
    const char *strings = _bfd_coff_read_string_table(abfd);
    if (!strings)
        return NULL;

    bfd_size_type strings_len = obj_coff_strings_len(abfd);
    if ((bfd_size_type)(strindex + 1) >= strings_len)
        return NULL;

    strings += strindex;
    size_t len = strnlen(strings, strings_len - strindex);
    if (strindex + len >= strings_len)
        return NULL;

    char *name = (char *)bfd_alloc(abfd, len + 1);
    if (!name)
        return NULL;

    memcpy(name, strings, len);
    name[len] = '\0';
    return name;
}

/* Decode a base 64 coded string at STR of length LEN, and write the result
   to RES.  Return true on success.
   Return false in case of invalid character or overflow.  */

static bool decode_base64(const char *str, unsigned len, uint32_t *res)
{
    if (!str || !res || len == 0 || len > 6)
        return false;

    uint32_t val = 0;
    for (unsigned i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        unsigned d;

        if (c >= 'A' && c <= 'Z') {
            d = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            d = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            d = c - '0' + 52;
        } else if (c == '+') {
            d = 62;
        } else if (c == '/') {
            d = 63;
        } else {
            return false;
        }

        if (val > (UINT32_MAX >> 6))
            return false;

        val = (val << 6) | d;
    }

    *res = val;
    return true;
}

/* Take a section header read from a coff file (in HOST byte order),
   and make a BFD "section" out of it.  This is used by ECOFF.  */

static bool make_a_section_from_file(bfd *abfd, struct internal_scnhdr *hdr, unsigned int target_index)
{
    asection *newsect;
    char *name = NULL;
    bool result = true;
    flagword flags = 0;

    if (bfd_coff_set_long_section_names(abfd, bfd_coff_long_section_names(abfd)) && hdr->s_name[0] == '/')
    {
        bfd_coff_set_long_section_names(abfd, true);

        if (hdr->s_name[1] == '/')
        {
            uint32_t strindex;
            if (!decode_base64(hdr->s_name + 2, SCNNMLEN - 2, &strindex))
                return false;

            name = extract_long_section_name(abfd, strindex);
            if (name == NULL)
                return false;
        }
        else
        {
            char buf[SCNNMLEN];
            long strindex;
            char *p;

            memcpy(buf, hdr->s_name + 1, SCNNMLEN - 1);
            buf[SCNNMLEN - 1] = '\0';
            strindex = strtol(buf, &p, 10);
            if (*p == '\0' && strindex >= 0)
            {
                name = extract_long_section_name(abfd, strindex);
                if (name == NULL)
                    return false;
            }
        }
    }

    if (name == NULL)
    {
        size_t namelen = sizeof(hdr->s_name) + 2;
        name = (char *)bfd_alloc(abfd, (bfd_size_type)namelen);
        if (name == NULL)
            return false;
        strncpy(name, (char *)&hdr->s_name[0], sizeof(hdr->s_name));
        name[sizeof(hdr->s_name)] = 0;
    }

    newsect = bfd_make_section_anyway(abfd, name);
    if (newsect == NULL)
        return false;

    newsect->vma = hdr->s_vaddr;
    newsect->lma = hdr->s_paddr;
    newsect->size = hdr->s_size;
    newsect->filepos = hdr->s_scnptr;
    newsect->rel_filepos = hdr->s_relptr;
    newsect->reloc_count = hdr->s_nreloc;
    bfd_coff_set_alignment_hook(abfd, newsect, hdr);
    newsect->line_filepos = hdr->s_lnnoptr;
    newsect->lineno_count = hdr->s_nlnno;
    newsect->userdata = NULL;
    newsect->next = NULL;
    newsect->target_index = target_index;

    if (!bfd_coff_styp_to_sec_flags_hook(abfd, hdr, name, newsect, &flags))
        result = false;

    if ((flags & SEC_COFF_SHARED_LIBRARY) != 0)
        newsect->lineno_count = 0;

    if (hdr->s_nreloc != 0)
        flags |= SEC_RELOC;
    if (hdr->s_scnptr != 0)
        flags |= SEC_HAS_CONTENTS;

    newsect->flags = flags;

    if ((flags & SEC_DEBUGGING) != 0 && (flags & SEC_HAS_CONTENTS) != 0 &&
        (startswith(name, ".debug_") ||
         startswith(name, ".zdebug_") ||
         startswith(name, ".gnu.debuglto_.debug_") ||
         startswith(name, ".gnu.linkonce.wi.")))
    {
        enum { nothing, compress, decompress } action = nothing;
        if (bfd_is_section_compressed(abfd, newsect))
        {
            if ((abfd->flags & BFD_DECOMPRESS))
                action = decompress;
        }
        else
        {
            if ((abfd->flags & BFD_COMPRESS) && newsect->size != 0)
                action = compress;
        }

        if (action == compress)
        {
            if (!bfd_init_section_compress_status(abfd, newsect))
            {
                _bfd_error_handler(_("%pB: unable to compress section %s"), abfd, name);
                return false;
            }
        }
        else if (action == decompress)
        {
            if (!bfd_init_section_decompress_status(abfd, newsect))
            {
                _bfd_error_handler(_("%pB: unable to decompress section %s"), abfd, name);
                return false;
            }
            if (abfd->is_linker_input && name[1] == 'z')
            {
                char *new_name = bfd_zdebug_name_to_debug(abfd, name);
                if (new_name == NULL)
                    return false;
                bfd_rename_section(newsect, new_name);
            }
        }
    }

    return result;
}

void coff_object_cleanup(bfd *abfd) {
    struct coff_tdata *td = coff_data(abfd);
    if (!td) {
        return;
    }

    if (td->section_by_index) {
        htab_delete(td->section_by_index);
        td->section_by_index = NULL;
    }
    if (td->section_by_target_index) {
        htab_delete(td->section_by_target_index);
        td->section_by_target_index = NULL;
    }

    if (obj_pe(abfd)) {
        struct pe_tdata *pe = pe_data(abfd);
        if (pe && pe->comdat_hash) {
            htab_delete(pe->comdat_hash);
            pe->comdat_hash = NULL;
        }
    }
}

/* Read in a COFF object and make it into a BFD.  This is used by
   ECOFF as well.  */
bfd_cleanup
coff_real_object_p(bfd *abfd, unsigned nscns, struct internal_filehdr *internal_f, struct internal_aouthdr *internal_a) {
  flagword original_flags = abfd->flags;
  bfd_vma original_start = bfd_get_start_address(abfd);
  void *tdata = NULL;
  bfd_size_type readsize;
  unsigned int scnhsz;
  char *external_sections = NULL;

  if (!(internal_f->f_flags & F_RELFLG))
    abfd->flags |= HAS_RELOC;
  if (internal_f->f_flags & F_EXEC)
    abfd->flags |= EXEC_P;
  if (!(internal_f->f_flags & F_LNNO))
    abfd->flags |= HAS_LINENO;
  if (!(internal_f->f_flags & F_LSYMS))
    abfd->flags |= HAS_LOCALS;
  if ((internal_f->f_flags & F_EXEC) != 0)
    abfd->flags |= D_PAGED;

  abfd->symcount = internal_f->f_nsyms;
  if (internal_f->f_nsyms)
    abfd->flags |= HAS_SYMS;

  abfd->start_address = internal_a ? internal_a->entry : 0;

  tdata = bfd_coff_mkobject_hook(abfd, (void *)internal_f, (void *)internal_a);
  if (!tdata)
    goto fail2;

  scnhsz = bfd_coff_scnhsz(abfd);
  readsize = (bfd_size_type)nscns * scnhsz;

  external_sections = (char *)_bfd_alloc_and_read(abfd, readsize, readsize);
  if (!external_sections)
    goto fail;

  if (!bfd_coff_set_arch_mach_hook(abfd, (void *)internal_f))
    goto fail;

  if (nscns != 0) {
    unsigned int i;
    for (i = 0; i < nscns; i++) {
      struct internal_scnhdr tmp;
      bfd_coff_swap_scnhdr_in(
        abfd,
        (void *)(external_sections + i * scnhsz),
        (void *)&tmp
      );
      if (!make_a_section_from_file(abfd, &tmp, i + 1))
        goto fail;
    }
  }

  _bfd_coff_free_symbols(abfd);
  return coff_object_cleanup;

fail:
  coff_object_cleanup(abfd);
  _bfd_coff_free_symbols(abfd);
  if (tdata)
    bfd_release(abfd, tdata);
fail2:
  abfd->flags = original_flags;
  abfd->start_address = original_start;
  return NULL;
}

/* Turn a COFF file into a BFD, but fail with bfd_error_wrong_format if it is
   not a COFF file.  This is also used by ECOFF.  */

bfd_cleanup
coff_object_p(bfd *abfd)
{
    bfd_size_type filhsz = bfd_coff_filhsz(abfd);
    bfd_size_type aoutsz = bfd_coff_aoutsz(abfd);
    struct internal_filehdr internal_f;
    struct internal_aouthdr internal_a;
    unsigned int nscns;

    void *filehdr = _bfd_alloc_and_read(abfd, filhsz, filhsz);
    if (!filehdr) {
        if (bfd_get_error() != bfd_error_system_call)
            bfd_set_error(bfd_error_wrong_format);
        return NULL;
    }

    bfd_coff_swap_filehdr_in(abfd, filehdr, &internal_f);
    bfd_release(abfd, filehdr);

    if (!bfd_coff_bad_format_hook(abfd, &internal_f) || internal_f.f_opthdr > aoutsz) {
        bfd_set_error(bfd_error_wrong_format);
        return NULL;
    }
    nscns = internal_f.f_nscns;

    if (internal_f.f_opthdr) {
        void *opthdr = _bfd_alloc_and_read(abfd, aoutsz, internal_f.f_opthdr);
        if (!opthdr)
            return NULL;
        if (internal_f.f_opthdr < aoutsz)
            memset((char *)opthdr + internal_f.f_opthdr, 0, aoutsz - internal_f.f_opthdr);

        bfd_coff_swap_aouthdr_in(abfd, opthdr, &internal_a);
        bfd_release(abfd, opthdr);
    }

    return coff_real_object_p(
        abfd,
        nscns,
        &internal_f,
        internal_f.f_opthdr ? &internal_a : NULL
    );
}

static hashval_t htab_hash_section_target_index(const void *entry)
{
    if (entry == NULL) {
        return 0;
    }
    const struct bfd_section *sec = (const struct bfd_section *)entry;
    return sec->target_index;
}

static int htab_eq_section_target_index(const void *e1, const void *e2) {
    if (!e1 || !e2) {
        return 0;
    }
    const struct bfd_section *sec1 = (const struct bfd_section *)e1;
    const struct bfd_section *sec2 = (const struct bfd_section *)e2;
    return sec1->target_index == sec2->target_index;
}

/* Get the BFD section from a COFF symbol section number.  */

asection *
coff_section_from_bfd_index(bfd *abfd, int section_index)
{
  if (section_index == N_ABS || section_index == N_DEBUG)
    return bfd_abs_section_ptr;
  if (section_index == N_UNDEF)
    return bfd_und_section_ptr;

  htab_t table = coff_data(abfd)->section_by_target_index;
  struct bfd_section *answer = NULL;

  if (!table)
  {
    table = htab_create(10, htab_hash_section_target_index, htab_eq_section_target_index, NULL);
    if (!table)
      return bfd_und_section_ptr;
    coff_data(abfd)->section_by_target_index = table;
  }

  if (htab_elements(table) == 0)
  {
    for (answer = abfd->sections; answer; answer = answer->next)
    {
      void **slot = htab_find_slot(table, answer, INSERT);
      if (!slot)
        return bfd_und_section_ptr;
      *slot = answer;
    }
  }

  struct bfd_section needle;
  memset(&needle, 0, sizeof(needle));
  needle.target_index = section_index;

  answer = htab_find(table, &needle);
  if (answer)
    return answer;

  for (answer = abfd->sections; answer; answer = answer->next)
  {
    if (answer->target_index == section_index)
    {
      void **slot = htab_find_slot(table, answer, INSERT);
      if (slot)
        *slot = answer;
      return answer;
    }
  }

  return bfd_und_section_ptr;
}

/* Get the upper bound of a COFF symbol table.  */

long coff_get_symtab_upper_bound(bfd *abfd) {
  if (!abfd || !bfd_coff_slurp_symbol_table(abfd))
    return -1;

  long symcount = bfd_get_symcount(abfd);
  if (symcount < 0)
    return -1;

  size_t result = ((size_t)symcount + 1) * sizeof(coff_symbol_type *);
  if (result > LONG_MAX)
    return -1;

  return (long)result;
}

/* Canonicalize a COFF symbol table.  */

long coff_canonicalize_symtab(bfd *abfd, asymbol **alocation) {
    if (!bfd_coff_slurp_symbol_table(abfd) || !alocation)
        return -1;

    coff_symbol_type *symbase = obj_symbols(abfd);
    unsigned int symcount = bfd_get_symcount(abfd);

    if (!symbase || symcount == 0)
    {
        if (alocation)
            *alocation = NULL;
        return 0;
    }

    coff_symbol_type **location = (coff_symbol_type **) alocation;
    for (unsigned int i = 0; i < symcount; i++)
        location[i] = symbase + i;

    location[symcount] = NULL;

    return symcount;
}

/* Get the name of a symbol.  The caller must pass in a buffer of size
   >= SYMNMLEN + 1.  */

const char *
_bfd_coff_internal_syment_name(bfd *abfd, const struct internal_syment *sym, char *buf)
{
  if (sym->_n._n_n._n_zeroes != 0 || sym->_n._n_n._n_offset == 0)
  {
    memcpy(buf, sym->_n._n_name, SYMNMLEN);
    buf[SYMNMLEN] = '\0';
    return buf;
  }

  if (sym->_n._n_n._n_offset < STRING_SIZE_SIZE)
    return NULL;

  const char *strings = obj_coff_strings(abfd);
  if (!strings)
  {
    strings = _bfd_coff_read_string_table(abfd);
    if (!strings)
      return NULL;
  }

  if (sym->_n._n_n._n_offset >= obj_coff_strings_len(abfd))
    return NULL;

  return strings + sym->_n._n_n._n_offset;
}

/* Read in and swap the relocs.  This returns a buffer holding the
   relocs for section SEC in file ABFD.  If CACHE is TRUE and
   INTERNAL_RELOCS is NULL, the relocs read in will be saved in case
   the function is called again.  If EXTERNAL_RELOCS is not NULL, it
   is a buffer large enough to hold the unswapped relocs.  If
   INTERNAL_RELOCS is not NULL, it is a buffer large enough to hold
   the swapped relocs.  If REQUIRE_INTERNAL is TRUE, then the return
   value must be INTERNAL_RELOCS.  The function returns NULL on error.  */

struct internal_reloc *
_bfd_coff_read_internal_relocs(bfd *abfd,
                               asection *sec,
                               bool cache,
                               bfd_byte *external_relocs,
                               bool require_internal,
                               struct internal_reloc *internal_relocs) {
    if (sec->reloc_count == 0)
        return internal_relocs;

    struct coff_section_tdata *section_tdata = coff_section_data(abfd, sec);
    if (section_tdata && section_tdata->relocs) {
        if (!require_internal)
            return section_tdata->relocs;
        memcpy(internal_relocs, section_tdata->relocs,
               sec->reloc_count * sizeof(struct internal_reloc));
        return internal_relocs;
    }

    bfd_size_type relsz = bfd_coff_relsz(abfd);
    bfd_size_type ext_amt = sec->reloc_count * relsz;
    bfd_byte *local_external = NULL;
    if (!external_relocs) {
        local_external = bfd_malloc(ext_amt);
        if (!local_external)
            return NULL;
        external_relocs = local_external;
    }

    if (bfd_seek(abfd, sec->rel_filepos, SEEK_SET) != 0 ||
        bfd_read(external_relocs, ext_amt, abfd) != ext_amt) {
        free(local_external);
        return NULL;
    }

    bfd_size_type int_amt = sec->reloc_count * sizeof(struct internal_reloc);
    struct internal_reloc *local_internal = NULL;
    if (!internal_relocs) {
        local_internal = bfd_malloc(int_amt);
        if (!local_internal) {
            free(local_external);
            return NULL;
        }
        internal_relocs = local_internal;
    }

    bfd_byte *erel = external_relocs;
    struct internal_reloc *irel = internal_relocs;
    for (bfd_size_type i = 0; i < sec->reloc_count; i++) {
        bfd_coff_swap_reloc_in(abfd, erel, irel);
        erel += relsz;
        irel++;
    }

    free(local_external);

    if (cache && local_internal) {
        if (!coff_section_data(abfd, sec)) {
            section_tdata = bfd_zalloc(abfd, sizeof(struct coff_section_tdata));
            if (!section_tdata) {
                free(local_internal);
                return NULL;
            }
            sec->used_by_bfd = section_tdata;
            section_tdata->contents = NULL;
        }
        coff_section_data(abfd, sec)->relocs = local_internal;
    }

    return internal_relocs;
}

/* Set lineno_count for the output sections of a COFF file.  */

int coff_count_linenumbers(bfd *abfd)
{
    unsigned int limit = bfd_get_symcount(abfd);
    unsigned int i;
    int total = 0;
    asymbol **p;
    asection *s;

    if (limit == 0)
    {
        for (s = abfd->sections; s != NULL; s = s->next)
            total += s->lineno_count;
        return total;
    }

    for (s = abfd->sections; s != NULL; s = s->next)
        BFD_ASSERT(s->lineno_count == 0);

    p = abfd->outsymbols;
    for (i = 0; i < limit && p != NULL; i++, p++)
    {
        asymbol *sym = *p;
        bfd *sym_bfd = bfd_asymbol_bfd(sym);
        if (sym_bfd == NULL)
            continue;
        if (!bfd_family_coff(sym_bfd))
            continue;

        coff_symbol_type *coff_sym = coffsymbol(sym);
        if (coff_sym == NULL)
            continue;
        if (coff_sym->lineno == NULL)
            continue;
        if (coff_sym->symbol.section == NULL || coff_sym->symbol.section->owner == NULL)
            continue;

        alent *l = coff_sym->lineno;
        while (l->line_number != 0)
        {
            asection *sec = coff_sym->symbol.section->output_section;
            if (sec && !bfd_is_const_section(sec))
                sec->lineno_count++;
            total++;
            l++;
        }
    }

    return total;
}

static void fixup_symbol_value(bfd *abfd, coff_symbol_type *coff_symbol_ptr, struct internal_syment *syment)
{
    if (coff_symbol_ptr == NULL || syment == NULL || abfd == NULL)
        return;

    if (coff_symbol_ptr->symbol.section && bfd_is_com_section(coff_symbol_ptr->symbol.section)) {
        syment->n_scnum = N_UNDEF;
        syment->n_value = coff_symbol_ptr->symbol.value;
        return;
    }

    if ((coff_symbol_ptr->symbol.flags & BSF_DEBUGGING) &&
        !(coff_symbol_ptr->symbol.flags & BSF_DEBUGGING_RELOC)) {
        syment->n_value = coff_symbol_ptr->symbol.value;
        return;
    }

    if (bfd_is_und_section(coff_symbol_ptr->symbol.section)) {
        syment->n_scnum = N_UNDEF;
        syment->n_value = 0;
        return;
    }

    if (coff_symbol_ptr->symbol.section && coff_symbol_ptr->symbol.section->output_section) {
        syment->n_scnum = coff_symbol_ptr->symbol.section->output_section->target_index;
        syment->n_value = coff_symbol_ptr->symbol.value + coff_symbol_ptr->symbol.section->output_offset;
        if (!obj_pe(abfd)) {
            if (syment->n_sclass == C_STATLAB)
                syment->n_value += coff_symbol_ptr->symbol.section->output_section->lma;
            else
                syment->n_value += coff_symbol_ptr->symbol.section->output_section->vma;
        }
        return;
    }

    syment->n_scnum = N_ABS;
    syment->n_value = coff_symbol_ptr->symbol.value;
}

/* Run through all the symbols in the symbol table and work out what
   their indexes into the symbol table will be when output.

   Coff requires that each C_FILE symbol points to the next one in the
   chain, and that the last one points to the first external symbol. We
   do that here too.  */

bool coff_renumber_symbols(bfd *bfd_ptr, int *first_undef) {
    unsigned int symbol_count = bfd_get_symcount(bfd_ptr);
    asymbol **old_syms = bfd_ptr->outsymbols;
    unsigned int native_index = 0;
    struct internal_syment *last_file = NULL;

    if (symbol_count == 0 || !old_syms || !first_undef)
        return false;

    bfd_size_type amt = sizeof(asymbol *) * ((bfd_size_type)symbol_count + 1);
    asymbol **new_syms = (asymbol **)bfd_alloc(bfd_ptr, amt);
    if (!new_syms)
        return false;

    bfd_ptr->outsymbols = new_syms;
    asymbol **p = new_syms;
    unsigned int i;

    // Fill defined, BSF_NOT_AT_END/block
    for (i = 0; i < symbol_count; ++i) {
        asymbol *s = old_syms[i];
        if ((s->flags & BSF_NOT_AT_END) ||
            (!bfd_is_und_section(s->section) &&
             !bfd_is_com_section(s->section) &&
             ((s->flags & BSF_FUNCTION) ||
              ((s->flags & (BSF_GLOBAL | BSF_WEAK)) == 0))))
            *p++ = s;
    }

    // Fill defined globals/functions
    for (i = 0; i < symbol_count; ++i) {
        asymbol *s = old_syms[i];
        if (!(s->flags & BSF_NOT_AT_END) &&
            !bfd_is_und_section(s->section) &&
            (bfd_is_com_section(s->section) ||
             (!(s->flags & BSF_FUNCTION) && (s->flags & (BSF_GLOBAL | BSF_WEAK)))))
            *p++ = s;
    }

    *first_undef = (int)(p - new_syms);

    // Fill undefined
    for (i = 0; i < symbol_count; ++i) {
        asymbol *s = old_syms[i];
        if (!(s->flags & BSF_NOT_AT_END) && bfd_is_und_section(s->section))
            *p++ = s;
    }
    *p = NULL;
    asymbol **syms = bfd_ptr->outsymbols;

    for (i = 0; i < symbol_count; ++i) {
        coff_symbol_type *coff_ptr = coff_symbol_from(syms[i]);
        syms[i]->udata.i = i;
        if (coff_ptr && coff_ptr->native) {
            combined_entry_type *entry = coff_ptr->native;
            int num_aux = entry->u.syment.n_numaux;
            BFD_ASSERT(entry->is_sym);
            if (entry->u.syment.n_sclass == C_FILE) {
                if (last_file)
                    last_file->n_value = native_index;
                last_file = &(entry->u.syment);
            } else {
                fixup_symbol_value(bfd_ptr, coff_ptr, &(entry->u.syment));
            }
            for (int j = 0; j < num_aux + 1; ++j)
                entry[j].offset = native_index++;
        } else {
            native_index++;
        }
    }
    obj_conv_table_size(bfd_ptr) = native_index;
    return true;
}

/* Run thorough the symbol table again, and fix it so that all
   pointers to entries are changed to the entries' index in the output
   symbol table.  */

void coff_mangle_symbols(bfd *bfd_ptr)
{
    if (!bfd_ptr)
        return;
    unsigned int symbol_count = bfd_get_symcount(bfd_ptr);
    asymbol **symbol_ptr_ptr = bfd_ptr->outsymbols;
    if (!symbol_ptr_ptr)
        return;

    for (unsigned int symbol_index = 0; symbol_index < symbol_count; symbol_index++) {
        coff_symbol_type *coff_symbol_ptr = coff_symbol_from(symbol_ptr_ptr[symbol_index]);
        if (!coff_symbol_ptr || !coff_symbol_ptr->native)
            continue;

        combined_entry_type *s = coff_symbol_ptr->native;

        if (!s->is_sym)
            continue;

        if (s->fix_value) {
            uintptr_t value = (uintptr_t)s->u.syment.n_value;
            combined_entry_type *ce = (combined_entry_type *)value;
            s->u.syment.n_value = (uintptr_t)ce->offset;
            s->fix_value = 0;
        }

        if (s->fix_line) {
            section_type *sec = coff_symbol_ptr->symbol.section;
            if (sec && sec->output_section) {
                s->u.syment.n_value =
                    sec->output_section->line_filepos +
                    s->u.syment.n_value * bfd_coff_linesz(bfd_ptr);
                coff_symbol_ptr->symbol.section =
                    coff_section_from_bfd_index(bfd_ptr, N_DEBUG);
                if (!(coff_symbol_ptr->symbol.flags & BSF_DEBUGGING))
                    continue;
            }
        }

        int numaux = s->u.syment.n_numaux;
        for (int i = 0; i < numaux; i++) {
            combined_entry_type *a = s + i + 1;
            if (a->is_sym)
                continue;

            if (a->fix_tag && a->u.auxent.x_sym.x_tagndx.p) {
                a->u.auxent.x_sym.x_tagndx.u32 = a->u.auxent.x_sym.x_tagndx.p->offset;
                a->fix_tag = 0;
            }

            if (a->fix_end && a->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p) {
                a->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32 =
                    a->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p->offset;
                a->fix_end = 0;
            }

            if (a->fix_scnlen && a->u.auxent.x_csect.x_scnlen.p) {
                a->u.auxent.x_csect.x_scnlen.u64 = a->u.auxent.x_csect.x_scnlen.p->offset;
                a->fix_scnlen = 0;
            }
        }
    }
}

static bool coff_write_auxent_fname(bfd *abfd, char *str, union internal_auxent *auxent, struct bfd_strtab_hash *strtab, bool hash) {
    unsigned int str_length = strlen(str);
    unsigned int filnmlen = bfd_coff_filnmlen(abfd);

    if (bfd_coff_long_filenames(abfd)) {
        if (str_length <= filnmlen) {
            memset(auxent->x_file.x_n.x_fname, 0, filnmlen);
            strncpy(auxent->x_file.x_n.x_fname, str, filnmlen);
        } else {
            bfd_size_type indx = _bfd_stringtab_add(strtab, str, hash, false);
            if (indx == (bfd_size_type)-1) {
                return false;
            }
            auxent->x_file.x_n.x_n.x_offset = STRING_SIZE_SIZE + indx;
            auxent->x_file.x_n.x_n.x_zeroes = 0;
        }
    } else {
        memset(auxent->x_file.x_n.x_fname, 0, filnmlen);
        strncpy(auxent->x_file.x_n.x_fname, str, filnmlen - 1);
        auxent->x_file.x_n.x_fname[filnmlen - 1] = '\0';
    }

    return true;
}

static bool coff_fix_symbol_name(
    bfd *abfd,
    asymbol *symbol,
    combined_entry_type *native,
    struct bfd_strtab_hash *strtab,
    bool hash,
    asection **debug_string_section_p,
    bfd_size_type *debug_string_size_p)
{
    unsigned int name_length;
    char *name;
    bfd_size_type indx;

    name = (char *) symbol->name;
    if (!name) {
        symbol->name = "strange";
        name = (char *) symbol->name;
    }
    name_length = (unsigned int) strlen(name);

    BFD_ASSERT(native->is_sym);

    if (native->u.syment.n_sclass == C_FILE && native->u.syment.n_numaux > 0) {
        if (bfd_coff_force_symnames_in_strings(abfd)) {
            indx = _bfd_stringtab_add(strtab, ".file", hash, false);
            if (indx == (bfd_size_type)-1)
                return false;
            native->u.syment._n._n_n._n_offset = STRING_SIZE_SIZE + indx;
            native->u.syment._n._n_n._n_zeroes = 0;
        } else {
            strncpy(native->u.syment._n._n_name, ".file", SYMNMLEN);
        }
        BFD_ASSERT(!(native + 1)->is_sym);
        if (!coff_write_auxent_fname(
                abfd, name, &(native + 1)->u.auxent, strtab, hash)) {
            return false;
        }
    } else {
        bool name_fits = (name_length <= SYMNMLEN) && !bfd_coff_force_symnames_in_strings(abfd);
        if (name_fits) {
            strncpy(native->u.syment._n._n_name, symbol->name, SYMNMLEN);
        } else if (!bfd_coff_symname_in_debug(abfd, &native->u.syment)) {
            indx = _bfd_stringtab_add(strtab, name, hash, false);
            if (indx == (bfd_size_type)-1)
                return false;
            native->u.syment._n._n_n._n_offset = STRING_SIZE_SIZE + indx;
            native->u.syment._n._n_n._n_zeroes = 0;
        } else {
            file_ptr filepos;
            bfd_byte buf[4];
            int prefix_len = bfd_coff_debug_string_prefix_length(abfd);
            asection *debug_sec = *debug_string_section_p;
            bfd_size_type debug_off = *debug_string_size_p;

            if (debug_sec == NULL)
                *debug_string_section_p = debug_sec = bfd_get_section_by_name(abfd, ".debug");

            filepos = bfd_tell(abfd);
            if (prefix_len == 4) {
                bfd_put_32(abfd, (bfd_vma)(name_length + 1), buf);
            } else {
                bfd_put_16(abfd, (bfd_vma)(name_length + 1), buf);
            }

            if (!bfd_set_section_contents(
                    abfd, debug_sec, (void *)buf, (file_ptr)debug_off, (bfd_size_type)prefix_len) ||
                !bfd_set_section_contents(
                    abfd, debug_sec, (void *)symbol->name,
                    (file_ptr)(debug_off + prefix_len), (bfd_size_type)(name_length + 1))) {
                return false;
            }

            if (bfd_seek(abfd, filepos, SEEK_SET) != 0)
                return false;

            native->u.syment._n._n_n._n_offset = debug_off + prefix_len;
            native->u.syment._n._n_n._n_zeroes = 0;
            *debug_string_size_p += name_length + 1 + prefix_len;
        }
    }
    return true;
}

/* We need to keep track of the symbol index so that when we write out
   the relocs we can get the index for a symbol.  This method is a
   hack.  FIXME.  */

#define set_index(symbol, idx)	((symbol)->udata.i = (idx))

/* Write a symbol out to a COFF file.  */

static bool coff_write_symbol(bfd *abfd,
                             asymbol *symbol,
                             combined_entry_type *native,
                             bfd_vma *written,
                             struct bfd_strtab_hash *strtab,
                             bool hash,
                             asection **debug_string_section_p,
                             bfd_size_type *debug_string_size_p) {
    unsigned int numaux = native->u.syment.n_numaux;
    int type = native->u.syment.n_type;
    int n_sclass = (int) native->u.syment.n_sclass;
    asection *output_section = symbol->section->output_section ? symbol->section->output_section : symbol->section;
    bfd_size_type symesz;
    void *buf = NULL;

    BFD_ASSERT(native->is_sym);

    if (native->u.syment.n_sclass == C_FILE)
        symbol->flags |= BSF_DEBUGGING;

    if ((symbol->flags & BSF_DEBUGGING) && bfd_is_abs_section(symbol->section)) {
        native->u.syment.n_scnum = N_DEBUG;
    } else if (bfd_is_abs_section(symbol->section)) {
        native->u.syment.n_scnum = N_ABS;
    } else if (bfd_is_und_section(symbol->section)) {
        native->u.syment.n_scnum = N_UNDEF;
    } else {
        native->u.syment.n_scnum = output_section->target_index;
    }

    if (!coff_fix_symbol_name(abfd, symbol, native, strtab, hash, debug_string_section_p, debug_string_size_p))
        return false;

    symesz = bfd_coff_symesz(abfd);
    buf = bfd_alloc(abfd, symesz);
    if (!buf)
        return false;

    bfd_coff_swap_sym_out(abfd, &native->u.syment, buf);
    if (bfd_write(buf, symesz, abfd) != symesz) {
        bfd_release(abfd, buf);
        return false;
    }
    bfd_release(abfd, buf);

    if (numaux > 0) {
        bfd_size_type auxesz = bfd_coff_auxesz(abfd);
        buf = bfd_alloc(abfd, auxesz);
        if (!buf)
            return false;

        for (unsigned int j = 0; j < numaux; j++) {
            combined_entry_type *aux_entry = native + j + 1;
            BFD_ASSERT(!aux_entry->is_sym);

            if (native->u.syment.n_sclass == C_FILE &&
                aux_entry->u.auxent.x_file.x_ftype &&
                aux_entry->extrap) {
                coff_write_auxent_fname(abfd, (char *)aux_entry->extrap, &aux_entry->u.auxent, strtab, hash);
            }

            bfd_coff_swap_aux_out(abfd, &aux_entry->u.auxent, type, n_sclass, (int)j, numaux, buf);
            if (bfd_write(buf, auxesz, abfd) != auxesz) {
                bfd_release(abfd, buf);
                return false;
            }
        }
        bfd_release(abfd, buf);
    }

    set_index(symbol, *written);
    *written += numaux + 1;
    return true;
}

/* Write out a symbol to a COFF file that does not come from a COFF
   file originally.  This symbol may have been created by the linker,
   or we may be linking a non COFF file to a COFF file.  */

bool
coff_write_alien_symbol(bfd *abfd,
                        asymbol *symbol,
                        struct internal_syment *isym,
                        bfd_vma *written,
                        struct bfd_strtab_hash *strtab,
                        bool hash,
                        asection **debug_string_section_p,
                        bfd_size_type *debug_string_size_p)
{
    combined_entry_type dummy[2];
    combined_entry_type *native = dummy;
    asection *output_section = symbol->section->output_section
                                ? symbol->section->output_section
                                : symbol->section;
    struct bfd_link_info *link_info = coff_data(abfd)->link_info;
    bool ret;

    if ((!link_info || link_info->strip_discarded)
        && !bfd_is_abs_section(symbol->section)
        && symbol->section->output_section == bfd_abs_section_ptr)
    {
        symbol->name = "";
        if (isym)
            memset(isym, 0, sizeof(*isym));
        return true;
    }

    memset(dummy, 0, sizeof(dummy));
    native->is_sym = true;
    native[1].is_sym = false;
    native->u.syment.n_type = T_NULL;
    native->u.syment.n_flags = 0;
    native->u.syment.n_numaux = 0;

    if (bfd_is_und_section(symbol->section) || bfd_is_com_section(symbol->section))
    {
        native->u.syment.n_scnum = N_UNDEF;
        native->u.syment.n_value = symbol->value;
    }
    else if (symbol->flags & BSF_FILE)
    {
        native->u.syment.n_scnum = N_DEBUG;
        native->u.syment.n_numaux = 1;
    }
    else if (symbol->flags & BSF_DEBUGGING)
    {
        symbol->name = "";
        if (isym)
            memset(isym, 0, sizeof(*isym));
        return true;
    }
    else
    {
        native->u.syment.n_scnum = output_section->target_index;
        native->u.syment.n_value = symbol->value + symbol->section->output_offset;
        if (!obj_pe(abfd))
            native->u.syment.n_value += output_section->vma;

        coff_symbol_type *c = coff_symbol_from(symbol);
        if (c)
            native->u.syment.n_flags = bfd_asymbol_bfd(&c->symbol)->flags;

        const elf_symbol_type *elfsym = elf_symbol_from(symbol);
        if (elfsym && (symbol->flags & BSF_FUNCTION) && elfsym->internal_elf_sym.st_size)
        {
            native->u.syment.n_type = DT_FCN << 4;
            native->u.syment.n_numaux = 1;
            native[1].u.auxent.x_sym.x_misc.x_fsize =
                elfsym->internal_elf_sym.st_size;
        }
    }

    if (symbol->flags & BSF_FILE)
        native->u.syment.n_sclass = C_FILE;
    else if (symbol->flags & BSF_LOCAL)
        native->u.syment.n_sclass = C_STAT;
    else if (symbol->flags & BSF_WEAK)
        native->u.syment.n_sclass = obj_pe(abfd) ? C_NT_WEAK : C_WEAKEXT;
    else
        native->u.syment.n_sclass = C_EXT;

    ret = coff_write_symbol(abfd, symbol, native, written, strtab, hash,
                            debug_string_section_p, debug_string_size_p);
    if (isym)
        *isym = native->u.syment;
    return ret;
}

/* Write a native symbol to a COFF file.  */

static bool
coff_write_native_symbol(bfd *abfd,
                         coff_symbol_type *symbol,
                         bfd_vma *written,
                         struct bfd_strtab_hash *strtab,
                         asection **debug_string_section_p,
                         bfd_size_type *debug_string_size_p)
{
    combined_entry_type *native = symbol->native;
    alent *lineno = symbol->lineno;
    struct bfd_link_info *link_info = coff_data(abfd) ? coff_data(abfd)->link_info : NULL;
    asection *section = symbol->symbol.section;
    asection *out_section = section ? section->output_section : NULL;

    if ((!link_info || link_info->strip_discarded)
        && section && !bfd_is_abs_section(section)
        && out_section == bfd_abs_section_ptr)
    {
        symbol->symbol.name = "";
        return true;
    }

    if (!native || !native->is_sym)
        return false;

    if (lineno && !symbol->done_lineno && section && section->owner)
    {
        unsigned int count = 0;
        bfd_size_type linesz = bfd_coff_linesz(abfd);
        bfd_vma off = *written;

        lineno[count].u.offset = off;
        if (native->u.syment.n_numaux)
        {
            union internal_auxent *a = &((native + 1)->u.auxent);
            if (out_section)
                a->x_sym.x_fcnary.x_fcn.x_lnnoptr = out_section->moving_line_filepos;
        }
        count++;
        while (lineno[count].line_number != 0)
        {
            if (out_section)
                lineno[count].u.offset += out_section->vma + section->output_offset;
            count++;
        }
        symbol->done_lineno = true;

        if (out_section && !bfd_is_const_section(out_section))
            out_section->moving_line_filepos += count * linesz;
    }

    return coff_write_symbol(
        abfd, &(symbol->symbol), native, written,
        strtab, true, debug_string_section_p,
        debug_string_size_p
    );
}

static void null_error_handler(const char *fmt, va_list ap)
{
    (void)fmt;
    (void)ap;
}

/* Write out the COFF symbols.  */

bool coff_write_symbols(bfd *abfd) {
    struct bfd_strtab_hash *strtab = NULL;
    asection *debug_string_section = NULL;
    bfd_size_type debug_string_size = 0;
    unsigned int i = 0;
    unsigned int limit = bfd_get_symcount(abfd);
    bfd_vma written = 0;
    asymbol **p = NULL;

    strtab = _bfd_stringtab_init();
    if (!strtab) return false;

    if (bfd_coff_long_section_names(abfd)) {
        for (asection *o = abfd->sections; o; o = o->next) {
            if (strlen(o->name) > SCNNMLEN &&
                _bfd_stringtab_add(strtab, o->name, false, false) == (bfd_size_type)-1) {
                _bfd_stringtab_free(strtab);
                return false;
            }
        }
    }

    if (bfd_seek(abfd, obj_sym_filepos(abfd), SEEK_SET) != 0) {
        _bfd_stringtab_free(strtab);
        return false;
    }

    written = 0;
    for (p = abfd->outsymbols, i = 0; i < limit; i++, p++) {
        asymbol *symbol = *p;
        coff_symbol_type *c_symbol = coff_symbol_from(symbol);

        if (!c_symbol || !c_symbol->native) {
            if (!coff_write_alien_symbol(abfd, symbol, NULL, &written,
                                         strtab, true, &debug_string_section,
                                         &debug_string_size)) {
                _bfd_stringtab_free(strtab);
                return false;
            }
            continue;
        }

        if (coff_backend_info(abfd)->_bfd_coff_classify_symbol) {
            bfd_error_handler_type prev_handler = bfd_set_error_handler(null_error_handler);
            BFD_ASSERT(c_symbol->native->is_sym);
            enum coff_symbol_classification sym_class =
                bfd_coff_classify_symbol(abfd, &c_symbol->native->u.syment);
            (void) bfd_set_error_handler(prev_handler);

            unsigned char *n_sclass = &c_symbol->native->u.syment.n_sclass;

            if (symbol->flags & BSF_WEAK) {
                *n_sclass = obj_pe(abfd) ? C_NT_WEAK : C_WEAKEXT;
            } else if ((symbol->flags & BSF_LOCAL) && sym_class != COFF_SYMBOL_LOCAL) {
                *n_sclass = C_STAT;
            } else if ((symbol->flags & BSF_GLOBAL)
                       && (sym_class != COFF_SYMBOL_GLOBAL
#ifdef COFF_WITH_PE
                           || *n_sclass == C_NT_WEAK
#endif
                           || *n_sclass == C_WEAKEXT)) {
                *n_sclass = C_EXT;
            }
        }

        if (!coff_write_native_symbol(abfd, c_symbol, &written,
                                      strtab, &debug_string_section,
                                      &debug_string_size)) {
            _bfd_stringtab_free(strtab);
            return false;
        }
    }

    obj_raw_syment_count(abfd) = written;

    {
        bfd_byte buffer[STRING_SIZE_SIZE];

#if STRING_SIZE_SIZE == 4
        H_PUT_32(abfd, _bfd_stringtab_size(strtab) + STRING_SIZE_SIZE, buffer);
#else
#error Change H_PUT_32
#endif
        if (bfd_write(buffer, sizeof(buffer), abfd) != sizeof(buffer)) {
            _bfd_stringtab_free(strtab);
            return false;
        }

        if (!_bfd_stringtab_emit(abfd, strtab)) {
            _bfd_stringtab_free(strtab);
            return false;
        }
    }

    _bfd_stringtab_free(strtab);

    BFD_ASSERT(debug_string_size == 0
             || (debug_string_section != NULL
                 && BFD_ALIGN(debug_string_size,
                              1 << debug_string_section->alignment_power)
                    == debug_string_section->size));

    return true;
}

bool coff_write_linenumbers(bfd *abfd)
{
    if (!abfd)
        return false;

    bfd_size_type linesz = bfd_coff_linesz(abfd);
    void *buff = bfd_alloc(abfd, linesz);
    if (!buff)
        return false;

    for (asection *s = abfd->sections; s; s = s->next)
    {
        if (s->lineno_count == 0)
            continue;

        if (bfd_seek(abfd, s->line_filepos, SEEK_SET) != 0)
        {
            bfd_release(abfd, buff);
            return false;
        }

        for (asymbol **q = abfd->outsymbols; q && *q; ++q)
        {
            asymbol *p = *q;
            if (!p || !p->section || p->section->output_section != s)
                continue;

            alent *l = BFD_SEND(bfd_asymbol_bfd(p), _get_lineno, (bfd_asymbol_bfd(p), p));
            if (!l)
                continue;

            struct internal_lineno out;
            memset(&out, 0, sizeof(out));
            out.l_lnno = 0;
            out.l_addr.l_symndx = l->u.offset;
            bfd_coff_swap_lineno_out(abfd, &out, buff);
            if (bfd_write(buff, linesz, abfd) != linesz)
            {
                bfd_release(abfd, buff);
                return false;
            }

            ++l;
            while (l->line_number)
            {
                out.l_lnno = l->line_number;
                out.l_addr.l_symndx = l->u.offset;
                bfd_coff_swap_lineno_out(abfd, &out, buff);
                if (bfd_write(buff, linesz, abfd) != linesz)
                {
                    bfd_release(abfd, buff);
                    return false;
                }
                ++l;
            }
        }
    }

    bfd_release(abfd, buff);
    return true;
}

alent *
coff_get_lineno(bfd *ignore_abfd, asymbol *symbol)
{
  if (symbol == NULL) {
    return NULL;
  }
  return coffsymbol(symbol) ? coffsymbol(symbol)->lineno : NULL;
}

/* This function transforms the offsets into the symbol table into
   pointers to syments.  */

static void coff_pointerize_aux(bfd *abfd,
                                combined_entry_type *table_base,
                                combined_entry_type *symbol,
                                unsigned int indaux,
                                combined_entry_type *auxent)
{
    unsigned int type, n_sclass;
    const coff_backend_info_type *backend;

    BFD_ASSERT(symbol->is_sym);

    backend = coff_backend_info(abfd);
    type = symbol->u.syment.n_type;
    n_sclass = symbol->u.syment.n_sclass;

    if (backend->_bfd_coff_pointerize_aux_hook) {
        if (backend->_bfd_coff_pointerize_aux_hook(abfd, table_base, symbol, indaux, auxent)) {
            return;
        }
    }

    /* Ignore file or section and certain special classes */
    if ((n_sclass == C_STAT && type == T_NULL) ||
        n_sclass == C_FILE ||
        n_sclass == C_DWARF) {
        return;
    }

    BFD_ASSERT(!auxent->is_sym);

    if ((ISFCN(type) || ISTAG(n_sclass) || n_sclass == C_BLOCK || n_sclass == C_FCN) &&
        auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32 > 0 &&
        auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32 < obj_raw_syment_count(abfd)) {
        auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p =
            table_base + auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32;
        auxent->fix_end = 1;
    }

    if (auxent->u.auxent.x_sym.x_tagndx.u32 < obj_raw_syment_count(abfd)) {
        auxent->u.auxent.x_sym.x_tagndx.p =
            table_base + auxent->u.auxent.x_sym.x_tagndx.u32;
        auxent->fix_tag = 1;
    }
}

/* Allocate space for the ".debug" section, and read it.
   We did not read the debug section until now, because
   we didn't want to go to the trouble until someone needed it.  */

static char *
build_debug_section(bfd *abfd, asection **sect_return)
{
    asection *sect;
    char *debug_section = NULL;
    file_ptr position;
    bfd_size_type sec_size;

    if (!abfd || !sect_return) {
        return NULL;
    }

    sect = bfd_get_section_by_name(abfd, ".debug");
    if (!sect) {
        bfd_set_error(bfd_error_no_debug_section);
        return NULL;
    }

    position = bfd_tell(abfd);
    if (position == (file_ptr)(-1)) {
        return NULL;
    }

    if (bfd_seek(abfd, sect->filepos, SEEK_SET) != 0) {
        return NULL;
    }

    sec_size = sect->size;
    if (sec_size == 0 || sec_size > (bfd_size_type)(-2)) {
        bfd_seek(abfd, position, SEEK_SET);
        return NULL;
    }

    debug_section = (char *)_bfd_alloc_and_read(abfd, sec_size + 1, sec_size);
    if (!debug_section) {
        bfd_seek(abfd, position, SEEK_SET);
        return NULL;
    }
    debug_section[sec_size] = '\0';

    if (bfd_seek(abfd, position, SEEK_SET) != 0) {
        free(debug_section);
        return NULL;
    }

    *sect_return = sect;
    return debug_section;
}

/* Return a pointer to a malloc'd copy of 'name'.  'name' may not be
   \0-terminated, but will not exceed 'maxlen' characters.  The copy *will*
   be \0-terminated.  */

static char *
copy_name(bfd *abfd, const char *name, size_t maxlen)
{
    if (name == NULL || abfd == NULL)
        return NULL;

    size_t len = 0;
    while (len < maxlen && name[len] != '\0')
        ++len;

    char *newname = (char *)bfd_alloc(abfd, (bfd_size_type)len + 1);
    if (newname == NULL)
        return NULL;

    if (len > 0)
        memcpy(newname, name, len);

    newname[len] = '\0';
    return newname;
}

/* Read in the external symbols.  */

bool _bfd_coff_get_external_symbols(bfd *abfd)
{
    size_t symesz;
    size_t size;
    void *syms;
    ufile_ptr filesize;
    ufile_ptr sym_filepos;

    if (obj_coff_external_syms(abfd))
        return true;

    symesz = bfd_coff_symesz(abfd);

    if (_bfd_mul_overflow(obj_raw_syment_count(abfd), symesz, &size) || size == 0)
    {
        if (size == 0)
            return true;
        bfd_set_error(bfd_error_file_truncated);
        return false;
    }

    filesize = bfd_get_file_size(abfd);
    sym_filepos = obj_sym_filepos(abfd);

    if (filesize != 0 &&
        (sym_filepos > filesize || size > (filesize - sym_filepos)))
    {
        bfd_set_error(bfd_error_file_truncated);
        return false;
    }

    if (bfd_seek(abfd, sym_filepos, SEEK_SET) != 0)
        return false;

    syms = _bfd_malloc_and_read(abfd, size, size);

    if (!syms)
        return false;

    obj_coff_external_syms(abfd) = syms;
    return true;
}

/* Read in the external strings.  The strings are not loaded until
   they are needed.  This is because we have no simple way of
   detecting a missing string table in an archive.  If the strings
   are loaded then the STRINGS and STRINGS_LEN fields in the
   coff_tdata structure will be set.  */

const char *
_bfd_coff_read_string_table(bfd *abfd)
{
  char extstrsize[STRING_SIZE_SIZE];
  bfd_size_type strsize;
  char *strings = NULL;
  ufile_ptr pos, filesize;
  size_t symesz, size;

  if (obj_coff_strings(abfd))
    return obj_coff_strings(abfd);

  if (!obj_sym_filepos(abfd)) {
    bfd_set_error(bfd_error_no_symbols);
    return NULL;
  }

  symesz = bfd_coff_symesz(abfd);
  pos = obj_sym_filepos(abfd);
  if (_bfd_mul_overflow(obj_raw_syment_count(abfd), symesz, &size) || (pos + size < pos)) {
    bfd_set_error(bfd_error_file_truncated);
    return NULL;
  }

  if (bfd_seek(abfd, pos + size, SEEK_SET) != 0)
    return NULL;

  if (bfd_read(extstrsize, sizeof(extstrsize), abfd) != sizeof(extstrsize)) {
    if (bfd_get_error() != bfd_error_file_truncated)
      return NULL;
    strsize = STRING_SIZE_SIZE;
  } else {
#if STRING_SIZE_SIZE == 4
    strsize = H_GET_32(abfd, extstrsize);
#else
 #error Change H_GET_32
#endif
  }

  filesize = bfd_get_file_size(abfd);
  if (strsize < STRING_SIZE_SIZE || (filesize && strsize > filesize)) {
    _bfd_error_handler(_("%pB: bad string table size %" PRIu64), abfd, (uint64_t)strsize);
    bfd_set_error(bfd_error_bad_value);
    return NULL;
  }

  strings = (char *)bfd_malloc(strsize + 1);
  if (!strings)
    return NULL;

  memset(strings, 0, STRING_SIZE_SIZE);

  if (bfd_read(strings + STRING_SIZE_SIZE, strsize - STRING_SIZE_SIZE, abfd) != (strsize - STRING_SIZE_SIZE)) {
    free(strings);
    return NULL;
  }

  obj_coff_strings(abfd) = strings;
  obj_coff_strings_len(abfd) = strsize;
  strings[strsize] = 0;
  return strings;
}

/* Free up the external symbols and strings read from a COFF file.  */

bool _bfd_coff_free_symbols(bfd *abfd)
{
    if (!bfd_family_coff(abfd))
        return false;

    if (obj_coff_external_syms(abfd) && !obj_coff_keep_syms(abfd)) {
        free(obj_coff_external_syms(abfd));
        obj_coff_external_syms(abfd) = NULL;
    }

    if (obj_coff_strings(abfd) && !obj_coff_keep_strings(abfd)) {
        free(obj_coff_strings(abfd));
        obj_coff_strings(abfd) = NULL;
        obj_coff_strings_len(abfd) = 0;
    }

    return true;
}

/* Read a symbol table into freshly bfd_allocated memory, swap it, and
   knit the symbol names into a normalized form.  By normalized here I
   mean that all symbols have an n_offset pointer that points to a null-
   terminated string.  */

combined_entry_type *
coff_get_normalized_symtab(bfd *abfd)
{
    combined_entry_type *internal;
    combined_entry_type *internal_ptr;
    size_t symesz;
    char *raw_src;
    char *raw_end;
    const char *string_table = NULL;
    asection *debug_sec = NULL;
    char *debug_sec_data = NULL;
    bfd_size_type count, alloc_size;

    if (obj_raw_syments(abfd) != NULL)
        return obj_raw_syments(abfd);

    if (!_bfd_coff_get_external_symbols(abfd))
        return NULL;

    count = obj_raw_syment_count(abfd);
    if (count > (bfd_size_type)-1 / sizeof(combined_entry_type))
        return NULL;

    alloc_size = count * sizeof(combined_entry_type);
    internal = (combined_entry_type *)bfd_zalloc(abfd, alloc_size);
    if (internal == NULL && alloc_size != 0)
        return NULL;

    symesz = bfd_coff_symesz(abfd);
    raw_src = (char *)obj_coff_external_syms(abfd);
    raw_end = PTR_ADD(raw_src, count * symesz);

    internal_ptr = internal;
    while (raw_src < raw_end) {
        unsigned int i;

        bfd_coff_swap_sym_in(abfd, (void *)raw_src, (void *)&internal_ptr->u.syment);
        internal_ptr->is_sym = true;
        combined_entry_type *sym = internal_ptr;

        if (sym->u.syment.n_numaux > ((raw_end - 1) - raw_src) / symesz)
            return NULL;

        for (i = 0; i < sym->u.syment.n_numaux; i++) {
            internal_ptr++;
            raw_src += symesz;

            bfd_coff_swap_aux_in(
                abfd, (void *)raw_src,
                sym->u.syment.n_type,
                sym->u.syment.n_sclass,
                (int)i, sym->u.syment.n_numaux,
                &(internal_ptr->u.auxent)
            );
            internal_ptr->is_sym = false;
            coff_pointerize_aux(abfd, internal, sym, i, internal_ptr);
        }

        if (sym->u.syment.n_sclass == C_FILE && sym->u.syment.n_numaux > 0) {
            combined_entry_type *aux = sym + 1;

            BFD_ASSERT(!aux->is_sym);

            if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0) {
                if (string_table == NULL) {
                    string_table = _bfd_coff_read_string_table(abfd);
                    if (string_table == NULL)
                        return NULL;
                }
                if ((bfd_size_type)aux->u.auxent.x_file.x_n.x_n.x_offset >= obj_coff_strings_len(abfd))
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)bfd_symbol_error_name;
                else
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)(string_table + aux->u.auxent.x_file.x_n.x_n.x_offset);
            } else {
                size_t len;
                char *src;
                if (sym->u.syment.n_numaux > 1 && obj_pe(abfd)) {
                    len = sym->u.syment.n_numaux * symesz;
                    src = raw_src - (len - symesz);
                } else {
                    len = bfd_coff_filnmlen(abfd);
                    src = aux->u.auxent.x_file.x_n.x_fname;
                }
                sym->u.syment._n._n_n._n_offset = (uintptr_t)copy_name(abfd, src, len);
            }

            if (!obj_pe(abfd)) {
                int numaux;
                for (numaux = 1; numaux < sym->u.syment.n_numaux; numaux++) {
                    aux = sym + numaux + 1;
                    BFD_ASSERT(!aux->is_sym);
                    if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0) {
                        if (string_table == NULL) {
                            string_table = _bfd_coff_read_string_table(abfd);
                            if (string_table == NULL)
                                return NULL;
                        }
                        if ((bfd_size_type)aux->u.auxent.x_file.x_n.x_n.x_offset >= obj_coff_strings_len(abfd))
                            aux->u.auxent.x_file.x_n.x_n.x_offset = (uintptr_t)bfd_symbol_error_name;
                        else
                            aux->u.auxent.x_file.x_n.x_n.x_offset = (uintptr_t)(string_table + aux->u.auxent.x_file.x_n.x_n.x_offset);
                    } else {
                        aux->u.auxent.x_file.x_n.x_n.x_offset =
                            (uintptr_t)copy_name(abfd,
                                aux->u.auxent.x_file.x_n.x_fname,
                                bfd_coff_filnmlen(abfd));
                    }
                }
            }
        } else {
            if (sym->u.syment._n._n_n._n_zeroes != 0) {
                size_t name_len = 0;
                while (name_len < SYMNMLEN && sym->u.syment._n._n_name[name_len] != '\0')
                    ++name_len;
                char *newstring = bfd_alloc(abfd, name_len + 1);
                if (newstring == NULL)
                    return NULL;
                memcpy(newstring, sym->u.syment._n._n_name, name_len);
                newstring[name_len] = 0;
                sym->u.syment._n._n_n._n_offset = (uintptr_t)newstring;
                sym->u.syment._n._n_n._n_zeroes = 0;
            } else if (sym->u.syment._n._n_n._n_offset == 0) {
                sym->u.syment._n._n_n._n_offset = (uintptr_t)"";
            } else if (!bfd_coff_symname_in_debug(abfd, &sym->u.syment)) {
                if (string_table == NULL) {
                    string_table = _bfd_coff_read_string_table(abfd);
                    if (string_table == NULL)
                        return NULL;
                }
                if (sym->u.syment._n._n_n._n_offset >= obj_coff_strings_len(abfd))
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)bfd_symbol_error_name;
                else
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)(string_table + sym->u.syment._n._n_n._n_offset);
            } else {
                if (debug_sec_data == NULL) {
                    debug_sec_data = build_debug_section(abfd, &debug_sec);
                    if (debug_sec_data == NULL)
                        return NULL;
                }
                if (sym->u.syment._n._n_n._n_offset >= debug_sec->size)
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)bfd_symbol_error_name;
                else
                    sym->u.syment._n._n_n._n_offset = (uintptr_t)(debug_sec_data + sym->u.syment._n._n_n._n_offset);
            }
        }

        raw_src += symesz;
        internal_ptr++;
    }

    if (obj_coff_external_syms(abfd) != NULL && !obj_coff_keep_syms(abfd)) {
        free(obj_coff_external_syms(abfd));
        obj_coff_external_syms(abfd) = NULL;
    }

    obj_raw_syments(abfd) = internal;
    BFD_ASSERT(obj_raw_syment_count(abfd) == (size_t)(internal_ptr - internal));

    return internal;
}

long coff_get_reloc_upper_bound(bfd *abfd, sec_ptr asect) {
    size_t count;
    size_t raw;

    if (!abfd || !asect) {
        bfd_set_error(bfd_error_invalid_operation);
        return -1;
    }

    count = asect->reloc_count;

    if (count >= LONG_MAX / sizeof(arelent *) ||
        _bfd_mul_overflow(count, bfd_coff_relsz(abfd), &raw)) {
        bfd_set_error(bfd_error_file_too_big);
        return -1;
    }

    if (!bfd_write_p(abfd)) {
        ufile_ptr filesize = bfd_get_file_size(abfd);
        if (filesize != 0 && raw > filesize) {
            bfd_set_error(bfd_error_file_truncated);
            return -1;
        }
    }

    if (count >= LONG_MAX - 1) {
        bfd_set_error(bfd_error_file_too_big);
        return -1;
    }

    return ((long)(count + 1)) * (long)sizeof(arelent *);
}

asymbol *coff_make_empty_symbol(bfd *abfd)
{
  size_t amt = sizeof(coff_symbol_type);
  coff_symbol_type *new_symbol = (coff_symbol_type *)bfd_zalloc(abfd, amt);

  if (!new_symbol)
    return NULL;

  new_symbol->symbol.section = NULL;
  new_symbol->native = NULL;
  new_symbol->lineno = NULL;
  new_symbol->done_lineno = false;
  new_symbol->symbol.the_bfd = abfd;

  return &new_symbol->symbol;
}

/* Make a debugging symbol.  */

asymbol *coff_bfd_make_debug_symbol(bfd *abfd)
{
    size_t aux_count = 10;
    size_t symbol_size = sizeof(coff_symbol_type);
    size_t native_size = sizeof(combined_entry_type) * aux_count;

    coff_symbol_type *new_symbol = (coff_symbol_type *)bfd_alloc(abfd, symbol_size);
    if (!new_symbol)
        return NULL;

    new_symbol->native = (combined_entry_type *)bfd_zalloc(abfd, native_size);
    if (!new_symbol->native)
        return NULL;

    new_symbol->native->is_sym = true;
    new_symbol->symbol.section = bfd_abs_section_ptr;
    new_symbol->symbol.flags = BSF_DEBUGGING;
    new_symbol->lineno = NULL;
    new_symbol->done_lineno = false;
    new_symbol->symbol.the_bfd = abfd;

    return &new_symbol->symbol;
}

void coff_get_symbol_info(bfd *abfd, asymbol *symbol, symbol_info *ret)
{
    bfd_symbol_info(symbol, ret);

    coff_symbol_type *csym = coffsymbol(symbol);
    if (!csym) return;

    void *native = csym->native;
    if (!native) return;

    if (((COFF_NATIVE_TYPE*)native)->fix_value && ((COFF_NATIVE_TYPE*)native)->is_sym)
    {
        uintptr_t syment_value = (uintptr_t)((COFF_NATIVE_TYPE*)native)->u.syment.n_value;
        uintptr_t raw_syments = (uintptr_t)obj_raw_syments(abfd);
        ret->value = (syment_value - raw_syments) / sizeof(combined_entry_type);
    }
}

/* Print out information about COFF symbol.  */

void coff_print_symbol(bfd *abfd, void *filep, asymbol *symbol, bfd_print_symbol_type how)
{
    FILE *file = (FILE *)filep;
    const char *symname = (symbol->name != bfd_symbol_error_name) ? symbol->name : _("<corrupt>");
    switch (how)
    {
        case bfd_print_symbol_name:
            fprintf(file, "%s", symname);
            break;

        case bfd_print_symbol_more:
            fprintf(file, "coff %s %s",
                    coffsymbol(symbol)->native ? "n" : "g",
                    coffsymbol(symbol)->lineno ? "l" : " ");
            break;

        case bfd_print_symbol_all:
        {
            if (coffsymbol(symbol)->native)
            {
                bfd_vma val;
                unsigned int aux;
                combined_entry_type *combined = coffsymbol(symbol)->native;
                combined_entry_type *root = obj_raw_syments(abfd);
                struct lineno_cache_entry *l = coffsymbol(symbol)->lineno;

                long index = (long)(combined - root);

                if (combined < root ||
                    combined >= root + obj_raw_syment_count(abfd))
                {
                    fprintf(file, "[???] <corrupt info> %s", symname);
                    break;
                }

                fprintf(file, "[%3ld]", index);

                BFD_ASSERT(combined->is_sym);
                val = !combined->fix_value
                    ? (bfd_vma)combined->u.syment.n_value
                    : (((uintptr_t)combined->u.syment.n_value - (uintptr_t)root) / sizeof(combined_entry_type));

                fprintf(file, "(sec %2d)(fl 0x%02x)(ty %4x)(scl %3d) (nx %d) 0x",
                        combined->u.syment.n_scnum,
                        combined->u.syment.n_flags,
                        combined->u.syment.n_type,
                        combined->u.syment.n_sclass,
                        combined->u.syment.n_numaux);

                bfd_fprintf_vma(abfd, file, val);
                fprintf(file, " %s", symname);

                for (aux = 0; aux < combined->u.syment.n_numaux; aux++)
                {
                    combined_entry_type *auxp = combined + aux + 1;
                    long tagndx;

                    BFD_ASSERT(!auxp->is_sym);

                    tagndx = auxp->fix_tag
                        ? (long)(auxp->u.auxent.x_sym.x_tagndx.p - root)
                        : auxp->u.auxent.x_sym.x_tagndx.u32;

                    fprintf(file, "\n");

                    if (bfd_coff_print_aux(abfd, file, root, combined, auxp, aux))
                        continue;

                    switch (combined->u.syment.n_sclass)
                    {
                        case C_FILE:
                            fprintf(file, "File ");
                            if (auxp->u.auxent.x_file.x_ftype)
                                fprintf(file, "ftype %d fname \"%s\"",
                                        auxp->u.auxent.x_file.x_ftype,
                                        (char *)auxp->u.auxent.x_file.x_n.x_n.x_offset);
                            break;

                        case C_DWARF:
                            fprintf(file, "AUX scnlen %#" PRIx64 " nreloc %" PRId64,
                                    auxp->u.auxent.x_sect.x_scnlen,
                                    auxp->u.auxent.x_sect.x_nreloc);
                            break;

                        case C_STAT:
                            if (combined->u.syment.n_type == T_NULL)
                            {
                                fprintf(file, "AUX scnlen 0x%lx nreloc %d nlnno %d",
                                        (unsigned long)auxp->u.auxent.x_scn.x_scnlen,
                                        auxp->u.auxent.x_scn.x_nreloc,
                                        auxp->u.auxent.x_scn.x_nlinno);
                                if (auxp->u.auxent.x_scn.x_checksum != 0
                                    || auxp->u.auxent.x_scn.x_associated != 0
                                    || auxp->u.auxent.x_scn.x_comdat != 0)
                                    fprintf(file, " checksum 0x%x assoc %d comdat %d",
                                            auxp->u.auxent.x_scn.x_checksum,
                                            auxp->u.auxent.x_scn.x_associated,
                                            auxp->u.auxent.x_scn.x_comdat);
                                break;
                            }
                            // fall through

                        case C_EXT:
                        case C_AIX_WEAKEXT:
                            if (ISFCN(combined->u.syment.n_type))
                            {
                                long next, llnos;
                                next = auxp->fix_end
                                    ? (long)(auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p - root)
                                    : auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32;
                                llnos = auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_lnnoptr;
                                fprintf(file,
                                        "AUX tagndx %ld ttlsiz 0x%lx lnnos %ld next %ld",
                                        tagndx,
                                        (unsigned long)auxp->u.auxent.x_sym.x_misc.x_fsize,
                                        llnos, next);
                                break;
                            }
                            // fall through
                        default:
                            fprintf(file, "AUX lnno %d size 0x%x tagndx %ld",
                                    auxp->u.auxent.x_sym.x_misc.x_lnsz.x_lnno,
                                    auxp->u.auxent.x_sym.x_misc.x_lnsz.x_size,
                                    tagndx);
                            if (auxp->fix_end)
                                fprintf(file, " endndx %ld",
                                        (long)(auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p - root));
                            break;
                    }
                }

                if (l)
                {
                    fprintf(file, "\n%s :", (l->u.sym->name != bfd_symbol_error_name) ? l->u.sym->name : _("<corrupt>"));
                    l++;
                    while (l->line_number)
                    {
                        if (l->line_number > 0)
                        {
                            fprintf(file, "\n%4d : ", l->line_number);
                            bfd_fprintf_vma(abfd, file, l->u.offset + symbol->section->vma);
                        }
                        l++;
                    }
                }
            }
            else
            {
                bfd_print_symbol_vandf(abfd, file, symbol);
                fprintf(file, " %-5s %s %s %s",
                        symbol->section->name,
                        coffsymbol(symbol)->native ? "n" : "g",
                        coffsymbol(symbol)->lineno ? "l" : " ",
                        symname);
            }
        }
        break;

        default:
            break;
    }
}

/* Return whether a symbol name implies a local symbol.  In COFF,
   local symbols generally start with ``.L''.  Most targets use this
   function for the is_local_label_name entry point, but some may
   override it.  */

bool _bfd_coff_is_local_label_name(bfd *abfd ATTRIBUTE_UNUSED, const char *name) {
  if (!name || name[0] != '.' || name[1] != 'L') {
    return false;
  }
  return true;
}

/* Provided a BFD, a section and an offset (in bytes, not octets) into the
   section, calculate and return the name of the source file and the line
   nearest to the wanted location.  */

bool coff_find_nearest_line_with_names(
    bfd *abfd,
    asymbol **symbols,
    asection *section,
    bfd_vma offset,
    const char **filename_ptr,
    const char **functionname_ptr,
    unsigned int *line_ptr,
    const struct dwarf_debug_section *debug_sections
) {
    unsigned int i = 0, line_base = 0;
    coff_data_type *cof = coff_data(abfd);
    combined_entry_type *p, *pend;
    alent *l;
    struct coff_section_tdata *sec_data;
    size_t amt;

    if (!_bfd_stab_section_find_nearest_line(abfd, symbols, section, offset,
                                             NULL, filename_ptr, functionname_ptr,
                                             line_ptr, &coff_data(abfd)->line_info))
        return false;
    if (*filename_ptr || *functionname_ptr || *line_ptr)
        return true;

    if (_bfd_dwarf2_find_nearest_line(abfd, symbols, NULL, section, offset,
                                      filename_ptr, functionname_ptr, line_ptr,
                                      NULL, debug_sections,
                                      &coff_data(abfd)->dwarf2_find_line_info))
        return true;

    sec_data = coff_section_data(abfd, section);

    if (coff_data(abfd)->dwarf2_find_line_info) {
        bfd_signed_vma bias = 0;

        if (!sec_data && section->owner == abfd) {
            amt = sizeof(struct coff_section_tdata);
            section->used_by_bfd = bfd_zalloc(abfd, amt);
            sec_data = (struct coff_section_tdata *)section->used_by_bfd;
        }

        if (sec_data && sec_data->saved_bias) {
            bias = sec_data->bias;
        } else if (symbols) {
            bias = _bfd_dwarf2_find_symbol_bias(symbols,
                  &coff_data(abfd)->dwarf2_find_line_info);
            if (sec_data) {
                sec_data->saved_bias = true;
                sec_data->bias = bias;
            }
        }
        if (bias &&
            _bfd_dwarf2_find_nearest_line(abfd, symbols, NULL, section,
                                          offset + bias, filename_ptr, functionname_ptr,
                                          line_ptr, NULL, debug_sections,
                                          &coff_data(abfd)->dwarf2_find_line_info))
            return true;
    }

    *filename_ptr = NULL;
    *functionname_ptr = NULL;
    *line_ptr = 0;

    if (!bfd_family_coff(abfd) || !cof)
        return false;

    p = cof->raw_syments;
    if (!p)
        return false;
    pend = p + cof->raw_syment_count;
    while (p < pend) {
        if (!p->is_sym) return false;
        if (p->u.syment.n_sclass == C_FILE)
            break;
        p += 1 + p->u.syment.n_numaux;
    }
    if (p < pend) {
        bfd_vma sec_vma = bfd_section_vma(section);
        bfd_vma maxdiff = (bfd_vma)0 - (bfd_vma)1;
        *filename_ptr = (char *)p->u.syment._n._n_n._n_offset;
        while (1) {
            bfd_vma file_addr;
            combined_entry_type *p2;

            for (p2 = p + 1 + p->u.syment.n_numaux; p2 < pend; p2 += 1 + p2->u.syment.n_numaux) {
                if (!p2->is_sym) return false;
                if (p2->u.syment.n_scnum > 0 &&
                    section == coff_section_from_bfd_index(abfd, p2->u.syment.n_scnum))
                    break;
                if (p2->u.syment.n_sclass == C_FILE) {
                    p2 = pend;
                    break;
                }
            }
            if (p2 >= pend)
                break;
            file_addr = (bfd_vma)p2->u.syment.n_value;
            if (p2->u.syment.n_scnum > 0)
                file_addr += coff_section_from_bfd_index(abfd, p2->u.syment.n_scnum)->vma;

            if (p2 < pend &&
                offset + sec_vma >= file_addr &&
                offset + sec_vma - file_addr <= maxdiff) {
                *filename_ptr = (char *)p->u.syment._n._n_n._n_offset;
                maxdiff = offset + sec_vma - p2->u.syment.n_value;
            }
            if (p->u.syment.n_value >= cof->raw_syment_count)
                break;
            if (p >= cof->raw_syments + p->u.syment.n_value)
                break;
            p = cof->raw_syments + p->u.syment.n_value;
            if (!p->is_sym || p->u.syment.n_sclass != C_FILE)
                break;
        }
    }

    if (section->lineno_count == 0) {
        *functionname_ptr = NULL;
        *line_ptr = 0;
        return true;
    }

    if (sec_data && sec_data->i > 0 && offset >= sec_data->offset) {
        i = sec_data->i;
        *functionname_ptr = sec_data->function;
        line_base = sec_data->line_base;
    } else {
        i = 0;
        line_base = 0;
    }

    if (section->lineno) {
        bfd_vma last_value = 0;
        l = &section->lineno[i];
        for (; i < section->lineno_count; i++, l++) {
            if (l->line_number == 0) {
                coff_symbol_type *coff = (coff_symbol_type *)(l->u.sym);
                if (coff->symbol.value > offset)
                    break;
                *functionname_ptr = coff->symbol.name;
                last_value = coff->symbol.value;
                if (coff->native) {
                    combined_entry_type *s = coff->native;
                    if (!s->is_sym) return false;
                    s = s + 1 + s->u.syment.n_numaux;

                    if ((size_t)((char *)s - (char *)obj_raw_syments(abfd)) <
                        obj_raw_syment_count(abfd) * sizeof(*s) &&
                        s->u.syment.n_scnum == N_DEBUG)
                        s = s + 1 + s->u.syment.n_numaux;

                    if ((size_t)((char *)s - (char *)obj_raw_syments(abfd)) <
                        obj_raw_syment_count(abfd) * sizeof(*s) &&
                        s->u.syment.n_numaux) {
                        union internal_auxent *a = &((s + 1)->u.auxent);
                        line_base = a->x_sym.x_misc.x_lnsz.x_lnno;
                        *line_ptr = line_base;
                    }
                }
            } else {
                if (l->u.offset > offset)
                    break;
                *line_ptr = l->line_number + line_base - 1;
            }
        }
        if (i >= section->lineno_count && last_value != 0 &&
            offset - last_value > 0x100) {
            *functionname_ptr = NULL;
            *line_ptr = 0;
        }
    }

    if (!sec_data && section->owner == abfd) {
        amt = sizeof(struct coff_section_tdata);
        section->used_by_bfd = bfd_zalloc(abfd, amt);
        sec_data = (struct coff_section_tdata *)section->used_by_bfd;
    }
    if (sec_data) {
        sec_data->offset = offset;
        sec_data->i = (i > 0) ? (i - 1) : 0;
        sec_data->function = *functionname_ptr;
        sec_data->line_base = line_base;
    }
    return true;
}

bool coff_find_nearest_line(bfd *abfd,
                            asymbol **symbols,
                            asection *section,
                            bfd_vma offset,
                            const char **filename_ptr,
                            const char **functionname_ptr,
                            unsigned int *line_ptr,
                            unsigned int *discriminator_ptr)
{
    if (discriminator_ptr != NULL)
        *discriminator_ptr = 0;

    if (!abfd || !symbols || !section || !filename_ptr || !functionname_ptr || !line_ptr)
        return false;

    return coff_find_nearest_line_with_names(abfd, symbols, section, offset,
                                             filename_ptr, functionname_ptr,
                                             line_ptr, dwarf_debug_sections);
}

bool coff_find_inliner_info(bfd *abfd,
                            const char **filename_ptr,
                            const char **functionname_ptr,
                            unsigned int *line_ptr)
{
    if (!abfd || !filename_ptr || !functionname_ptr || !line_ptr)
        return false;

    dwarf2_find_line_info_type *info = &coff_data(abfd)->dwarf2_find_line_info;
    if (!info)
        return false;

    return _bfd_dwarf2_find_inliner_info(abfd, filename_ptr, functionname_ptr, line_ptr, info);
}

int coff_sizeof_headers(bfd *abfd, struct bfd_link_info *info)
{
    size_t size = bfd_coff_filhsz(abfd);

    if (!bfd_link_relocatable(info)) {
        size += bfd_coff_aoutsz(abfd);
    }

    size += abfd->section_count * bfd_coff_scnhsz(abfd);

    if (size > INT_MAX) {
        return -1;
    }
    return (int)size;
}

/* Change the class of a coff symbol held by BFD.  */

bool bfd_coff_set_symbol_class(bfd *abfd, asymbol *symbol, unsigned int symbol_class) {
    coff_symbol_type *csym = coff_symbol_from(symbol);
    if (!csym) {
        bfd_set_error(bfd_error_invalid_operation);
        return false;
    }
    if (!csym->native) {
        combined_entry_type *native;
        size_t amt = sizeof(*native);

        native = (combined_entry_type *)bfd_zalloc(abfd, amt);
        if (!native)
            return false;

        native->is_sym = true;
        native->u.syment.n_type = T_NULL;
        native->u.syment.n_sclass = symbol_class;

        if (bfd_is_und_section(symbol->section) || bfd_is_com_section(symbol->section)) {
            native->u.syment.n_scnum = N_UNDEF;
            native->u.syment.n_value = symbol->value;
        } else if (symbol->section && symbol->section->output_section) {
            native->u.syment.n_scnum = symbol->section->output_section->target_index;
            native->u.syment.n_value = symbol->value + symbol->section->output_offset;
            if (!obj_pe(abfd))
                native->u.syment.n_value += symbol->section->output_section->vma;
            native->u.syment.n_flags = bfd_asymbol_bfd(&csym->symbol)->flags;
        } else {
            bfd_set_error(bfd_error_invalid_operation);
            return false;
        }

        csym->native = native;
    } else {
        csym->native->u.syment.n_sclass = symbol_class;
    }
    return true;
}

bool _bfd_coff_section_already_linked(bfd *abfd, asection *sec, struct bfd_link_info *info) {
    flagword flags;
    const char *name, *key;
    struct bfd_section_already_linked *l;
    struct bfd_section_already_linked_hash_entry *already_linked_list;
    struct coff_comdat_info *s_comdat;

    if (sec->output_section == bfd_abs_section_ptr)
        return false;

    flags = sec->flags;
    if ((flags & SEC_LINK_ONCE) == 0)
        return false;

    if ((flags & SEC_GROUP) != 0)
        return false;

    name = bfd_section_name(sec);
    s_comdat = bfd_coff_get_comdat_section(abfd, sec);

    if (s_comdat) {
        key = s_comdat->name;
    } else if (startswith(name, ".gnu.linkonce.")) {
        key = strchr(name + sizeof(".gnu.linkonce.") - 1, '.');
        key = key ? key + 1 : name;
    } else {
        key = name;
    }

    already_linked_list = bfd_section_already_linked_table_lookup(key);
    if (!already_linked_list) {
        info->callbacks->fatal(_("%P: already_linked_table: %E\n"));
        return false;
    }

    for (l = already_linked_list->entry; l; l = l->next) {
        struct coff_comdat_info *l_comdat = bfd_coff_get_comdat_section(l->sec->owner, l->sec);

        if ((((s_comdat != NULL) == (l_comdat != NULL) && strcmp(name, l->sec->name) == 0) ||
             (l->sec->owner->flags & BFD_PLUGIN) != 0 ||
             (sec->owner->flags & BFD_PLUGIN) != 0)) {
            return _bfd_handle_already_linked(sec, l, info);
        }
    }

    if (!bfd_section_already_linked_table_insert(already_linked_list, sec)) {
        info->callbacks->fatal(_("%P: already_linked_table: %E\n"));
    }
    return false;
}

/* Initialize COOKIE for input bfd ABFD. */

static bool
init_reloc_cookie(struct coff_reloc_cookie *cookie,
                  struct bfd_link_info *info ATTRIBUTE_UNUSED,
                  bfd *abfd)
{
    if (!cookie || !abfd)
        return false;

    if (!bfd_coff_slurp_symbol_table(abfd))
        return false;

    cookie->abfd = abfd;
    cookie->sym_hashes = obj_coff_sym_hashes(abfd);
    cookie->symbols = obj_symbols(abfd);

    if (!cookie->sym_hashes || !cookie->symbols)
        return false;

    return true;
}

/* Free the memory allocated by init_reloc_cookie, if appropriate.  */

static void fini_reloc_cookie(struct coff_reloc_cookie *cookie, bfd *abfd) {
  (void)cookie;
  (void)abfd;
}

/* Initialize the relocation information in COOKIE for input section SEC
   of input bfd ABFD.  */

static bool init_reloc_cookie_rels(struct coff_reloc_cookie *cookie, struct bfd_link_info *info ATTRIBUTE_UNUSED, bfd *abfd, asection *sec)
{
    if (!cookie || !abfd || !sec) {
        return false;
    }

    if (sec->reloc_count == 0) {
        cookie->rels = NULL;
        cookie->relend = NULL;
        cookie->rel = NULL;
        return true;
    }

    cookie->rels = _bfd_coff_read_internal_relocs(abfd, sec, false, NULL, 0, NULL);
    if (!cookie->rels) {
        cookie->rel = NULL;
        cookie->relend = NULL;
        return false;
    }

    cookie->rel = cookie->rels;
    cookie->relend = cookie->rels + sec->reloc_count;
    return true;
}

/* Free the memory allocated by init_reloc_cookie_rels,
   if appropriate.  */

static void fini_reloc_cookie_rels(struct coff_reloc_cookie *cookie, asection *sec) {
    struct coff_section_tdata *sec_data;

    if (!cookie || !sec)
        return;

    sec_data = coff_section_data(NULL, sec);
    if (!cookie->rels)
        return;

    if (sec_data && sec_data->relocs != cookie->rels)
        free(cookie->rels);
}

/* Initialize the whole of COOKIE for input section SEC.  */

static bool init_reloc_cookie_for_section(struct coff_reloc_cookie *cookie, struct bfd_link_info *info, asection *sec) {
  if (!init_reloc_cookie(cookie, info, sec->owner))
    return false;

  if (!init_reloc_cookie_rels(cookie, info, sec->owner, sec)) {
    fini_reloc_cookie(cookie, sec->owner);
    return false;
  }

  return true;
}

/* Free the memory allocated by init_reloc_cookie_for_section,
   if appropriate.  */

static void fini_reloc_cookie_for_section(struct coff_reloc_cookie *cookie, asection *sec)
{
    if (!cookie || !sec || !sec->owner)
        return;

    fini_reloc_cookie_rels(cookie, sec);
    fini_reloc_cookie(cookie, sec->owner);
}

static asection *
_bfd_coff_gc_mark_hook(asection *sec,
                       struct bfd_link_info *info ATTRIBUTE_UNUSED,
                       struct internal_reloc *rel ATTRIBUTE_UNUSED,
                       struct coff_link_hash_entry *h,
                       struct internal_syment *sym)
{
    if (h == NULL)
        return coff_section_from_bfd_index(sec->owner, sym->n_scnum);

    switch (h->root.type) {
    case bfd_link_hash_defined:
    case bfd_link_hash_defweak:
        return h->root.u.def.section;

    case bfd_link_hash_common:
        return h->root.u.c.p->section;

    case bfd_link_hash_undefweak:
        if (h->symbol_class == C_NT_WEAK && h->numaux == 1 &&
            h->auxbfd && h->auxbfd->tdata.coff_obj_data &&
            h->auxbfd->tdata.coff_obj_data->sym_hashes) {
            struct coff_link_hash_entry *h2 =
                h->auxbfd->tdata.coff_obj_data->sym_hashes[
                    h->aux->x_sym.x_tagndx.u32
                ];
            if (h2 && h2->root.type != bfd_link_hash_undefined)
                return h2->root.u.def.section;
        }
        break;

    case bfd_link_hash_undefined:
    default:
        break;
    }

    return NULL;
}

/* COOKIE->rel describes a relocation against section SEC, which is
   a section we've decided to keep.  Return the section that contains
   the relocation symbol, or NULL if no section contains it.  */

static asection *
_bfd_coff_gc_mark_rsec(struct bfd_link_info *info, asection *sec,
                       coff_gc_mark_hook_fn gc_mark_hook,
                       struct coff_reloc_cookie *cookie)
{
    struct coff_link_hash_entry *h = cookie->sym_hashes[cookie->rel->r_symndx];

    if (h) {
        while (h->root.type == bfd_link_hash_indirect ||
               h->root.type == bfd_link_hash_warning) {
            struct bfd_link_hash_entry *next = h->root.u.i.link;
            if (!next) break;
            h = (struct coff_link_hash_entry *)next;
        }
        return gc_mark_hook(sec, info, cookie->rel, h, NULL);
    }

    {
        size_t idx = obj_convert(sec->owner)[cookie->rel->r_symndx];
        void *syment_ptr = &(cookie->symbols[idx].native->u.syment);
        return gc_mark_hook(sec, info, cookie->rel, NULL, syment_ptr);
    }
}

static bool _bfd_coff_gc_mark
  (struct bfd_link_info *, asection *, coff_gc_mark_hook_fn);

/* COOKIE->rel describes a relocation against section SEC, which is
   a section we've decided to keep.  Mark the section that contains
   the relocation symbol.  */

static bool
_bfd_coff_gc_mark_reloc(struct bfd_link_info *info,
                        asection *sec,
                        coff_gc_mark_hook_fn gc_mark_hook,
                        struct coff_reloc_cookie *cookie)
{
    asection *rsec = _bfd_coff_gc_mark_rsec(info, sec, gc_mark_hook, cookie);

    if (!rsec || rsec->gc_mark) {
        return true;
    }

    if (bfd_get_flavour(rsec->owner) != bfd_target_coff_flavour) {
        rsec->gc_mark = 1;
        return true;
    }

    return _bfd_coff_gc_mark(info, rsec, gc_mark_hook);
}

/* The mark phase of garbage collection.  For a given section, mark
   it and any sections in this section's group, and all the sections
   which define symbols to which it refers.  */

static bool
_bfd_coff_gc_mark(struct bfd_link_info *info, asection *sec, coff_gc_mark_hook_fn gc_mark_hook)
{
    sec->gc_mark = 1;

    if ((sec->flags & SEC_RELOC) && sec->reloc_count > 0) {
        struct coff_reloc_cookie cookie;
        if (!init_reloc_cookie_for_section(&cookie, info, sec)) {
            return false;
        }
        for (; cookie.rel < cookie.relend; ++cookie.rel) {
            if (!_bfd_coff_gc_mark_reloc(info, sec, gc_mark_hook, &cookie)) {
                fini_reloc_cookie_for_section(&cookie, sec);
                return false;
            }
        }
        fini_reloc_cookie_for_section(&cookie, sec);
    }

    return true;
}

static bool
_bfd_coff_gc_mark_extra_sections(struct bfd_link_info *info,
                                 coff_gc_mark_hook_fn mark_hook ATTRIBUTE_UNUSED)
{
    for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next)
    {
        if (bfd_get_flavour(ibfd) != bfd_target_coff_flavour)
            continue;

        bool found_marked = false;
        for (asection *isec = ibfd->sections; isec; isec = isec->next)
        {
            if (isec->flags & SEC_LINKER_CREATED)
            {
                isec->gc_mark = 1;
            }
            else if (isec->gc_mark)
            {
                found_marked = true;
            }
        }

        if (!found_marked)
            continue;

        for (asection *isec = ibfd->sections; isec; isec = isec->next)
        {
            if ((isec->flags & SEC_DEBUGGING) ||
                (isec->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0)
            {
                isec->gc_mark = 1;
            }
        }
    }
    return true;
}

/* Sweep symbols in swept sections.  Called via coff_link_hash_traverse.  */

static bool
coff_gc_sweep_symbol(struct coff_link_hash_entry *h, void *data ATTRIBUTE_UNUSED)
{
  struct coff_link_hash_entry *entry = h;

  if (!entry)
    return false;

  if (entry->root.type == bfd_link_hash_warning && entry->root.u.i.link)
    entry = (struct coff_link_hash_entry *)entry->root.u.i.link;

  if ((entry->root.type == bfd_link_hash_defined || entry->root.type == bfd_link_hash_defweak) &&
      entry->root.u.def.section &&
      !entry->root.u.def.section->gc_mark &&
      entry->root.u.def.section->owner &&
      !(entry->root.u.def.section->owner->flags & DYNAMIC))
  {
    entry->root.u.def.section = bfd_und_section_ptr;
    entry->symbol_class = C_HIDDEN;
  }

  return true;
}

/* The sweep phase of garbage collection.  Remove all garbage sections.  */

typedef bool (*gc_sweep_hook_fn)
  (bfd *, struct bfd_link_info *, asection *, const struct internal_reloc *);

static inline bool
is_subsection(const char *str, const char *prefix)
{
    if (!str || !prefix)
        return false;

    size_t n = strlen(prefix);

    if (strncmp(str, prefix, n) != 0)
        return false;

    if (str[n] == '\0')
        return true;

    if (str[n] != '$')
        return false;

    return str[n + 1] != '\0' && ISDIGIT(str[n + 1]) && str[n + 2] == '\0';
}

static bool coff_gc_sweep(bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
    bfd *sub = info->input_bfds;
    while (sub) {
        if (bfd_get_flavour(sub) == bfd_target_coff_flavour) {
            asection *o = sub->sections;
            while (o) {
                bool keep_section = false;
                if ((o->flags & (SEC_DEBUGGING | SEC_LINKER_CREATED)) != 0 ||
                    (o->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0)
                {
                    keep_section = true;
                } else if (
                    startswith(o->name, ".idata") ||
                    startswith(o->name, ".pdata") ||
                    startswith(o->name, ".xdata") ||
                    is_subsection(o->name, ".didat") ||
                    startswith(o->name, ".rsrc"))
                {
                    keep_section = true;
                }

                if (keep_section) {
                    o->gc_mark = 1;
                }

                if (o->gc_mark || (o->flags & SEC_EXCLUDE)) {
                    o = o->next;
                    continue;
                }

                o->flags |= SEC_EXCLUDE;

                if (info->print_gc_sections && o->size != 0) {
                    _bfd_error_handler(_("removing unused section '%pA' in file '%pB'"), o, sub);
                }

                o = o->next;
            }
        }
        sub = sub->link.next;
    }

    coff_link_hash_traverse(coff_hash_table(info), coff_gc_sweep_symbol, NULL);

    return true;
}

/* Keep all sections containing symbols undefined on the command-line,
   and the section containing the entry symbol.  */

static void _bfd_coff_gc_keep(struct bfd_link_info *info)
{
    if (!info || !info->gc_sym_list)
        return;

    struct bfd_sym_chain *sym = info->gc_sym_list;
    while (sym) {
        struct coff_link_hash_entry *h = coff_link_hash_lookup(
            coff_hash_table(info), sym->name, false, false, false);

        if (h && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)) {
            asection *sec = h->root.u.def.section;
            if (sec && !bfd_is_abs_section(sec))
                sec->flags |= SEC_KEEP;
        }
        sym = sym->next;
    }
}

/* Do mark and sweep of unused sections.  */

bool bfd_coff_gc_sections(bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
    bfd *sub;

    _bfd_coff_gc_keep(info);

    for (sub = info->input_bfds; sub; sub = sub->link.next)
    {
        if (bfd_get_flavour(sub) != bfd_target_coff_flavour)
            continue;

        for (asection *o = sub->sections; o; o = o->next)
        {
            bool is_special = ((o->flags & (SEC_EXCLUDE | SEC_KEEP)) == SEC_KEEP)
                || startswith(o->name, ".vectors")
                || startswith(o->name, ".ctors")
                || startswith(o->name, ".dtors");

            if (is_special && !o->gc_mark)
            {
                if (!_bfd_coff_gc_mark(info, o, _bfd_coff_gc_mark_hook))
                    return false;
            }
        }
    }

    _bfd_coff_gc_mark_extra_sections(info, _bfd_coff_gc_mark_hook);

    return coff_gc_sweep(abfd, info);
}

/* Return name used to identify a comdat group.  */

const char *
bfd_coff_group_name(bfd *abfd, const asection *sec)
{
  struct coff_comdat_info *ci;
  if (!abfd || !sec)
    return NULL;
  ci = bfd_coff_get_comdat_section(abfd, sec);
  return ci ? ci->name : NULL;
}

bool _bfd_coff_free_cached_info(bfd *abfd)
{
    struct coff_tdata *tdata = NULL;

    if (!bfd_family_coff(abfd))
        return _bfd_generic_bfd_free_cached_info(abfd);

    int format = bfd_get_format(abfd);
    if (format != bfd_object && format != bfd_core)
        return _bfd_generic_bfd_free_cached_info(abfd);

    tdata = coff_data(abfd);
    if (!tdata)
        return _bfd_generic_bfd_free_cached_info(abfd);

    if (tdata->section_by_index) {
        htab_delete(tdata->section_by_index);
        tdata->section_by_index = NULL;
    }

    if (tdata->section_by_target_index) {
        htab_delete(tdata->section_by_target_index);
        tdata->section_by_target_index = NULL;
    }

    if (obj_pe(abfd)) {
        struct pe_tdata_struct *pe = pe_data(abfd);
        if (pe && pe->comdat_hash) {
            htab_delete(pe->comdat_hash);
            pe->comdat_hash = NULL;
        }
    }

    _bfd_dwarf2_cleanup_debug_info(abfd, &tdata->dwarf2_find_line_info);
    _bfd_stab_cleanup(abfd, &tdata->line_info);
    _bfd_coff_free_symbols(abfd);

    if (!obj_coff_keep_raw_syms(abfd) && obj_raw_syments(abfd)) {
        bfd_release(abfd, obj_raw_syments(abfd));
        obj_raw_syments(abfd) = NULL;
        obj_symbols(abfd) = NULL;
        obj_convert(abfd) = NULL;
    }

    return _bfd_generic_bfd_free_cached_info(abfd);
}
