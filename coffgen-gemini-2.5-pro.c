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

static char *
extract_long_section_name(bfd *abfd, unsigned long strindex)
{
  const char *strings = _bfd_coff_read_string_table(abfd);
  bfd_size_type string_table_len;

  if (strings == NULL)
  {
    return NULL;
  }

  string_table_len = obj_coff_strings_len(abfd);
  if ((bfd_size_type)strindex >= string_table_len)
  {
    return NULL;
  }

  return bfd_strdup(strings + strindex);
}

/* Decode a base 64 coded string at STR of length LEN, and write the result
   to RES.  Return true on success.
   Return false in case of invalid character or overflow.  */

static int
get_b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

static bool
decode_base64(const char *str, unsigned len, uint32_t *res)
{
    if (!str || !res) {
        return false;
    }

    uint32_t val = 0;
    const unsigned BITS_PER_B64_CHAR = 6;
    const unsigned OVERFLOW_CHECK_SHIFT = 32 - BITS_PER_B64_CHAR;

    for (unsigned i = 0; i < len; i++) {
        int decoded_val = get_b64_value(str[i]);
        if (decoded_val < 0) {
            return false;
        }

        if (val >> OVERFLOW_CHECK_SHIFT) {
            return false;
        }

        val = (val << BITS_PER_B64_CHAR) | (uint32_t)decoded_val;
    }

    *res = val;
    return true;
}

/* Take a section header read from a coff file (in HOST byte order),
   and make a BFD "section" out of it.  This is used by ECOFF.  */

static char *
get_section_name (bfd *abfd, const struct internal_scnhdr *hdr)
{
  if (bfd_coff_set_long_section_names (abfd, bfd_coff_long_section_names (abfd))
      && hdr->s_name[0] == '/')
    {
      bfd_coff_set_long_section_names (abfd, true);

      if (hdr->s_name[1] == '/')
	{
	  uint32_t strindex;
	  if (!decode_base64 (hdr->s_name + 2, SCNNMLEN - 2, &strindex))
	    return NULL;
	  return extract_long_section_name (abfd, strindex);
	}
      else
	{
	  char buf[SCNNMLEN];
	  char *p;
	  long strindex;

	  memcpy (buf, hdr->s_name + 1, SCNNMLEN - 1);
	  buf[SCNNMLEN - 1] = '\0';

	  strindex = strtol (buf, &p, 10);
	  if (*p != '\0' || strindex < 0)
	    return NULL;

	  return extract_long_section_name (abfd, (uint32_t) strindex);
	}
    }

  char *name = (char *) bfd_alloc (abfd, (bfd_size_type) SCNNMLEN + 1);
  if (name == NULL)
    return NULL;

  memcpy (name, hdr->s_name, SCNNMLEN);
  name[SCNNMLEN] = '\0';
  return name;
}

static bool
handle_debug_section_compression (bfd *abfd, asection *sect)
{
  const char *name = bfd_get_section_name (sect);

  if (!((sect->flags & SEC_DEBUGGING)
	&& (sect->flags & SEC_HAS_CONTENTS)
	&& (startswith (name, ".debug_")
	    || startswith (name, ".zdebug_")
	    || startswith (name, ".gnu.debuglto_.debug_")
	    || startswith (name, ".gnu.linkonce.wi."))))
    return true;

  if (bfd_is_section_compressed (abfd, sect))
    {
      if ((abfd->flags & BFD_DECOMPRESS))
	{
	  if (!bfd_init_section_decompress_status (abfd, sect))
	    {
	      _bfd_error_handler (_("%pB: unable to decompress section %s"),
				  abfd, name);
	      return false;
	    }
	  if (abfd->is_linker_input && name[1] == 'z')
	    {
	      char *new_name = bfd_zdebug_name_to_debug (abfd, name);
	      if (new_name == NULL)
		return false;
	      bfd_rename_section (sect, new_name);
	    }
	}
    }
  else if ((abfd->flags & BFD_COMPRESS) && sect->size != 0)
    {
      if (!bfd_init_section_compress_status (abfd, sect))
	{
	  _bfd_error_handler (_("%pB: unable to compress section %s"),
			      abfd, name);
	  return false;
	}
    }

  return true;
}

static bool
make_a_section_from_file (bfd *abfd,
			  struct internal_scnhdr *hdr,
			  unsigned int target_index)
{
  char *name = get_section_name (abfd, hdr);
  if (name == NULL)
    return false;

  asection *newsect = bfd_make_section_anyway (abfd, name);
  if (newsect == NULL)
    return false;

  newsect->vma = hdr->s_vaddr;
  newsect->lma = hdr->s_paddr;
  newsect->size = hdr->s_size;
  newsect->filepos = hdr->s_scnptr;
  newsect->rel_filepos = hdr->s_relptr;
  newsect->reloc_count = hdr->s_nreloc;
  newsect->line_filepos = hdr->s_lnnoptr;
  newsect->lineno_count = hdr->s_nlnno;
  newsect->userdata = NULL;
  newsect->next = NULL;
  newsect->target_index = target_index;

  bfd_coff_set_alignment_hook (abfd, newsect, hdr);

  flagword flags;
  if (!bfd_coff_styp_to_sec_flags_hook (abfd, hdr, name, newsect, &flags))
    return false;

  if ((flags & SEC_COFF_SHARED_LIBRARY) != 0)
    newsect->lineno_count = 0;

  if (hdr->s_nreloc != 0)
    flags |= SEC_RELOC;

  if (hdr->s_scnptr != 0)
    flags |= SEC_HAS_CONTENTS;

  newsect->flags = flags;

  return handle_debug_section_compression (abfd, newsect);
}

void
coff_object_cleanup (bfd *abfd)
{
  struct coff_tdata *td = coff_data (abfd);
  if (!td)
    {
      return;
    }

  if (td->section_by_index)
    {
      htab_delete (td->section_by_index);
      td->section_by_index = NULL;
    }

  if (td->section_by_target_index)
    {
      htab_delete (td->section_by_target_index);
      td->section_by_target_index = NULL;
    }

  if (obj_pe (abfd))
    {
      struct pe_tdata *ped = pe_data (abfd);
      if (ped && ped->comdat_hash)
        {
          htab_delete (ped->comdat_hash);
          ped->comdat_hash = NULL;
        }
    }
}

/* Read in a COFF object and make it into a BFD.  This is used by
   ECOFF as well.  */
bfd_cleanup
coff_real_object_p (bfd *abfd,
		    unsigned nscns,
		    struct internal_filehdr *internal_f,
		    struct internal_aouthdr *internal_a)
{
  flagword oflags = abfd->flags;
  bfd_vma ostart = bfd_get_start_address (abfd);
  void *tdata = NULL;
  char *external_sections = NULL;

  if (!(internal_f->f_flags & F_RELFLG))
    abfd->flags |= HAS_RELOC;
  if (internal_f->f_flags & F_EXEC)
    abfd->flags |= EXEC_P | D_PAGED;
  if (!(internal_f->f_flags & F_LNNO))
    abfd->flags |= HAS_LINENO;
  if (!(internal_f->f_flags & F_LSYMS))
    abfd->flags |= HAS_LOCALS;

  abfd->symcount = internal_f->f_nsyms;
  if (internal_f->f_nsyms)
    abfd->flags |= HAS_SYMS;

  abfd->start_address = (internal_a != NULL) ? internal_a->entry : 0;

  tdata = bfd_coff_mkobject_hook (abfd, (void *) internal_f, (void *) internal_a);
  if (tdata == NULL)
    goto error_return;

  if (!bfd_coff_set_arch_mach_hook (abfd, (void *) internal_f))
    goto error_return;

  if (nscns > 0)
    {
      unsigned int scnhsz = bfd_coff_scnhsz (abfd);
      bfd_size_type readsize = (bfd_size_type) nscns * scnhsz;

      external_sections = (char *) _bfd_alloc_and_read (abfd, readsize, readsize);
      if (external_sections == NULL)
	goto error_return;

      for (unsigned int i = 0; i < nscns; i++)
	{
	  struct internal_scnhdr tmp;
	  bfd_coff_swap_scnhdr_in (abfd,
				   (void *) (external_sections + i * scnhsz),
				   (void *) &tmp);
	  if (!make_a_section_from_file (abfd, &tmp, i + 1))
	    goto error_return;
	}
    }

  _bfd_coff_free_symbols (abfd);
  return coff_object_cleanup;

error_return:
  if (tdata != NULL)
    {
      coff_object_cleanup (abfd);
      _bfd_coff_free_symbols (abfd);
      bfd_release (abfd, tdata);
    }
  abfd->flags = oflags;
  abfd->start_address = ostart;
  return NULL;
}

/* Turn a COFF file into a BFD, but fail with bfd_error_wrong_format if it is
   not a COFF file.  This is also used by ECOFF.  */

bfd_cleanup
coff_object_p (bfd *abfd)
{
  bfd_size_type filhsz;
  bfd_size_type aoutsz;
  void *filehdr;
  struct internal_filehdr internal_f;
  struct internal_aouthdr internal_a;
  struct internal_aouthdr *p_aouthdr = NULL;

  filhsz = bfd_coff_filhsz (abfd);
  aoutsz = bfd_coff_aoutsz (abfd);

  filehdr = _bfd_alloc_and_read (abfd, filhsz, filhsz);
  if (filehdr == NULL)
    {
      if (bfd_get_error () != bfd_error_system_call)
        bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }
  bfd_coff_swap_filehdr_in (abfd, filehdr, &internal_f);
  bfd_release (abfd, filehdr);

  if (!bfd_coff_bad_format_hook (abfd, &internal_f)
      || internal_f.f_opthdr > aoutsz)
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  if (internal_f.f_opthdr > 0)
    {
      void *opthdr = _bfd_alloc_and_read (abfd, aoutsz, internal_f.f_opthdr);
      if (opthdr == NULL)
        return NULL;

      if (internal_f.f_opthdr < aoutsz)
        memset ((char *) opthdr + internal_f.f_opthdr, 0,
                aoutsz - internal_f.f_opthdr);

      bfd_coff_swap_aouthdr_in (abfd, opthdr, &internal_a);
      bfd_release (abfd, opthdr);
      p_aouthdr = &internal_a;
    }

  return coff_real_object_p (abfd, internal_f.f_nscns, &internal_f, p_aouthdr);
}

static hashval_t
htab_hash_section_target_index (const void *entry)
{
  return ((const struct bfd_section *) entry)->target_index;
}

static int
htab_eq_section_target_index (const void * e1, const void * e2)
{
  if (e1 == e2)
    {
      return 1;
    }

  if (e1 == NULL || e2 == NULL)
    {
      return 0;
    }

  const struct bfd_section *sec1 = (const struct bfd_section *) e1;
  const struct bfd_section *sec2 = (const struct bfd_section *) e2;

  return sec1->target_index == sec2->target_index;
}

/* Get the BFD section from a COFF symbol section number.  */

asection *
coff_section_from_bfd_index (bfd *abfd, int section_index)
{
  if (section_index == N_ABS || section_index == N_DEBUG)
    return bfd_abs_section_ptr;
  if (section_index == N_UNDEF)
    return bfd_und_section_ptr;

  htab_t table = coff_data (abfd)->section_by_target_index;

  if (table == NULL)
    {
      table = htab_create (10, htab_hash_section_target_index,
			   htab_eq_section_target_index, NULL);
      if (table == NULL)
	return bfd_und_section_ptr;
      coff_data (abfd)->section_by_target_index = table;
    }

  if (htab_elements (table) == 0 && abfd->sections != NULL)
    {
      for (asection *sec = abfd->sections; sec; sec = sec->next)
	{
	  void **slot = htab_find_slot (table, sec, INSERT);
	  if (slot == NULL)
	    return bfd_und_section_ptr;
	  *slot = sec;
	}
    }

  struct bfd_section needle;
  needle.target_index = section_index;

  asection *answer = htab_find (table, &needle);
  if (answer != NULL)
    return answer;

  for (asection *sec = abfd->sections; sec; sec = sec->next)
    {
      if (sec->target_index == section_index)
	{
	  void **slot = htab_find_slot (table, sec, INSERT);
	  if (slot != NULL)
	    *slot = sec;
	  return sec;
	}
    }

  return bfd_und_section_ptr;
}

/* Get the upper bound of a COFF symbol table.  */

#include <limits.h>

long
coff_get_symtab_upper_bound (bfd *abfd)
{
  if (!bfd_coff_slurp_symbol_table (abfd))
    {
      return -1;
    }

  long sym_count = bfd_get_symcount (abfd);

  if (sym_count < 0 || sym_count == LONG_MAX)
    {
      return -1;
    }

  const unsigned long num_entries = (unsigned long)sym_count + 1;
  const size_t entry_size = sizeof (coff_symbol_type *);

  if (entry_size > 0 && num_entries > (unsigned long)LONG_MAX / entry_size)
    {
      return -1;
    }

  return (long) (num_entries * entry_size);
}

/* Canonicalize a COFF symbol table.  */

long
coff_canonicalize_symtab (bfd *abfd, asymbol **alocation)
{
  coff_symbol_type **location = (coff_symbol_type **) alocation;
  long symcount;

  if (!bfd_coff_slurp_symbol_table (abfd))
    {
      return -1;
    }

  symcount = bfd_get_symcount (abfd);
  if (symcount < 0)
    {
      return symcount;
    }

  size_t count = (size_t) symcount;
  if (count > 0)
    {
      coff_symbol_type *symbase = obj_symbols (abfd);
      for (size_t i = 0; i < count; i++)
        {
          location[i] = &symbase[i];
        }
    }

  location[count] = NULL;

  return symcount;
}

/* Get the name of a symbol.  The caller must pass in a buffer of size
   >= SYMNMLEN + 1.  */

const char *
_bfd_coff_internal_syment_name (bfd *abfd,
                                const struct internal_syment *sym,
                                char *buf)
{
  if (sym->_n._n_n._n_zeroes != 0 || sym->_n._n_n._n_offset == 0)
    {
      memcpy (buf, sym->_n._n_name, SYMNMLEN);
      buf[SYMNMLEN] = '\0';
      return buf;
    }

  const char *strings = obj_coff_strings (abfd);
  if (strings == NULL)
    {
      strings = _bfd_coff_read_string_table (abfd);
      if (strings == NULL)
        {
          return NULL;
        }
    }

  unsigned long offset = sym->_n._n_n._n_offset;

  BFD_ASSERT (offset >= STRING_SIZE_SIZE);

  if (offset >= obj_coff_strings_len (abfd))
    {
      return NULL;
    }

  return strings + offset;
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
_bfd_coff_read_internal_relocs (bfd *abfd,
				asection *sec,
				bool cache,
				bfd_byte *external_relocs,
				bool require_internal,
				struct internal_reloc *internal_relocs)
{
  if (sec->reloc_count == 0)
    return internal_relocs;

  struct coff_section_tdata *sdata = coff_section_data (abfd, sec);
  if (sdata != NULL && sdata->relocs != NULL)
    {
      if (!require_internal)
	return sdata->relocs;

      memcpy (internal_relocs, sdata->relocs,
	      sec->reloc_count * sizeof (struct internal_reloc));
      return internal_relocs;
    }

  bfd_byte *free_external = NULL;
  struct internal_reloc *free_internal = NULL;
  const bfd_size_type relsz = bfd_coff_relsz (abfd);
  const bfd_size_type external_amt = sec->reloc_count * relsz;

  if (external_relocs == NULL)
    {
      free_external = bfd_malloc (external_amt);
      if (free_external == NULL)
	return NULL;
      external_relocs = free_external;
    }

  if (bfd_seek (abfd, sec->rel_filepos, SEEK_SET) != 0
      || bfd_read (external_relocs, external_amt, abfd) != external_amt)
    goto error_return;

  if (internal_relocs == NULL)
    {
      const bfd_size_type internal_amt =
	sec->reloc_count * sizeof (struct internal_reloc);
      free_internal = bfd_malloc (internal_amt);
      if (free_internal == NULL)
	goto error_return;
      internal_relocs = free_internal;
    }

  for (bfd_size_type i = 0; i < sec->reloc_count; i++)
    {
      bfd_byte *erel = external_relocs + (i * relsz);
      struct internal_reloc *irel = &internal_relocs[i];
      bfd_coff_swap_reloc_in (abfd, erel, irel);
    }

  free (free_external);
  free_external = NULL;

  if (cache && free_internal != NULL)
    {
      if (sdata == NULL)
	{
	  sdata = bfd_zalloc (abfd, sizeof (*sdata));
	  if (sdata == NULL)
	    goto error_return;
	  sec->used_by_bfd = sdata;
	}
      sdata->relocs = free_internal;
      free_internal = NULL;
    }

  return internal_relocs;

error_return:
  free (free_external);
  free (free_internal);
  return NULL;
}

/* Set lineno_count for the output sections of a COFF file.  */

int
coff_count_linenumbers (bfd *abfd)
{
  const unsigned int symbol_count = bfd_get_symcount (abfd);

  if (symbol_count == 0)
    {
      /* From the backend linker; section line number counts are assumed correct. */
      int total = 0;
      for (asection *section = abfd->sections; section != NULL; section = section->next)
	{
	  total += section->lineno_count;
	}
      return total;
    }

  /* We are calculating the counts, so clear any pre-existing values. */
  for (asection *section = abfd->sections; section != NULL; section = section->next)
    {
      section->lineno_count = 0;
    }

  int total_linenos = 0;
  for (unsigned int i = 0; i < symbol_count; ++i)
    {
      asymbol *symbol = abfd->outsymbols[i];
      bfd *symbol_bfd = bfd_asymbol_bfd (symbol);

      if (symbol_bfd == NULL || !bfd_family_coff (symbol_bfd))
	{
	  continue;
	}

      coff_symbol_type *coff_sym = coffsymbol (symbol);

      /* A valid symbol for line numbers must have them and belong to a section. */
      if (coff_sym->lineno == NULL || coff_sym->symbol.section == NULL
	  || coff_sym->symbol.section->owner == NULL)
	{
	  continue;
	}

      asection *output_section = coff_sym->symbol.section->output_section;
      const bool can_update_section = (output_section != NULL
				       && !bfd_is_const_section (output_section));

      for (alent *lineno_entry = coff_sym->lineno; lineno_entry->line_number != 0; ++lineno_entry)
	{
	  if (can_update_section)
	    {
	      output_section->lineno_count++;
	    }
	  total_linenos++;
	}
    }

  return total_linenos;
}

static void
fixup_symbol_value (bfd *abfd,
		    coff_symbol_type *coff_symbol_ptr,
		    struct internal_syment *syment)
{
  asymbol *symbol = &coff_symbol_ptr->symbol;
  asection *section = symbol->section;

  if (section && bfd_is_com_section (section))
    {
      syment->n_scnum = N_UNDEF;
      syment->n_value = symbol->value;
      return;
    }

  if ((symbol->flags & BSF_DEBUGGING) != 0
      && (symbol->flags & BSF_DEBUGGING_RELOC) == 0)
    {
      syment->n_value = symbol->value;
      return;
    }

  if (bfd_is_und_section (section))
    {
      syment->n_scnum = N_UNDEF;
      syment->n_value = 0;
      return;
    }

  if (section)
    {
      asection *output_section = section->output_section;
      syment->n_scnum = output_section->target_index;
      syment->n_value = symbol->value + section->output_offset;

      if (!obj_pe (abfd))
	{
	  bfd_vma section_base = (syment->n_sclass == C_STATLAB)
	    ? output_section->lma
	    : output_section->vma;
	  syment->n_value += section_base;
	}
    }
  else
    {
      syment->n_scnum = N_ABS;
      syment->n_value = symbol->value;
    }
}

/* Run through all the symbols in the symbol table and work out what
   their indexes into the symbol table will be when output.

   Coff requires that each C_FILE symbol points to the next one in the
   chain, and that the last one points to the first external symbol. We
   do that here too.  */

bool
coff_renumber_symbols (bfd *bfd_ptr, int *first_undef)
{
  unsigned int symbol_count = bfd_get_symcount (bfd_ptr);
  if (symbol_count == 0)
    {
      *first_undef = 0;
      obj_conv_table_size (bfd_ptr) = 0;
      return true;
    }

  asymbol **old_symbols = bfd_ptr->outsymbols;
  bfd_size_type sym_alloc_count = (bfd_size_type) symbol_count + 1;
  asymbol **new_symbols = (asymbol **) bfd_zalloc (bfd_ptr, sym_alloc_count * sizeof (asymbol *));
  if (!new_symbols)
    {
      return false;
    }

  enum coff_symbol_category
  {
    COFF_SYMBOL_NORMAL,
    COFF_SYMBOL_GLOBAL,
    COFF_SYMBOL_UNDEFINED,
    COFF_SYMBOL_CATEGORY_COUNT
  };

  bfd_size_type cat_alloc_size = symbol_count;
  enum coff_symbol_category *categories = (enum coff_symbol_category *)
    bfd_alloc (bfd_ptr, cat_alloc_size * sizeof (enum coff_symbol_category));

  if (!categories)
    {
      bfd_release (bfd_ptr, new_symbols);
      return false;
    }

  unsigned int counts[COFF_SYMBOL_CATEGORY_COUNT] = { 0 };

  for (unsigned int i = 0; i < symbol_count; i++)
    {
      asymbol *sym = old_symbols[i];
      bool not_at_end = (sym->flags & BSF_NOT_AT_END) != 0;
      bool is_undef = bfd_is_und_section (sym->section);

      if (!not_at_end && is_undef)
        {
          categories[i] = COFF_SYMBOL_UNDEFINED;
        }
      else if (!not_at_end && !is_undef
               && (bfd_is_com_section (sym->section)
                   || (!(sym->flags & BSF_FUNCTION)
                       && (sym->flags & (BSF_GLOBAL | BSF_WEAK)) != 0)))
        {
          categories[i] = COFF_SYMBOL_GLOBAL;
        }
      else
        {
          categories[i] = COFF_SYMBOL_NORMAL;
        }
      counts[categories[i]]++;
    }

  asymbol **dest_pointers[COFF_SYMBOL_CATEGORY_COUNT];
  dest_pointers[COFF_SYMBOL_NORMAL] = new_symbols;
  dest_pointers[COFF_SYMBOL_GLOBAL] = new_symbols + counts[COFF_SYMBOL_NORMAL];
  dest_pointers[COFF_SYMBOL_UNDEFINED] = new_symbols + counts[COFF_SYMBOL_NORMAL] + counts[COFF_SYMBOL_GLOBAL];

  *first_undef = dest_pointers[COFF_SYMBOL_UNDEFINED] - new_symbols;

  for (unsigned int i = 0; i < symbol_count; i++)
    {
      *dest_pointers[categories[i]]++ = old_symbols[i];
    }

  bfd_release (bfd_ptr, categories);
  bfd_ptr->outsymbols = new_symbols;

  unsigned int native_index = 0;
  struct internal_syment *last_file = NULL;

  for (unsigned int symbol_index = 0; symbol_index < symbol_count; symbol_index++)
    {
      asymbol *current_sym = bfd_ptr->outsymbols[symbol_index];
      current_sym->udata.i = symbol_index;

      coff_symbol_type *coff_sym = coff_symbol_from (current_sym);

      if (coff_sym && coff_sym->native)
        {
          combined_entry_type *s = coff_sym->native;
          BFD_ASSERT (s->is_sym);

          if (s->u.syment.n_sclass == C_FILE)
            {
              if (last_file)
                last_file->n_value = native_index;
              last_file = &s->u.syment;
            }
          else
            {
              fixup_symbol_value (bfd_ptr, coff_sym, &s->u.syment);
            }

          unsigned int num_entries = s->u.syment.n_numaux + 1;
          for (unsigned int i = 0; i < num_entries; i++)
            s[i].offset = native_index + i;
          native_index += num_entries;
        }
      else
        {
          native_index++;
        }
    }

  obj_conv_table_size (bfd_ptr) = native_index;

  return true;
}

/* Run thorough the symbol table again, and fix it so that all
   pointers to entries are changed to the entries' index in the output
   symbol table.  */

static void
process_aux_entry (combined_entry_type *aux_entry)
{
  BFD_ASSERT (aux_entry && !aux_entry->is_sym);

  if (aux_entry->fix_tag)
    {
      aux_entry->u.auxent.x_sym.x_tagndx.u32 =
	aux_entry->u.auxent.x_sym.x_tagndx.p->offset;
      aux_entry->fix_tag = 0;
    }

  if (aux_entry->fix_end)
    {
      aux_entry->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32 =
	aux_entry->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p->offset;
      aux_entry->fix_end = 0;
    }

  if (aux_entry->fix_scnlen)
    {
      aux_entry->u.auxent.x_csect.x_scnlen.u64 =
	aux_entry->u.auxent.x_csect.x_scnlen.p->offset;
      aux_entry->fix_scnlen = 0;
    }
}

static void
process_coff_symbol (bfd *bfd_ptr, coff_symbol_type *coff_symbol)
{
  combined_entry_type *s = coff_symbol->native;
  BFD_ASSERT (s && s->is_sym);

  if (s->fix_value)
    {
      combined_entry_type *target_symbol =
	(combined_entry_type *) (uintptr_t) s->u.syment.n_value;
      s->u.syment.n_value = target_symbol->offset;
      s->fix_value = 0;
    }

  if (s->fix_line)
    {
      s->u.syment.n_value =
	(coff_symbol->symbol.section->output_section->line_filepos
	 + s->u.syment.n_value * bfd_coff_linesz (bfd_ptr));
      coff_symbol->symbol.section =
	coff_section_from_bfd_index (bfd_ptr, N_DEBUG);
      BFD_ASSERT (coff_symbol->symbol.flags & BSF_DEBUGGING);
    }

  for (int i = 0; i < s->u.syment.n_numaux; i++)
    {
      process_aux_entry (s + i + 1);
    }
}

void
coff_mangle_symbols (bfd *bfd_ptr)
{
  if (!bfd_ptr || !bfd_ptr->outsymbols)
    {
      return;
    }

  unsigned int symbol_count = bfd_get_symcount (bfd_ptr);
  asymbol **symbol_ptr_ptr = bfd_ptr->outsymbols;

  for (unsigned int i = 0; i < symbol_count; i++)
    {
      coff_symbol_type *coff_symbol = coff_symbol_from (symbol_ptr_ptr[i]);
      if (coff_symbol && coff_symbol->native)
	{
	  process_coff_symbol (bfd_ptr, coff_symbol);
	}
    }
}

static bool
coff_write_auxent_fname (bfd *abfd,
			 char *str,
			 union internal_auxent *auxent,
			 struct bfd_strtab_hash *strtab,
			 bool hash)
{
  const unsigned int str_length = strlen (str);
  const unsigned int filnmlen = bfd_coff_filnmlen (abfd);

  if (bfd_coff_long_filenames (abfd) && str_length > filnmlen)
    {
      const bfd_size_type indx = _bfd_stringtab_add (strtab, str, hash, false);

      if (indx == (bfd_size_type) -1)
	{
	  return false;
	}

      auxent->x_file.x_n.x_n.x_zeroes = 0;
      auxent->x_file.x_n.x_n.x_offset = STRING_SIZE_SIZE + indx;
    }
  else
    {
      strncpy (auxent->x_file.x_n.x_fname, str, filnmlen);
    }

  return true;
}

static bool
write_symbol_to_debug_section (bfd *abfd,
			       const char *name,
			       combined_entry_type *native,
			       asection **debug_string_section_p,
			       bfd_size_type *debug_string_size_p)
{
  if (*debug_string_section_p == NULL)
    {
      *debug_string_section_p = bfd_get_section_by_name (abfd, ".debug");
      if (*debug_string_section_p == NULL)
	return false;
    }

  size_t name_length = strlen (name);
  int prefix_len = bfd_coff_debug_string_prefix_length (abfd);
  file_ptr filepos = bfd_tell (abfd);
  bfd_byte buf[4];

  if (prefix_len == 4)
    bfd_put_32 (abfd, (bfd_vma) (name_length + 1), buf);
  else
    bfd_put_16 (abfd, (bfd_vma) (name_length + 1), buf);

  if (!bfd_set_section_contents (abfd, *debug_string_section_p, buf,
				 (file_ptr) *debug_string_size_p,
				 (bfd_size_type) prefix_len))
    return false;

  if (!bfd_set_section_contents (abfd, *debug_string_section_p, name,
				 (file_ptr) (*debug_string_size_p + prefix_len),
				 (bfd_size_type) name_length + 1))
    return false;

  if (bfd_seek (abfd, filepos, SEEK_SET) != 0)
    return false;

  native->u.syment._n._n_n._n_offset = *debug_string_size_p + prefix_len;
  native->u.syment._n._n_n._n_zeroes = 0;
  *debug_string_size_p += name_length + 1 + prefix_len;

  return true;
}

static bool
handle_regular_symbol (bfd *abfd,
		       const char *name,
		       combined_entry_type *native,
		       struct bfd_strtab_hash *strtab,
		       bool hash,
		       asection **debug_string_section_p,
		       bfd_size_type *debug_string_size_p)
{
  size_t name_length = strlen (name);

  if (name_length <= SYMNMLEN && !bfd_coff_force_symnames_in_strings (abfd))
    {
      strncpy (native->u.syment._n._n_name, name, SYMNMLEN);
      return true;
    }

  if (!bfd_coff_symname_in_debug (abfd, &native->u.syment))
    {
      bfd_size_type indx = _bfd_stringtab_add (strtab, name, hash, false);
      if (indx == (bfd_size_type) -1)
	return false;

      native->u.syment._n._n_n._n_offset = STRING_SIZE_SIZE + indx;
      native->u.syment._n._n_n._n_zeroes = 0;
      return true;
    }

  return write_symbol_to_debug_section (abfd, name, native,
					 debug_string_section_p,
					 debug_string_size_p);
}

static bool
handle_file_symbol (bfd *abfd,
		    const char *name,
		    combined_entry_type *native,
		    struct bfd_strtab_hash *strtab,
		    bool hash)
{
  if (bfd_coff_force_symnames_in_strings (abfd))
    {
      bfd_size_type indx = _bfd_stringtab_add (strtab, ".file", hash, false);
      if (indx == (bfd_size_type) -1)
	return false;

      native->u.syment._n._n_n._n_offset = STRING_SIZE_SIZE + indx;
      native->u.syment._n._n_n._n_zeroes = 0;
    }
  else
    {
      strncpy (native->u.syment._n._n_name, ".file", SYMNMLEN);
    }

  BFD_ASSERT (! (native + 1)->is_sym);
  return coff_write_auxent_fname (abfd, name, &(native + 1)->u.auxent,
				  strtab, hash);
}

static bool
coff_fix_symbol_name (bfd *abfd,
		      asymbol *symbol,
		      combined_entry_type *native,
		      struct bfd_strtab_hash *strtab,
		      bool hash,
		      asection **debug_string_section_p,
		      bfd_size_type *debug_string_size_p)
{
  if (symbol->name == NULL)
    {
      symbol->name = "strange";
    }

  BFD_ASSERT (native->is_sym);

  if (native->u.syment.n_sclass == C_FILE
      && native->u.syment.n_numaux > 0)
    {
      return handle_file_symbol (abfd, symbol->name, native, strtab, hash);
    }

  return handle_regular_symbol (abfd, symbol->name, native, strtab, hash,
				debug_string_section_p,
				debug_string_size_p);
}

/* We need to keep track of the symbol index so that when we write out
   the relocs we can get the index for a symbol.  This method is a
   hack.  FIXME.  */

#define set_index(symbol, idx)	((symbol)->udata.i = (idx))

/* Write a symbol out to a COFF file.  */

static bool
coff_write_symbol (bfd *abfd,
		   asymbol *symbol,
		   combined_entry_type *native,
		   bfd_vma *written,
		   struct bfd_strtab_hash *strtab,
		   bool hash,
		   asection **debug_string_section_p,
		   bfd_size_type *debug_string_size_p)
{
  BFD_ASSERT (native->is_sym);

  if (native->u.syment.n_sclass == C_FILE)
    symbol->flags |= BSF_DEBUGGING;

  if (bfd_is_abs_section (symbol->section))
    native->u.syment.n_scnum = (symbol->flags & BSF_DEBUGGING) ? N_DEBUG : N_ABS;
  else if (bfd_is_und_section (symbol->section))
    native->u.syment.n_scnum = N_UNDEF;
  else
    {
      asection *output_section = symbol->section->output_section
                                 ? symbol->section->output_section
                                 : symbol->section;
      native->u.syment.n_scnum = output_section->target_index;
    }

  if (!coff_fix_symbol_name (abfd, symbol, native, strtab, hash,
			     debug_string_section_p, debug_string_size_p))
    return false;

  bfd_size_type symesz = bfd_coff_symesz (abfd);
  void *sym_buf = bfd_alloc (abfd, symesz);
  if (!sym_buf)
    return false;

  bfd_coff_swap_sym_out (abfd, &native->u.syment, sym_buf);
  bool sym_write_ok = (bfd_write (sym_buf, symesz, abfd) == symesz);
  bfd_release (abfd, sym_buf);

  if (!sym_write_ok)
    return false;

  unsigned int numaux = native->u.syment.n_numaux;
  if (numaux > 0)
    {
      bool aux_write_ok = true;
      bfd_size_type auxesz = bfd_coff_auxesz (abfd);
      void *aux_buf = bfd_alloc (abfd, auxesz);
      if (!aux_buf)
        return false;

      int type = native->u.syment.n_type;
      int n_sclass = (int) native->u.syment.n_sclass;

      for (unsigned int j = 0; j < numaux; j++)
        {
          combined_entry_type *aux_native = native + j + 1;
          BFD_ASSERT (!aux_native->is_sym);

          if (n_sclass == C_FILE
              && aux_native->u.auxent.x_file.x_ftype
              && aux_native->extrap)
            {
              coff_write_auxent_fname (abfd, (char *) aux_native->extrap,
                                       &aux_native->u.auxent, strtab, hash);
            }

          bfd_coff_swap_aux_out (abfd, &aux_native->u.auxent, type, n_sclass,
                                 (int) j, numaux, aux_buf);

          if (bfd_write (aux_buf, auxesz, abfd) != auxesz)
            {
              aux_write_ok = false;
              break;
            }
        }
      bfd_release (abfd, aux_buf);

      if (!aux_write_ok)
        return false;
    }

  set_index (symbol, *written);
  *written += numaux + 1;
  return true;
}

/* Write out a symbol to a COFF file that does not come from a COFF
   file originally.  This symbol may have been created by the linker,
   or we may be linking a non COFF file to a COFF file.  */

bool
coff_write_alien_symbol (bfd *abfd,
			 asymbol *symbol,
			 struct internal_syment *isym,
			 bfd_vma *written,
			 struct bfd_strtab_hash *strtab,
			 bool hash,
			 asection **debug_string_section_p,
			 bfd_size_type *debug_string_size_p)
{
  combined_entry_type native_entries[2];
  combined_entry_type *native = native_entries;
  asection *output_section = symbol->section->output_section
			       ? symbol->section->output_section
			       : symbol->section;
  struct bfd_link_info *link_info = coff_data (abfd)->link_info;
  bool ret;

  if (((!link_info || link_info->strip_discarded)
       && !bfd_is_abs_section (symbol->section)
       && symbol->section->output_section == bfd_abs_section_ptr)
      || (symbol->flags & BSF_DEBUGGING))
    {
      symbol->name = "";
      if (isym)
	memset (isym, 0, sizeof (*isym));
      return true;
    }

  memset (native_entries, 0, sizeof (native_entries));
  native->is_sym = true;
  native[1].is_sym = false;
  native->u.syment.n_type = T_NULL;

  if (bfd_is_und_section (symbol->section)
      || bfd_is_com_section (symbol->section))
    {
      native->u.syment.n_scnum = N_UNDEF;
      native->u.syment.n_value = symbol->value;
    }
  else if (symbol->flags & BSF_FILE)
    {
      native->u.syment.n_scnum = N_DEBUG;
      native->u.syment.n_numaux = 1;
    }
  else
    {
      native->u.syment.n_scnum = output_section->target_index;
      native->u.syment.n_value = symbol->value + symbol->section->output_offset;
      if (!obj_pe (abfd))
	native->u.syment.n_value += output_section->vma;

      coff_symbol_type *c = coff_symbol_from (symbol);
      if (c)
	native->u.syment.n_flags = bfd_asymbol_bfd (&c->symbol)->flags;

      const elf_symbol_type *elfsym = elf_symbol_from (symbol);
      if (elfsym
	  && (symbol->flags & BSF_FUNCTION)
	  && elfsym->internal_elf_sym.st_size)
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
    native->u.syment.n_sclass = obj_pe (abfd) ? C_NT_WEAK : C_WEAKEXT;
  else
    native->u.syment.n_sclass = C_EXT;

  ret = coff_write_symbol (abfd, symbol, native, written, strtab, hash,
			   debug_string_section_p, debug_string_size_p);
  if (isym)
    *isym = native->u.syment;
  return ret;
}

/* Write a native symbol to a COFF file.  */

static void
coff_process_symbol_lineno (bfd *abfd,
			    coff_symbol_type *symbol,
			    bfd_vma written)
{
  alent *lineno = symbol->lineno;
  combined_entry_type *native = symbol->native;
  asection *sec = symbol->symbol.section;
  asection *output_section = sec->output_section;
  unsigned int count = 0;

  lineno[count].u.offset = written;
  if (native->u.syment.n_numaux)
    {
      union internal_auxent *aux = &native[1].u.auxent;

      aux->x_sym.x_fcnary.x_fcn.x_lnnoptr =
	output_section->moving_line_filepos;
    }

  count++;
  while (lineno[count].line_number != 0)
    {
      lineno[count].u.offset +=
	(output_section->vma + sec->output_offset);
      count++;
    }
  symbol->done_lineno = true;

  if (!bfd_is_const_section (output_section))
    output_section->moving_line_filepos +=
      count * bfd_coff_linesz (abfd);
}

static bool
coff_write_native_symbol (bfd *abfd,
			  coff_symbol_type *symbol,
			  bfd_vma *written,
			  struct bfd_strtab_hash *strtab,
			  asection **debug_string_section_p,
			  bfd_size_type *debug_string_size_p)
{
  struct bfd_link_info *link_info = coff_data (abfd)->link_info;
  asection *sec = symbol->symbol.section;

  if ((!link_info || link_info->strip_discarded)
      && !bfd_is_abs_section (sec)
      && sec->output_section == bfd_abs_section_ptr)
    {
      symbol->symbol.name = "";
      return true;
    }

  combined_entry_type *native = symbol->native;
  BFD_ASSERT (native->is_sym);

  if (symbol->lineno && !symbol->done_lineno && sec->owner != NULL)
    {
      coff_process_symbol_lineno (abfd, symbol, *written);
    }

  return coff_write_symbol (abfd, &(symbol->symbol), native, written,
			    strtab, true, debug_string_section_p,
			    debug_string_size_p);
}

static void null_error_handler(const char *fmt, va_list ap)
{
    (void)fmt;
    (void)ap;
}

/* Write out the COFF symbols.  */

static bool
add_long_section_names_to_strtab (bfd *abfd, struct bfd_strtab_hash *strtab)
{
  if (bfd_coff_long_section_names (abfd))
    {
      for (asection *o = abfd->sections; o != NULL; o = o->next)
	{
	  if (strlen (o->name) > SCNNMLEN
	      && _bfd_stringtab_add (strtab, o->name, false, false)
		 == (bfd_size_type) -1)
	    {
	      return false;
	    }
	}
    }
  return true;
}

static void
classify_and_update_symbol_sclass (bfd *abfd, asymbol *symbol,
				   coff_symbol_type *c_symbol)
{
  if (coff_backend_info (abfd)->_bfd_coff_classify_symbol == NULL)
    {
      return;
    }

  bfd_error_handler_type current_error_handler;
  enum coff_symbol_classification sym_class;
  unsigned char *n_sclass;

  current_error_handler = bfd_set_error_handler (null_error_handler);
  BFD_ASSERT (c_symbol->native->is_sym);
  sym_class = bfd_coff_classify_symbol (abfd, &c_symbol->native->u.syment);
  (void) bfd_set_error_handler (current_error_handler);

  n_sclass = &c_symbol->native->u.syment.n_sclass;

  if (symbol->flags & BSF_WEAK)
    {
      *n_sclass = obj_pe (abfd) ? C_NT_WEAK : C_WEAKEXT;
    }
  else if ((symbol->flags & BSF_LOCAL) && sym_class != COFF_SYMBOL_LOCAL)
    {
      *n_sclass = C_STAT;
    }
  else if ((symbol->flags & BSF_GLOBAL)
	   && (sym_class != COFF_SYMBOL_GLOBAL
#ifdef COFF_WITH_PE
	       || *n_sclass == C_NT_WEAK
#endif
	       || *n_sclass == C_WEAKEXT))
    {
      *n_sclass = C_EXT;
    }
}

static bool
process_one_symbol (bfd *abfd, asymbol *symbol, bfd_vma *written,
		    struct bfd_strtab_hash *strtab,
		    asection **debug_string_section,
		    bfd_size_type *debug_string_size)
{
  coff_symbol_type *c_symbol = coff_symbol_from (symbol);

  if (c_symbol == NULL || c_symbol->native == NULL)
    {
      return coff_write_alien_symbol (abfd, symbol, NULL, written, strtab,
				      true, debug_string_section,
				      debug_string_size);
    }

  classify_and_update_symbol_sclass (abfd, symbol, c_symbol);
  return coff_write_native_symbol (abfd, c_symbol, written, strtab,
				   debug_string_section,
				   debug_string_size);
}

static bool
write_string_table (bfd *abfd, struct bfd_strtab_hash *strtab)
{
  bfd_byte buffer[STRING_SIZE_SIZE];
  bfd_size_type strtab_size = _bfd_stringtab_size (strtab) + STRING_SIZE_SIZE;

#if STRING_SIZE_SIZE == 4
  H_PUT_32 (abfd, strtab_size, buffer);
#else
#error Change H_PUT_32
#endif

  if (bfd_write (buffer, sizeof (buffer), abfd) != sizeof (buffer))
    {
      return false;
    }

  return _bfd_stringtab_emit (abfd, strtab);
}

bool
coff_write_symbols (bfd *abfd)
{
  struct bfd_strtab_hash *strtab = _bfd_stringtab_init ();
  if (strtab == NULL)
    {
      return false;
    }

  bool success = false;
  asection *debug_string_section = NULL;
  bfd_size_type debug_string_size = 0;
  bfd_vma written = 0;

  if (!add_long_section_names_to_strtab (abfd, strtab))
    {
      goto cleanup;
    }

  if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
    {
      goto cleanup;
    }

  unsigned int limit = bfd_get_symcount (abfd);
  asymbol **symbols = abfd->outsymbols;
  for (unsigned int i = 0; i < limit; i++)
    {
      if (!process_one_symbol (abfd, symbols[i], &written, strtab,
			       &debug_string_section, &debug_string_size))
	{
	  goto cleanup;
	}
    }

  obj_raw_syment_count (abfd) = written;

  if (!write_string_table (abfd, strtab))
    {
      goto cleanup;
    }

  BFD_ASSERT (debug_string_size == 0
	      || (debug_string_section != NULL
		  && (BFD_ALIGN (debug_string_size,
				 1 << debug_string_section->alignment_power)
		      == debug_string_section->size)));

  success = true;

cleanup:
  _bfd_stringtab_free (strtab);
  return success;
}

static bool
write_one_lineno (bfd *abfd,
                  void *buff,
                  bfd_size_type linesz,
                  unsigned short line,
                  unsigned int offset)
{
  struct internal_lineno out;

  memset (&out, 0, sizeof (out));
  out.l_lnno = line;
  out.l_addr.l_symndx = offset;

  bfd_coff_swap_lineno_out (abfd, &out, buff);
  return bfd_write (buff, linesz, abfd) == linesz;
}

static bool
write_symbol_linenos (bfd *abfd,
                      void *buff,
                      bfd_size_type linesz,
                      asymbol *symbol)
{
  bfd *symbol_bfd = bfd_asymbol_bfd (symbol);
  alent *linenos =
    BFD_SEND (symbol_bfd, _get_lineno, (symbol_bfd, symbol));

  if (!linenos)
    return true;

  if (!write_one_lineno (abfd, buff, linesz, 0, linenos->u.offset))
    return false;

  for (alent *current = linenos + 1; current->line_number; ++current)
    {
      if (!write_one_lineno (abfd, buff, linesz, current->line_number,
                             current->u.offset))
        return false;
    }

  return true;
}

bool
coff_write_linenumbers (bfd *abfd)
{
  bool success = false;
  bfd_size_type linesz = bfd_coff_linesz (abfd);
  void *buff = bfd_alloc (abfd, linesz);

  if (!buff)
    return false;

  for (asection *section = abfd->sections; section; section = section->next)
    {
      if (!section->lineno_count)
        continue;

      if (bfd_seek (abfd, section->line_filepos, SEEK_SET) != 0)
        goto cleanup;

      for (asymbol **symbol_ptr = abfd->outsymbols; *symbol_ptr; ++symbol_ptr)
        {
          asymbol *symbol = *symbol_ptr;
          if (symbol->section->output_section == section)
            {
              if (!write_symbol_linenos (abfd, buff, linesz, symbol))
                goto cleanup;
            }
        }
    }

  success = true;

cleanup:
  bfd_release (abfd, buff);
  return success;
}

alent *
coff_get_lineno (bfd *abfd ATTRIBUTE_UNUSED, asymbol *symbol)
{
  if (symbol == NULL)
    {
      return NULL;
    }
  return coffsymbol (symbol)->lineno;
}

/* This function transforms the offsets into the symbol table into
   pointers to syments.  */

static void
coff_pointerize_aux (bfd *abfd,
		     combined_entry_type *table_base,
		     combined_entry_type *symbol,
		     unsigned int indaux,
		     combined_entry_type *auxent)
{
  const unsigned int type = symbol->u.syment.n_type;
  const unsigned int n_sclass = symbol->u.syment.n_sclass;
  bfd_boolean (*hook) (bfd *, combined_entry_type *, combined_entry_type *,
		       unsigned int, combined_entry_type *);

  BFD_ASSERT (symbol->is_sym);

  hook = coff_backend_info (abfd)->_bfd_coff_pointerize_aux_hook;
  if (hook && hook (abfd, table_base, symbol, indaux, auxent))
    {
      return;
    }

  if ((n_sclass == C_STAT && type == T_NULL)
      || n_sclass == C_FILE
      || n_sclass == C_DWARF)
    {
      return;
    }

  BFD_ASSERT (!auxent->is_sym);

  const unsigned long raw_syment_count = obj_raw_syment_count (abfd);
  bfd_coff_symbol_type *x_sym = &auxent->u.auxent.x_sym;

  const bfd_boolean is_function_like = ISFCN (type)
				       || ISTAG (n_sclass)
				       || n_sclass == C_BLOCK
				       || n_sclass == C_FCN;
  const unsigned long end_index = x_sym->x_fcnary.x_fcn.x_endndx.u32;

  if (is_function_like && end_index > 0 && end_index < raw_syment_count)
    {
      x_sym->x_fcnary.x_fcn.x_endndx.p = table_base + end_index;
      auxent->fix_end = 1;
    }

  const unsigned long tag_index = x_sym->x_tagndx.u32;
  if (tag_index < raw_syment_count)
    {
      x_sym->x_tagndx.p = table_base + tag_index;
      auxent->fix_tag = 1;
    }
}

/* Allocate space for the ".debug" section, and read it.
   We did not read the debug section until now, because
   we didn't want to go to the trouble until someone needed it.  */

static char *
build_debug_section (bfd *abfd, asection ** sect_return)
{
  char *debug_section = NULL;
  file_ptr position = (file_ptr) -1;

  asection *sect = bfd_get_section_by_name (abfd, ".debug");
  if (!sect)
    {
      bfd_set_error (bfd_error_no_debug_section);
      return NULL;
    }

  position = bfd_tell (abfd);
  if (position == (file_ptr) -1)
    {
      return NULL;
    }

  if (bfd_seek (abfd, sect->filepos, SEEK_SET) != 0)
    {
      goto fail;
    }

  bfd_size_type sec_size = sect->size;
  debug_section = _bfd_alloc_and_read (abfd, sec_size + 1, sec_size);
  if (debug_section == NULL)
    {
      goto fail;
    }
  debug_section[sec_size] = '\0';

  if (bfd_seek (abfd, position, SEEK_SET) != 0)
    {
      goto fail;
    }

  *sect_return = sect;
  return debug_section;

fail:
  free (debug_section);
  if (position != (file_ptr) -1)
    {
      bfd_seek (abfd, position, SEEK_SET);
    }
  return NULL;
}

/* Return a pointer to a malloc'd copy of 'name'.  'name' may not be
   \0-terminated, but will not exceed 'maxlen' characters.  The copy *will*
   be \0-terminated.  */

static char *
copy_name (bfd *abfd, const char *name, size_t maxlen)
{
  size_t len = strnlen (name, maxlen);
  char *newname = bfd_alloc (abfd, (bfd_size_type) len + 1);

  if (newname == NULL)
    {
      return NULL;
    }

  memcpy (newname, name, len);
  newname[len] = '\0';

  return newname;
}

/* Read in the external symbols.  */

bool
_bfd_coff_get_external_symbols (bfd *abfd)
{
  if (obj_coff_external_syms (abfd) != NULL)
    return true;

  const size_t sym_count = obj_raw_syment_count (abfd);
  if (sym_count == 0)
    return true;

  const size_t sym_entry_size = bfd_coff_symesz (abfd);
  size_t total_sym_size;
  if (_bfd_mul_overflow (sym_count, sym_entry_size, &total_sym_size))
    {
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  const ufile_ptr sym_file_pos = obj_sym_filepos (abfd);
  const ufile_ptr filesize = bfd_get_file_size (abfd);
  if (filesize > 0
      && (sym_file_pos > filesize
	  || total_sym_size > filesize - sym_file_pos))
    {
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  if (bfd_seek (abfd, sym_file_pos, SEEK_SET) != 0)
    return false;

  void *syms = _bfd_malloc_and_read (abfd, total_sym_size, total_sym_size);
  obj_coff_external_syms (abfd) = syms;
  return syms != NULL;
}

/* Read in the external strings.  The strings are not loaded until
   they are needed.  This is because we have no simple way of
   detecting a missing string table in an archive.  If the strings
   are loaded then the STRINGS and STRINGS_LEN fields in the
   coff_tdata structure will be set.  */

const char *
_bfd_coff_read_string_table (bfd *abfd)
{
  char *strings;
  bfd_size_type strsize;

  if (obj_coff_strings (abfd) != NULL)
    {
      return obj_coff_strings (abfd);
    }

  if (obj_sym_filepos (abfd) == 0)
    {
      bfd_set_error (bfd_error_no_symbols);
      return NULL;
    }

  ufile_ptr sym_table_pos = obj_sym_filepos (abfd);
  size_t sym_table_size;
  if (_bfd_mul_overflow (obj_raw_syment_count (abfd), bfd_coff_symesz (abfd), &sym_table_size)
      || sym_table_pos + sym_table_size < sym_table_pos)
    {
      bfd_set_error (bfd_error_file_truncated);
      return NULL;
    }

  if (bfd_seek (abfd, sym_table_pos + sym_table_size, SEEK_SET) != 0)
    {
      return NULL;
    }

  char extstrsize[STRING_SIZE_SIZE];
  if (bfd_read (extstrsize, sizeof extstrsize, abfd) != sizeof extstrsize)
    {
      if (bfd_get_error () != bfd_error_file_truncated)
        {
          return NULL;
        }
      /* A truncated read implies no string table, which is not an error. */
      strsize = STRING_SIZE_SIZE;
    }
  else
    {
#if STRING_SIZE_SIZE == 4
      strsize = H_GET_32 (abfd, extstrsize);
#else
#error Change H_GET_32
#endif
    }

  ufile_ptr filesize = bfd_get_file_size (abfd);
  if (strsize < STRING_SIZE_SIZE
      || (filesize != 0 && strsize > filesize))
    {
      _bfd_error_handler
        (_("%pB: bad string table size %" PRIu64), abfd, (uint64_t) strsize);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  strings = bfd_malloc (strsize + 1);
  if (strings == NULL)
    {
      return NULL;
    }

  /* PR 17521: A corrupt file could have an index into the first few
     bytes of the string table, so ensure they are zero. */
  memset (strings, 0, STRING_SIZE_SIZE);

  bfd_size_type bytes_to_read = strsize - STRING_SIZE_SIZE;
  if (bytes_to_read > 0)
    {
      if (bfd_read (strings + STRING_SIZE_SIZE, bytes_to_read, abfd)
          != bytes_to_read)
        {
          free (strings);
          return NULL;
        }
    }

  /* Null-terminate the entire table for safety. */
  strings[strsize] = '\0';

  obj_coff_strings (abfd) = strings;
  obj_coff_strings_len (abfd) = strsize;
  return strings;
}

/* Free up the external symbols and strings read from a COFF file.  */

bool
_bfd_coff_free_symbols (bfd *abfd)
{
  if (!bfd_family_coff (abfd))
    {
      return false;
    }

  void *syms = obj_coff_external_syms (abfd);
  if (syms != NULL && !obj_coff_keep_syms (abfd))
    {
      free (syms);
      obj_coff_external_syms (abfd) = NULL;
    }

  char *strings = obj_coff_strings (abfd);
  if (strings != NULL && !obj_coff_keep_strings (abfd))
    {
      free (strings);
      obj_coff_strings (abfd) = NULL;
      obj_coff_strings_len (abfd) = 0;
    }

  return true;
}

/* Read a symbol table into freshly bfd_allocated memory, swap it, and
   knit the symbol names into a normalized form.  By normalized here I
   mean that all symbols have an n_offset pointer that points to a null-
   terminated string.  */

static const char *
ensure_string_table (bfd *abfd, const char **string_table_ptr)
{
  if (*string_table_ptr == NULL)
    *string_table_ptr = _bfd_coff_read_string_table (abfd);
  return *string_table_ptr;
}

static char *
ensure_debug_section_data (bfd *abfd, char **debug_data_ptr,
                           asection **debug_sec_ptr)
{
  if (*debug_data_ptr == NULL)
    *debug_data_ptr = build_debug_section (abfd, debug_sec_ptr);
  return *debug_data_ptr;
}

static bool
process_c_file_symbol (bfd *abfd, combined_entry_type *sym,
                       char *raw_src_after_auxes, size_t symesz,
                       const char **string_table_ptr)
{
  combined_entry_type *aux = sym + 1;
  BFD_ASSERT (!aux->is_sym);

  if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0)
    {
      const char *string_table = ensure_string_table (abfd, string_table_ptr);
      if (string_table == NULL)
        return false;

      if ((bfd_size_type) aux->u.auxent.x_file.x_n.x_n.x_offset
          >= obj_coff_strings_len (abfd))
        sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
      else
        sym->u.syment._n._n_n._n_offset =
          (uintptr_t) (string_table
                       + aux->u.auxent.x_file.x_n.x_n.x_offset);
    }
  else
    {
      size_t len;
      char *src;
      if (sym->u.syment.n_numaux > 1 && obj_pe (abfd))
        {
          len = sym->u.syment.n_numaux * symesz;
          src = raw_src_after_auxes - (len - symesz);
        }
      else
        {
          len = bfd_coff_filnmlen (abfd);
          src = aux->u.auxent.x_file.x_n.x_fname;
        }
      char *name = copy_name (abfd, src, len);
      if (name == NULL && len > 0)
        return false;
      sym->u.syment._n._n_n._n_offset = (uintptr_t) name;
    }

  if (obj_pe (abfd))
    return true;

  for (int numaux = 1; numaux < sym->u.syment.n_numaux; numaux++)
    {
      aux = sym + numaux + 1;
      BFD_ASSERT (!aux->is_sym);

      if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0)
        {
          const char *string_table = ensure_string_table (abfd, string_table_ptr);
          if (string_table == NULL)
            return false;

          if ((bfd_size_type) aux->u.auxent.x_file.x_n.x_n.x_offset
              >= obj_coff_strings_len (abfd))
            aux->u.auxent.x_file.x_n.x_n.x_offset =
              (uintptr_t) bfd_symbol_error_name;
          else
            aux->u.auxent.x_file.x_n.x_n.x_offset =
              (uintptr_t) (string_table
                           + aux->u.auxent.x_file.x_n.x_n.x_offset);
        }
      else
        {
          char *name = copy_name (abfd, aux->u.auxent.x_file.x_n.x_fname,
                                  bfd_coff_filnmlen (abfd));
          if (name == NULL)
            return false;
          aux->u.auxent.x_file.x_n.x_n.x_offset = (uintptr_t) name;
        }
    }
  return true;
}

static bool
process_regular_symbol (bfd *abfd, combined_entry_type *sym,
                        const char **string_table_ptr,
                        char **debug_sec_data_ptr,
                        asection **debug_sec_ptr)
{
  if (sym->u.syment._n._n_n._n_zeroes != 0)
    {
      unsigned int i;
      for (i = 0; i < SYMNMLEN; ++i)
        if (sym->u.syment._n._n_name[i] == '\0')
          break;

      char *newstring = bfd_alloc (abfd, i + 1);
      if (newstring == NULL)
        return false;
      memcpy (newstring, sym->u.syment._n._n_name, i);
      newstring[i] = '\0';
      sym->u.syment._n._n_n._n_offset = (uintptr_t) newstring;
      sym->u.syment._n._n_n._n_zeroes = 0;
    }
  else if (sym->u.syment._n._n_n._n_offset == 0)
    {
      sym->u.syment._n._n_n._n_offset = (uintptr_t) "";
    }
  else if (!bfd_coff_symname_in_debug (abfd, &sym->u.syment))
    {
      const char *string_table = ensure_string_table (abfd, string_table_ptr);
      if (string_table == NULL)
        return false;

      if (sym->u.syment._n._n_n._n_offset >= obj_coff_strings_len (abfd))
        sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
      else
        sym->u.syment._n._n_n._n_offset =
          (uintptr_t) (string_table + sym->u.syment._n._n_n._n_offset);
    }
  else
    {
      char *debug_sec_data =
        ensure_debug_section_data (abfd, debug_sec_data_ptr, debug_sec_ptr);
      if (debug_sec_data == NULL)
        return false;

      if (sym->u.syment._n._n_n._n_offset >= (*debug_sec_ptr)->size)
        sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
      else
        sym->u.syment._n._n_n._n_offset =
          (uintptr_t) (debug_sec_data + sym->u.syment._n._n_n._n_offset);
    }
  return true;
}

combined_entry_type *
coff_get_normalized_symtab (bfd *abfd)
{
  if (obj_raw_syments (abfd) != NULL)
    return obj_raw_syments (abfd);

  if (!_bfd_coff_get_external_symbols (abfd))
    return NULL;

  bfd_size_type count = obj_raw_syment_count (abfd);
  if (count > (bfd_size_type) -1 / sizeof (combined_entry_type))
    return NULL;

  bfd_size_type size = count * sizeof (combined_entry_type);
  combined_entry_type *internal =
    (combined_entry_type *) bfd_zalloc (abfd, size);
  if (internal == NULL && size != 0)
    return NULL;

  char *raw_src = (char *) obj_coff_external_syms (abfd);
  size_t symesz = bfd_coff_symesz (abfd);
  char *raw_end = PTR_ADD (raw_src, count * symesz);

  const char *string_table = NULL;
  asection *debug_sec = NULL;
  char *debug_sec_data = NULL;

  combined_entry_type *internal_ptr;
  for (internal_ptr = internal; raw_src < raw_end;
       raw_src += symesz, internal_ptr++)
    {
      bfd_coff_swap_sym_in (abfd, (void *) raw_src,
                            (void *) &internal_ptr->u.syment);
      internal_ptr->is_sym = true;
      combined_entry_type *sym = internal_ptr;

      unsigned int numaux = sym->u.syment.n_numaux;
      if (numaux > ((raw_end - 1) - raw_src) / symesz)
        return NULL;

      for (unsigned int i = 0; i < numaux; i++)
        {
          combined_entry_type *aux_internal_ptr = internal_ptr + i + 1;
          char *aux_raw_src = raw_src + (i + 1) * symesz;

          bfd_coff_swap_aux_in (abfd, (void *) aux_raw_src,
                                sym->u.syment.n_type,
                                sym->u.syment.n_sclass,
                                (int) i, numaux,
                                &(aux_internal_ptr->u.auxent));

          aux_internal_ptr->is_sym = false;
          coff_pointerize_aux (abfd, internal, sym, i, aux_internal_ptr);
        }

      char *raw_src_after_auxes = raw_src + numaux * symesz;
      bool success;
      if (sym->u.syment.n_sclass == C_FILE && numaux > 0)
        {
          success = process_c_file_symbol (abfd, sym, raw_src_after_auxes,
                                           symesz, &string_table);
        }
      else
        {
          success = process_regular_symbol (abfd, sym, &string_table,
                                            &debug_sec_data, &debug_sec);
        }

      if (!success)
        return NULL;

      raw_src += numaux * symesz;
      internal_ptr += numaux;
    }

  if (obj_coff_external_syms (abfd) != NULL
      && !obj_coff_keep_syms (abfd))
    {
      free (obj_coff_external_syms (abfd));
      obj_coff_external_syms (abfd) = NULL;
    }

  obj_raw_syments (abfd) = internal;
  BFD_ASSERT (obj_raw_syment_count (abfd)
              == (size_t) (internal_ptr - internal));

  return internal;
}

long
coff_get_reloc_upper_bound (bfd *abfd, sec_ptr asect)
{
  size_t count = asect->reloc_count;
  size_t raw_size;

  if (count >= (size_t) LONG_MAX / sizeof (arelent *))
    {
      bfd_set_error (bfd_error_file_too_big);
      return -1;
    }

  if (_bfd_mul_overflow (count, bfd_coff_relsz (abfd), &raw_size))
    {
      bfd_set_error (bfd_error_file_too_big);
      return -1;
    }

  if (!bfd_write_p (abfd))
    {
      ufile_ptr filesize = bfd_get_file_size (abfd);
      if (filesize != 0 && raw_size > filesize)
        {
          bfd_set_error (bfd_error_file_truncated);
          return -1;
        }
    }

  return (long) ((count + 1) * sizeof (arelent *));
}

asymbol *
coff_make_empty_symbol (bfd *abfd)
{
  coff_symbol_type *new_symbol = bfd_zalloc (abfd, sizeof (*new_symbol));

  if (new_symbol == NULL)
    {
      return NULL;
    }

  new_symbol->symbol.the_bfd = abfd;
  return &new_symbol->symbol;
}

/* Make a debugging symbol.  */

asymbol *
coff_bfd_make_debug_symbol (bfd *abfd)
{
  const size_t max_aux_entries = 10;

  coff_symbol_type *new_symbol = (coff_symbol_type *) bfd_alloc (abfd, sizeof (coff_symbol_type));
  if (new_symbol == NULL)
    {
      return NULL;
    }

  size_t native_size = sizeof (combined_entry_type) * max_aux_entries;
  new_symbol->native = (combined_entry_type *) bfd_zalloc (abfd, native_size);
  if (new_symbol->native == NULL)
    {
      return NULL;
    }

  new_symbol->native->is_sym = true;
  new_symbol->symbol.section = bfd_abs_section_ptr;
  new_symbol->symbol.flags = BSF_DEBUGGING;
  new_symbol->symbol.the_bfd = abfd;
  new_symbol->lineno = NULL;
  new_symbol->done_lineno = false;

  return &new_symbol->symbol;
}

void
coff_get_symbol_info (bfd *abfd, asymbol *symbol, symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);

  struct coff_native_symbol *native_sym = coffsymbol (symbol)->native;

  if (native_sym != NULL && native_sym->fix_value && native_sym->is_sym)
    {
      uintptr_t symbol_val_ptr = (uintptr_t) native_sym->u.syment.n_value;
      uintptr_t raw_syms_ptr = (uintptr_t) obj_raw_syments (abfd);

      ret->value = (symbol_val_ptr - raw_syms_ptr) / sizeof (combined_entry_type);
    }
}

/* Print out information about COFF symbol.  */

static bfd_vma
get_symbol_value (const combined_entry_type *combined,
		  const combined_entry_type *root)
{
  if (!combined->fix_value)
    return (bfd_vma) combined->u.syment.n_value;

  return (bfd_vma) (((uintptr_t) combined->u.syment.n_value
		     - (uintptr_t) root) / sizeof (combined_entry_type));
}

static long
get_tag_index (const combined_entry_type *auxp,
	       const combined_entry_type *root)
{
  if (auxp->fix_tag)
    return auxp->u.auxent.x_sym.x_tagndx.p - root;

  return auxp->u.auxent.x_sym.x_tagndx.u32;
}

static long
get_fcn_end_index (const combined_entry_type *auxp,
		   const combined_entry_type *root)
{
  if (auxp->fix_end)
    return auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p - root;

  return auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32;
}

static void
print_aux_file (FILE *file, const combined_entry_type *auxp)
{
  fprintf (file, "File ");
  if (auxp->u.auxent.x_file.x_ftype)
    fprintf (file, "ftype %d fname \"%s\"", auxp->u.auxent.x_file.x_ftype,
	     (char *) auxp->u.auxent.x_file.x_n.x_n.x_offset);
}

static void
print_aux_dwarf (FILE *file, const combined_entry_type *auxp)
{
  fprintf (file, "AUX scnlen %#" PRIx64 " nreloc %" PRId64,
	   auxp->u.auxent.x_sect.x_scnlen, auxp->u.auxent.x_sect.x_nreloc);
}

static void
print_aux_stat_section (FILE *file, const combined_entry_type *auxp)
{
  fprintf (file, "AUX scnlen 0x%lx nreloc %d nlnno %d",
	   (unsigned long) auxp->u.auxent.x_scn.x_scnlen,
	   auxp->u.auxent.x_scn.x_nreloc, auxp->u.auxent.x_scn.x_nlinno);
  if (auxp->u.auxent.x_scn.x_checksum != 0
      || auxp->u.auxent.x_scn.x_associated != 0
      || auxp->u.auxent.x_scn.x_comdat != 0)
    fprintf (file, " checksum 0x%x assoc %d comdat %d",
	     auxp->u.auxent.x_scn.x_checksum,
	     auxp->u.auxent.x_scn.x_associated,
	     auxp->u.auxent.x_scn.x_comdat);
}

static void
print_aux_function (FILE *file, const combined_entry_type *auxp,
		    const combined_entry_type *root)
{
  long tagndx = get_tag_index (auxp, root);
  long next = get_fcn_end_index (auxp, root);
  long llnos = auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_lnnoptr;

  fprintf (file, "AUX tagndx %ld ttlsiz 0x%lx lnnos %ld next %ld",
	   tagndx, (unsigned long) auxp->u.auxent.x_sym.x_misc.x_fsize,
	   llnos, next);
}

static void
print_aux_default (FILE *file, const combined_entry_type *auxp,
		   const combined_entry_type *root)
{
  long tagndx = get_tag_index (auxp, root);

  fprintf (file, "AUX lnno %d size 0x%x tagndx %ld",
	   auxp->u.auxent.x_sym.x_misc.x_lnsz.x_lnno,
	   auxp->u.auxent.x_sym.x_misc.x_lnsz.x_size, tagndx);

  if (auxp->fix_end)
    fprintf (file, " endndx %ld", get_fcn_end_index (auxp, root));
}

static void
print_coff_aux_entry (bfd *abfd, FILE *file,
		      const combined_entry_type *combined,
		      const combined_entry_type *auxp,
		      unsigned int aux_index,
		      const combined_entry_type *root)
{
  fprintf (file, "\n");

  if (bfd_coff_print_aux (abfd, file, root, combined,
			  (combined_entry_type *) auxp, aux_index))
    return;

  switch (combined->u.syment.n_sclass)
    {
    case C_FILE:
      print_aux_file (file, auxp);
      break;

    case C_DWARF:
      print_aux_dwarf (file, auxp);
      break;

    case C_STAT:
      if (combined->u.syment.n_type == T_NULL)
	{
	  print_aux_stat_section (file, auxp);
	  break;
	}
      /* Fall through.  */
    case C_EXT:
    case C_AIX_WEAKEXT:
      if (ISFCN (combined->u.syment.n_type))
	{
	  print_aux_function (file, auxp, root);
	  break;
	}
      /* Fall through.  */
    default:
      print_aux_default (file, auxp, root);
      break;
    }
}

static void
print_coff_aux_symbols (bfd *abfd, FILE *file,
			const combined_entry_type *combined,
			const combined_entry_type *root)
{
  unsigned int num_aux = combined->u.syment.n_numaux;
  const combined_entry_type *limit = root + obj_raw_syment_count (abfd);

  for (unsigned int aux = 0; aux < num_aux; ++aux)
    {
      const combined_entry_type *auxp = combined + aux + 1;

      if (auxp >= limit)
	{
	  fprintf (file, _("\n<corrupt auxiliary entry>"));
	  break;
	}

      BFD_ASSERT (!auxp->is_sym);
      print_coff_aux_entry (abfd, file, combined, auxp, aux, root);
    }
}

static void
print_coff_symbol_lineno (bfd *abfd, FILE *file, asymbol *symbol)
{
  struct lineno_cache_entry *l = coffsymbol (symbol)->lineno;

  if (!l)
    return;

  const char *filename = (l->u.sym->name != bfd_symbol_error_name
			  ? l->u.sym->name : _("<corrupt>"));
  fprintf (file, "\n%s :", filename);
  l++;

  while (l->line_number)
    {
      if (l->line_number > 0)
	{
	  fprintf (file, "\n%4d : ", l->line_number);
	  bfd_fprintf_vma (abfd, file, l->u.offset + symbol->section->vma);
	}
      l++;
    }
}

static void
print_native_coff_symbol_all (bfd *abfd, FILE *file, asymbol *symbol,
			      const char *symname)
{
  combined_entry_type *combined = coffsymbol (symbol)->native;
  combined_entry_type *root = obj_raw_syments (abfd);
  long sym_index = combined - root;

  fprintf (file, "[%3ld]", sym_index);

  if (sym_index < 0 || (size_t) sym_index >= obj_raw_syment_count (abfd))
    {
      fprintf (file, _("<corrupt info> %s"), symname);
      return;
    }

  BFD_ASSERT (combined->is_sym);

  bfd_vma val = get_symbol_value (combined, root);

  fprintf (file, "(sec %2d)(fl 0x%02x)(ty %4x)(scl %3d) (nx %d) 0x",
	   combined->u.syment.n_scnum, combined->u.syment.n_flags,
	   combined->u.syment.n_type, combined->u.syment.n_sclass,
	   combined->u.syment.n_numaux);
  bfd_fprintf_vma (abfd, file, val);
  fprintf (file, " %s", symname);

  if (combined->u.syment.n_numaux > 0)
    print_coff_aux_symbols (abfd, file, combined, root);

  print_coff_symbol_lineno (abfd, file, symbol);
}

static void
print_generic_coff_symbol_all (bfd *abfd, FILE *file, asymbol *symbol,
			       const char *symname)
{
  bfd_print_symbol_vandf (abfd, (void *) file, symbol);
  fprintf (file, " %-5s %s %s %s", symbol->section->name,
	   coffsymbol (symbol)->native ? "n" : "g",
	   coffsymbol (symbol)->lineno ? "l" : " ", symname);
}

void
coff_print_symbol (bfd *abfd, void *filep, asymbol *symbol,
		   bfd_print_symbol_type how)
{
  FILE *file = (FILE *) filep;
  const char *symname = (symbol->name != bfd_symbol_error_name
			 ? symbol->name : _("<corrupt>"));

  switch (how)
    {
    case bfd_print_symbol_name:
      fprintf (file, "%s", symname);
      break;

    case bfd_print_symbol_more:
      fprintf (file, "coff %s %s",
	       coffsymbol (symbol)->native ? "n" : "g",
	       coffsymbol (symbol)->lineno ? "l" : " ");
      break;

    case bfd_print_symbol_all:
      if (coffsymbol (symbol)->native)
	print_native_coff_symbol_all (abfd, file, symbol, symname);
      else
	print_generic_coff_symbol_all (abfd, file, symbol, symname);
      break;
    }
}

/* Return whether a symbol name implies a local symbol.  In COFF,
   local symbols generally start with ``.L''.  Most targets use this
   function for the is_local_label_name entry point, but some may
   override it.  */

bool
_bfd_coff_is_local_label_name (bfd *abfd ATTRIBUTE_UNUSED,
			       const char *name)
{
  return name != NULL && name[0] == '.' && name[1] == 'L';
}

/* Provided a BFD, a section and an offset (in bytes, not octets) into the
   section, calculate and return the name of the source file and the line
   nearest to the wanted location.  */

bool
coff_find_nearest_line_with_names (bfd *abfd,
				   asymbol **symbols,
				   asection *section,
				   bfd_vma offset,
				   const char **filename_ptr,
				   const char **functionname_ptr,
				   unsigned int *line_ptr,
				   const struct dwarf_debug_section *debug_sections)
{
  coff_data_type *cof = coff_data (abfd);
  if (cof == NULL)
    {
      return false;
    }

  bool found = false;
  if (!_bfd_stab_section_find_nearest_line (abfd, symbols, section, offset,
					    &found, filename_ptr,
					    functionname_ptr, line_ptr,
					    &cof->line_info))
    {
      return false;
    }
  if (found)
    {
      return true;
    }

  if (_bfd_dwarf2_find_nearest_line (abfd, symbols, NULL, section, offset,
				     filename_ptr, functionname_ptr,
				     line_ptr, NULL, debug_sections,
				     &cof->dwarf2_find_line_info))
    {
      return true;
    }

  struct coff_section_tdata *sec_data = coff_section_data (abfd, section);

  if (cof->dwarf2_find_line_info != NULL)
    {
      bfd_signed_vma bias = 0;

      if (sec_data == NULL && section->owner == abfd)
	{
	  section->used_by_bfd = bfd_zalloc (abfd, sizeof (struct coff_section_tdata));
	  sec_data = (struct coff_section_tdata *) section->used_by_bfd;
	}

      if (sec_data != NULL && sec_data->saved_bias)
	{
	  bias = sec_data->bias;
	}
      else if (symbols)
	{
	  bias = _bfd_dwarf2_find_symbol_bias (symbols, &cof->dwarf2_find_line_info);
	  if (sec_data)
	    {
	      sec_data->saved_bias = true;
	      sec_data->bias = bias;
	    }
	}

      if (bias != 0
	  && _bfd_dwarf2_find_nearest_line (abfd, symbols, NULL, section,
					    offset + bias,
					    filename_ptr, functionname_ptr,
					    line_ptr, NULL, debug_sections,
					    &cof->dwarf2_find_line_info))
	{
	  return true;
	}
    }

  *filename_ptr = NULL;
  *functionname_ptr = NULL;
  *line_ptr = 0;

  if (!bfd_family_coff (abfd) || cof->raw_syments == NULL)
    {
      return false;
    }

  combined_entry_type *p = cof->raw_syments;
  combined_entry_type * const pend = p + cof->raw_syment_count;
  while (p < pend)
    {
      BFD_ASSERT (p->is_sym);
      if (p->u.syment.n_sclass == C_FILE)
	{
	  break;
	}
      p += 1 + p->u.syment.n_numaux;
    }

  if (p < pend)
    {
      bfd_vma sec_vma = bfd_section_vma (section);
      bfd_vma min_diff = (bfd_vma) -1;

      *filename_ptr = (const char *) p->u.syment._n._n_n._n_offset;

      for (;;)
	{
	  combined_entry_type *p2;

	  for (p2 = p + 1 + p->u.syment.n_numaux; p2 < pend; p2 += 1 + p2->u.syment.n_numaux)
	    {
	      BFD_ASSERT (p2->is_sym);
	      if (p2->u.syment.n_scnum > 0
		  && section == coff_section_from_bfd_index (abfd, p2->u.syment.n_scnum))
		{
		  break;
		}
	      if (p2->u.syment.n_sclass == C_FILE)
		{
		  p2 = pend;
		  break;
		}
	    }
	  if (p2 >= pend)
	    {
	      break;
	    }

	  bfd_vma file_addr = (bfd_vma) p2->u.syment.n_value;
	  if (p2->u.syment.n_scnum > 0)
	    {
	      file_addr += coff_section_from_bfd_index (abfd, p2->u.syment.n_scnum)->vma;
	    }
	  bfd_vma current_diff = offset + sec_vma - file_addr;
	  if (offset + sec_vma >= file_addr && current_diff <= min_diff)
	    {
	      *filename_ptr = (const char *) p->u.syment._n._n_n._n_offset;
	      min_diff = current_diff;
	    }

	  if (p->u.syment.n_value >= cof->raw_syment_count)
	    {
	      break;
	    }

	  combined_entry_type *next_p = cof->raw_syments + p->u.syment.n_value;
	  if (next_p <= p)
	    {
	      break;
	    }

	  p = next_p;
	  if (!p->is_sym || p->u.syment.n_sclass != C_FILE)
	    {
	      break;
	    }
	}
    }

  if (section->lineno_count == 0)
    {
      *functionname_ptr = NULL;
      *line_ptr = 0;
      return true;
    }

  unsigned int i;
  unsigned int line_base;
  if (sec_data != NULL && sec_data->i > 0 && offset >= sec_data->offset)
    {
      i = sec_data->i;
      *functionname_ptr = sec_data->function;
      line_base = sec_data->line_base;
    }
  else
    {
      i = 0;
      line_base = 0;
      *functionname_ptr = NULL;
    }

  if (section->lineno != NULL)
    {
      bfd_vma last_value = 0;
      alent *l = &section->lineno[i];

      for (; i < section->lineno_count; i++, l++)
	{
	  if (l->line_number == 0)
	    {
	      coff_symbol_type *coff_sym = (coff_symbol_type *) l->u.sym;
	      if (coff_sym->symbol.value > offset)
		{
		  break;
		}

	      *functionname_ptr = coff_sym->symbol.name;
	      last_value = coff_sym->symbol.value;
	      if (coff_sym->native)
		{
		  combined_entry_type *s = coff_sym->native;
		  BFD_ASSERT (s->is_sym);
		  s = s + 1 + s->u.syment.n_numaux;

		  if (s < pend && s->u.syment.n_scnum == N_DEBUG)
		    {
		      s = s + 1 + s->u.syment.n_numaux;
		    }

		  if (s < pend && s->u.syment.n_numaux)
		    {
		      union internal_auxent *a = &((s + 1)->u.auxent);
		      line_base = a->x_sym.x_misc.x_lnsz.x_lnno;
		      *line_ptr = line_base;
		    }
		}
	    }
	  else
	    {
	      if (l->u.offset > offset)
		{
		  break;
		}
	      *line_ptr = l->line_number + line_base - 1;
	    }
	}

      if (i >= section->lineno_count && last_value != 0 && offset - last_value > 0x100)
	{
	  *functionname_ptr = NULL;
	  *line_ptr = 0;
	}
    }

  if (section->owner == abfd)
    {
      if (sec_data == NULL)
	{
	  section->used_by_bfd = bfd_zalloc (abfd, sizeof (struct coff_section_tdata));
	  sec_data = (struct coff_section_tdata *) section->used_by_bfd;
	}

      if (sec_data != NULL)
	{
	  sec_data->offset = offset;
	  sec_data->i = (i > 0) ? (i - 1) : 0;
	  sec_data->function = *functionname_ptr;
	  sec_data->line_base = line_base;
	}
    }

  return true;
}

bool
coff_find_nearest_line (bfd *abfd,
			asymbol **symbols,
			asection *section,
			bfd_vma offset,
			const char **filename_ptr,
			const char **functionname_ptr,
			unsigned int *line_ptr,
			unsigned int *discriminator_ptr)
{
  if (discriminator_ptr != NULL)
    {
      *discriminator_ptr = 0;
    }
  return coff_find_nearest_line_with_names (abfd,
					    symbols,
					    section,
					    offset,
					    filename_ptr,
					    functionname_ptr,
					    line_ptr,
					    dwarf_debug_sections);
}

bool
coff_find_inliner_info (bfd *abfd,
                        const char **filename_ptr,
                        const char **functionname_ptr,
                        unsigned int *line_ptr)
{
  return _bfd_dwarf2_find_inliner_info (abfd, filename_ptr,
                                        functionname_ptr, line_ptr,
                                        &coff_data(abfd)->dwarf2_find_line_info);
}

int
coff_sizeof_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (!abfd || !info)
    {
      return 0;
    }

  size_t size = bfd_coff_filhsz (abfd);
  if (!bfd_link_relocatable (info))
    {
      size += bfd_coff_aoutsz (abfd);
    }

  size += (size_t) abfd->section_count * bfd_coff_scnhsz (abfd);

  if (size > (size_t) INT_MAX)
    {
      return -1;
    }

  return (int) size;
}

/* Change the class of a coff symbol held by BFD.  */

static combined_entry_type *
create_native_coff_symbol (bfd *abfd, asymbol *symbol)
{
  combined_entry_type *native =
    (combined_entry_type *) bfd_zalloc (abfd, sizeof (*native));
  if (native == NULL)
    {
      return NULL;
    }

  native->is_sym = true;
  native->u.syment.n_type = T_NULL;

  if (bfd_is_und_section (symbol->section)
      || bfd_is_com_section (symbol->section))
    {
      native->u.syment.n_scnum = N_UNDEF;
      native->u.syment.n_value = symbol->value;
    }
  else
    {
      native->u.syment.n_scnum =
	symbol->section->output_section->target_index;
      native->u.syment.n_value =
	(symbol->value + symbol->section->output_offset);
      if (!obj_pe (abfd))
	{
	  native->u.syment.n_value += symbol->section->output_section->vma;
	}
      native->u.syment.n_flags = bfd_asymbol_bfd (symbol)->flags;
    }

  return native;
}

bool
bfd_coff_set_symbol_class (bfd *abfd,
			   asymbol *symbol,
			   unsigned int symbol_class)
{
  coff_symbol_type *csym = coff_symbol_from (symbol);

  if (csym == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  if (csym->native == NULL)
    {
      csym->native = create_native_coff_symbol (abfd, symbol);
      if (csym->native == NULL)
	{
	  return false;
	}
    }

  csym->native->u.syment.n_sclass = symbol_class;
  return true;
}

static const char *
get_linkonce_key (const struct coff_comdat_info *s_comdat, const char *name)
{
  const char *key;

  if (s_comdat != NULL)
    return s_comdat->name;

  if (startswith (name, ".gnu.linkonce.")
      && (key = strchr (name + sizeof (".gnu.linkonce.") - 1, '.')) != NULL)
    return key + 1;

  /* FIXME: gcc as of 2011-09 emits sections like .text$<key>,
     .xdata$<key> and .pdata$<key> only the first of which has a
     comdat key.  Should these all match the LTO IR key?  */
  return name;
}

static bool
sections_are_linkonce_match (asection *sec,
			     const struct coff_comdat_info *s_comdat,
			     asection *l_sec,
			     const struct coff_comdat_info *l_comdat)
{
  if ((sec->owner->flags & BFD_PLUGIN) != 0
      || (l_sec->owner->flags & BFD_PLUGIN) != 0)
    return true;

  bool same_comdat_status = (s_comdat != NULL) == (l_comdat != NULL);
  return same_comdat_status && (strcmp (sec->name, l_sec->name) == 0);
}

bool
_bfd_coff_section_already_linked (bfd *abfd,
				  asection *sec,
				  struct bfd_link_info *info)
{
  if (sec->output_section == bfd_abs_section_ptr)
    return false;

  flagword flags = sec->flags;
  if ((flags & (SEC_LINK_ONCE | SEC_GROUP)) != SEC_LINK_ONCE)
    return false;

  const char *name = bfd_section_name (sec);
  struct coff_comdat_info *s_comdat = bfd_coff_get_comdat_section (abfd, sec);
  const char *key = get_linkonce_key (s_comdat, name);

  struct bfd_section_already_linked_hash_entry *already_linked_list;
  already_linked_list = bfd_section_already_linked_table_lookup (key);
  if (already_linked_list == NULL)
    {
      info->callbacks->fatal (_("%P: already_linked_table lookup: %E\n"));
      return false;
    }

  for (struct bfd_section_already_linked *l = already_linked_list->entry;
       l != NULL; l = l->next)
    {
      struct coff_comdat_info *l_comdat
	= bfd_coff_get_comdat_section (l->sec->owner, l->sec);

      if (sections_are_linkonce_match (sec, s_comdat, l->sec, l_comdat))
	return _bfd_handle_already_linked (sec, l, info);
    }

  if (!bfd_section_already_linked_table_insert (already_linked_list, sec))
    {
      info->callbacks->fatal (_("%P: already_linked_table insert: %E\n"));
    }

  return false;
}

/* Initialize COOKIE for input bfd ABFD. */

static bool
init_reloc_cookie (struct coff_reloc_cookie *cookie,
		   struct bfd_link_info *info ATTRIBUTE_UNUSED,
		   bfd *abfd)
{
  if (!bfd_coff_slurp_symbol_table (abfd))
    {
      return false;
    }

  cookie->abfd = abfd;
  cookie->sym_hashes = obj_coff_sym_hashes (abfd);
  cookie->symbols = obj_symbols (abfd);

  return cookie->sym_hashes != NULL && cookie->symbols != NULL;
}

/* Free the memory allocated by init_reloc_cookie, if appropriate.  */

static void
fini_reloc_cookie (struct coff_reloc_cookie *cookie, bfd *abfd)
{
  (void)cookie;
  (void)abfd;
}

/* Initialize the relocation information in COOKIE for input section SEC
   of input bfd ABFD.  */

static bool
init_reloc_cookie_rels (struct coff_reloc_cookie *cookie,
                        struct bfd_link_info *info ATTRIBUTE_UNUSED,
                        bfd *abfd,
                        asection *sec)
{
  if (sec->reloc_count > 0)
    {
      cookie->rels = _bfd_coff_read_internal_relocs (abfd, sec, false,
                                                     NULL, 0, NULL);
      if (cookie->rels == NULL)
        {
          return false;
        }
    }
  else
    {
      cookie->rels = NULL;
    }

  cookie->rel = cookie->rels;
  cookie->relend = cookie->rels + sec->reloc_count;
  return true;
}

/* Free the memory allocated by init_reloc_cookie_rels,
   if appropriate.  */

static void
fini_reloc_cookie_rels (struct coff_reloc_cookie *cookie,
			asection *sec)
{
  if (cookie->rels == NULL)
    {
      return;
    }

  struct coff_section_data *sdata = coff_section_data (NULL, sec);

  if (sdata != NULL && sdata->relocs != cookie->rels)
    {
      free (cookie->rels);
    }
}

/* Initialize the whole of COOKIE for input section SEC.  */

static bool
init_reloc_cookie_for_section (struct coff_reloc_cookie *cookie,
			       struct bfd_link_info *info,
			       asection *sec)
{
  bfd *owner = sec->owner;

  if (!init_reloc_cookie (cookie, info, owner))
    return false;

  if (!init_reloc_cookie_rels (cookie, info, owner, sec))
    {
      fini_reloc_cookie (cookie, owner);
      return false;
    }

  return true;
}

/* Free the memory allocated by init_reloc_cookie_for_section,
   if appropriate.  */

static void
fini_reloc_cookie_for_section (struct coff_reloc_cookie *cookie, asection *sec)
{
  if (!cookie || !sec)
    {
      return;
    }

  fini_reloc_cookie_rels (cookie, sec);
  fini_reloc_cookie (cookie, sec->owner);
}

static asection *
_bfd_coff_gc_mark_hook (asection *sec,
			struct bfd_link_info *info ATTRIBUTE_UNUSED,
			struct internal_reloc *rel ATTRIBUTE_UNUSED,
			struct coff_link_hash_entry *h,
			struct internal_syment *sym)
{
  if (h == NULL)
    {
      return coff_section_from_bfd_index (sec->owner, sym->n_scnum);
    }

  switch (h->root.type)
    {
    case bfd_link_hash_defined:
    case bfd_link_hash_defweak:
      return h->root.u.def.section;

    case bfd_link_hash_common:
      return h->root.u.c.p->section;

    case bfd_link_hash_undefweak:
      if (h->symbol_class == C_NT_WEAK && h->numaux == 1)
	{
	  struct coff_link_hash_entry *h2 =
	    h->auxbfd->tdata.coff_obj_data->sym_hashes
	    [h->aux->x_sym.x_tagndx.u32];

	  if (h2 != NULL && h2->root.type != bfd_link_hash_undefined)
	    {
	      return h2->root.u.def.section;
	    }
	}
      /* Fall through. */

    default:
      return NULL;
    }
}

/* COOKIE->rel describes a relocation against section SEC, which is
   a section we've decided to keep.  Return the section that contains
   the relocation symbol, or NULL if no section contains it.  */

static asection *
_bfd_coff_gc_mark_rsec (struct bfd_link_info *info, asection *sec,
			coff_gc_mark_hook_fn gc_mark_hook,
			struct coff_reloc_cookie *cookie)
{
  struct coff_link_hash_entry *h = cookie->sym_hashes[cookie->rel->r_symndx];
  void *syment_ptr = NULL;

  if (h != NULL)
    {
      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	{
	  h = (struct coff_link_hash_entry *) h->root.u.i.link;
	}
    }
  else
    {
      long *sym_indices = obj_convert (sec->owner);
      long sym_index = sym_indices[cookie->rel->r_symndx];
      syment_ptr = &(cookie->symbols + sym_index)->native->u.syment;
    }

  return (*gc_mark_hook) (sec, info, cookie->rel, h, syment_ptr);
}

static bool _bfd_coff_gc_mark
  (struct bfd_link_info *, asection *, coff_gc_mark_hook_fn);

/* COOKIE->rel describes a relocation against section SEC, which is
   a section we've decided to keep.  Mark the section that contains
   the relocation symbol.  */

static bool
_bfd_coff_gc_mark_reloc (struct bfd_link_info *info,
			 asection *sec,
			 coff_gc_mark_hook_fn gc_mark_hook,
			 struct coff_reloc_cookie *cookie)
{
  asection *rsec = _bfd_coff_gc_mark_rsec (info, sec, gc_mark_hook, cookie);

  if (!rsec || rsec->gc_mark)
    {
      return true;
    }

  if (bfd_get_flavour (rsec->owner) != bfd_target_coff_flavour)
    {
      rsec->gc_mark = 1;
      return true;
    }

  return _bfd_coff_gc_mark (info, rsec, gc_mark_hook);
}

/* The mark phase of garbage collection.  For a given section, mark
   it and any sections in this section's group, and all the sections
   which define symbols to which it refers.  */

static bool
_bfd_coff_gc_mark (struct bfd_link_info *info,
		   asection *sec,
		   coff_gc_mark_hook_fn gc_mark_hook)
{
  sec->gc_mark = 1;

  if ((sec->flags & SEC_RELOC) == 0 || sec->reloc_count == 0)
    return true;

  struct coff_reloc_cookie cookie;
  if (!init_reloc_cookie_for_section (&cookie, info, sec))
    return false;

  bool ret = true;
  for (; cookie.rel < cookie.relend; cookie.rel++)
    {
      if (!_bfd_coff_gc_mark_reloc (info, sec, gc_mark_hook, &cookie))
	{
	  ret = false;
	  break;
	}
    }

  fini_reloc_cookie_for_section (&cookie, sec);
  return ret;
}

static bool
check_and_mark_initial_sections (bfd *ibfd)
{
  bool some_kept = false;
  for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
      if ((isec->flags & SEC_LINKER_CREATED) != 0)
	{
	  isec->gc_mark = 1;
	}
      else if (isec->gc_mark)
	{
	  some_kept = true;
	}
    }
  return some_kept;
}

static void
mark_debug_and_special_sections (bfd *ibfd)
{
  for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
      if ((isec->flags & SEC_DEBUGGING) != 0
	  || (isec->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0)
	{
	  isec->gc_mark = 1;
	}
    }
}

static void
_bfd_coff_gc_mark_extra_sections (struct bfd_link_info *info)
{
  if (info == NULL)
    {
      return;
    }

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_flavour (ibfd) != bfd_target_coff_flavour)
	{
	  continue;
	}

      if (check_and_mark_initial_sections (ibfd))
	{
	  mark_debug_and_special_sections (ibfd);
	}
    }
}

/* Sweep symbols in swept sections.  Called via coff_link_hash_traverse.  */

static bool
coff_gc_sweep_symbol (struct coff_link_hash_entry *h,
		      void *data ATTRIBUTE_UNUSED)
{
  if (h->root.type == bfd_link_hash_warning)
    h = (struct coff_link_hash_entry *) h->root.u.i.link;

  if (!h
      || (h->root.type != bfd_link_hash_defined
	  && h->root.type != bfd_link_hash_defweak))
    return true;

  struct bfd_section *sec = h->root.u.def.section;
  if (!sec || !sec->owner)
    return true;

  bool is_unmarked_for_gc = !sec->gc_mark;
  bool is_not_dynamic = !(sec->owner->flags & DYNAMIC);

  if (is_unmarked_for_gc && is_not_dynamic)
    {
      h->root.u.def.section = bfd_und_section_ptr;
      h->symbol_class = C_HIDDEN;
    }

  return true;
}

/* The sweep phase of garbage collection.  Remove all garbage sections.  */

typedef bool (*gc_sweep_hook_fn)
  (bfd *, struct bfd_link_info *, asection *, const struct internal_reloc *);

static inline bool
is_subsection (const char *str, const char *prefix)
{
  size_t n = strlen (prefix);

  if (strncmp (str, prefix, n) != 0)
    {
      return false;
    }

  if (str[n] == '\0')
    {
      return true;
    }

  return str[n] == '$' && isdigit ((unsigned char) str[n + 1])
         && str[n + 2] == '\0';
}

static bool
should_keep_coff_section (const asection *sec)
{
  if ((sec->flags & (SEC_DEBUGGING | SEC_LINKER_CREATED)) != 0)
    return true;

  if ((sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0)
    return true;

  return startswith (sec->name, ".idata")
	 || startswith (sec->name, ".pdata")
	 || startswith (sec->name, ".xdata")
	 || is_subsection (sec->name, ".didat")
	 || startswith (sec->name, ".rsrc");
}

static void
sweep_section (asection *sec, bfd *sub, struct bfd_link_info *info)
{
  if (sec->gc_mark || should_keep_coff_section (sec))
    {
      sec->gc_mark = 1;
      return;
    }

  if ((sec->flags & SEC_EXCLUDE) != 0)
    return;

  sec->flags |= SEC_EXCLUDE;

  if (info->print_gc_sections && sec->size != 0)
    _bfd_error_handler (_("removing unused section '%pA' in file '%pB'"),
			sec, sub);
}

static bool
coff_gc_sweep (bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  for (bfd *sub = info->input_bfds; sub != NULL; sub = sub->link.next)
    {
      if (bfd_get_flavour (sub) != bfd_target_coff_flavour)
	continue;

      for (asection *sec = sub->sections; sec != NULL; sec = sec->next)
	{
	  sweep_section (sec, sub, info);
	}
    }

  coff_link_hash_traverse (coff_hash_table (info), coff_gc_sweep_symbol,
			   NULL);

  return true;
}

/* Keep all sections containing symbols undefined on the command-line,
   and the section containing the entry symbol.  */

static void
_bfd_coff_gc_keep (struct bfd_link_info *info)
{
  for (struct bfd_sym_chain *sym = info->gc_sym_list; sym; sym = sym->next)
    {
      struct coff_link_hash_entry *h =
        coff_link_hash_lookup (coff_hash_table (info), sym->name,
                               false, false, false);

      if (h == NULL
          || (h->root.type != bfd_link_hash_defined
              && h->root.type != bfd_link_hash_defweak))
        {
          continue;
        }

      asection *sec = h->root.u.def.section;
      if (!bfd_is_abs_section (sec))
        {
          sec->flags |= SEC_KEEP;
        }
    }
}

/* Do mark and sweep of unused sections.  */

static bool
is_gc_root_section (const asection *sec)
{
  if ((sec->flags & (SEC_EXCLUDE | SEC_KEEP)) == SEC_KEEP)
    return true;

  return startswith (sec->name, ".vectors")
         || startswith (sec->name, ".ctors")
         || startswith (sec->name, ".dtors");
}

bool
bfd_coff_gc_sections (bfd *abfd, struct bfd_link_info *info)
{
  _bfd_coff_gc_keep (info);

  for (bfd *sub = info->input_bfds; sub != NULL; sub = sub->link.next)
    {
      if (bfd_get_flavour (sub) != bfd_target_coff_flavour)
	continue;

      for (asection *sec = sub->sections; sec != NULL; sec = sec->next)
	{
	  if (!sec->gc_mark && is_gc_root_section (sec))
	    {
	      if (!_bfd_coff_gc_mark (info, sec, _bfd_coff_gc_mark_hook))
		return false;
	    }
	}
    }

  _bfd_coff_gc_mark_extra_sections (info, _bfd_coff_gc_mark_hook);

  return coff_gc_sweep (abfd, info);
}

/* Return name used to identify a comdat group.  */

const char *
bfd_coff_group_name (bfd *abfd, const asection *sec)
{
  struct coff_comdat_info *ci = bfd_coff_get_comdat_section (abfd, sec);
  return ci ? ci->name : NULL;
}

bool
_bfd_coff_free_cached_info (bfd *abfd)
{
  struct coff_tdata *tdata;
  bfd_format format;

  format = bfd_get_format (abfd);
  if (!bfd_family_coff (abfd)
      || (format != bfd_object && format != bfd_core))
    {
      return _bfd_generic_bfd_free_cached_info (abfd);
    }

  tdata = coff_data (abfd);
  if (!tdata)
    {
      return _bfd_generic_bfd_free_cached_info (abfd);
    }

  if (tdata->section_by_index)
    {
      htab_delete (tdata->section_by_index);
      tdata->section_by_index = NULL;
    }

  if (tdata->section_by_target_index)
    {
      htab_delete (tdata->section_by_target_index);
      tdata->section_by_target_index = NULL;
    }

  if (obj_pe (abfd))
    {
      struct pe_tdata *pedata = pe_data (abfd);
      if (pedata && pedata->comdat_hash)
	{
	  htab_delete (pedata->comdat_hash);
	  pedata->comdat_hash = NULL;
	}
    }

  _bfd_dwarf2_cleanup_debug_info (abfd, &tdata->dwarf2_find_line_info);
  _bfd_stab_cleanup (abfd, &tdata->line_info);
  _bfd_coff_free_symbols (abfd);

  if (!obj_coff_keep_raw_syms (abfd) && obj_raw_syments (abfd))
    {
      bfd_release (abfd, obj_raw_syments (abfd));
      obj_raw_syments (abfd) = NULL;
      obj_symbols (abfd) = NULL;
      obj_convert (abfd) = NULL;
    }

  return _bfd_generic_bfd_free_cached_info (abfd);
}
