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
  const char *strings;
  char *name;
  size_t name_length;

  strings = _bfd_coff_read_string_table (abfd);
  if (strings == NULL)
    return NULL;
  if ((bfd_size_type)(strindex + 2) >= obj_coff_strings_len (abfd))
    return NULL;
  strings += strindex;
  name_length = strlen (strings) + 1;
  name = (char *) bfd_alloc (abfd, (bfd_size_type) name_length);
  if (name == NULL)
    return NULL;
  strcpy (name, strings);

  return name;
}

/* Decode a base 64 coded string at STR of length LEN, and write the result
   to RES.  Return true on success.
   Return false in case of invalid character or overflow.  */

static unsigned char_to_base64_value(char c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return 255;
}

static bool check_overflow(uint32_t val)
{
  #define OVERFLOW_THRESHOLD 26
  return (val >> OVERFLOW_THRESHOLD) != 0;
}

static bool decode_base64(const char *str, unsigned len, uint32_t *res)
{
  uint32_t val = 0;
  
  for (unsigned i = 0; i < len; i++)
  {
    unsigned d = char_to_base64_value(str[i]);
    
    if (d == 255)
      return false;
    
    if (check_overflow(val))
      return false;
    
    val = (val << 6) + d;
  }
  
  *res = val;
  return true;
}

/* Take a section header read from a coff file (in HOST byte order),
   and make a BFD "section" out of it.  This is used by ECOFF.  */

static bool
decode_llvm_long_name(const char *encoded, uint32_t *strindex)
{
  return decode_base64(encoded, SCNNMLEN - 2, strindex);
}

static char *
decode_pe_long_name(const char *encoded, long *strindex)
{
  char buf[SCNNMLEN];
  char *p;
  
  memcpy(buf, encoded, SCNNMLEN - 1);
  buf[SCNNMLEN - 1] = '\0';
  *strindex = strtol(buf, &p, 10);
  
  if (*p == '\0' && *strindex >= 0)
    return p;
  
  return NULL;
}

static char *
process_long_section_name(bfd *abfd, struct internal_scnhdr *hdr)
{
  char *name = NULL;
  
  if (hdr->s_name[1] == '/')
    {
      uint32_t strindex;
      if (!decode_llvm_long_name(hdr->s_name + 2, &strindex))
        return NULL;
      name = extract_long_section_name(abfd, strindex);
    }
  else
    {
      long strindex;
      if (decode_pe_long_name(hdr->s_name + 1, &strindex))
        {
          name = extract_long_section_name(abfd, strindex);
        }
    }
  
  return name;
}

static char *
get_section_name(bfd *abfd, struct internal_scnhdr *hdr)
{
  char *name = NULL;
  
  if (bfd_coff_set_long_section_names(abfd, bfd_coff_long_section_names(abfd))
      && hdr->s_name[0] == '/')
    {
      bfd_coff_set_long_section_names(abfd, true);
      name = process_long_section_name(abfd, hdr);
    }
  
  if (name == NULL)
    {
      name = (char *) bfd_alloc(abfd, sizeof(hdr->s_name) + 2);
      if (name == NULL)
        return NULL;
      strncpy(name, (char *) &hdr->s_name[0], sizeof(hdr->s_name));
      name[sizeof(hdr->s_name)] = 0;
    }
  
  return name;
}

static void
initialize_section_properties(asection *newsect, 
                             struct internal_scnhdr *hdr,
                             unsigned int target_index)
{
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
}

static flagword
compute_section_flags(struct internal_scnhdr *hdr, flagword flags)
{
  if ((flags & SEC_COFF_SHARED_LIBRARY) == 0)
    {
      if (hdr->s_nreloc != 0)
        flags |= SEC_RELOC;
      if (hdr->s_scnptr != 0)
        flags |= SEC_HAS_CONTENTS;
    }
  else
    {
      if (hdr->s_nreloc != 0)
        flags |= SEC_RELOC;
      if (hdr->s_scnptr != 0)
        flags |= SEC_HAS_CONTENTS;
    }
  
  return flags;
}

static bool
is_debug_section(const char *name)
{
  return startswith(name, ".debug_")
         || startswith(name, ".zdebug_")
         || startswith(name, ".gnu.debuglto_.debug_")
         || startswith(name, ".gnu.linkonce.wi.");
}

static bool
should_compress(bfd *abfd, asection *newsect)
{
  return !bfd_is_section_compressed(abfd, newsect)
         && (abfd->flags & BFD_COMPRESS)
         && newsect->size != 0;
}

static bool
should_decompress(bfd *abfd, asection *newsect)
{
  return bfd_is_section_compressed(abfd, newsect)
         && (abfd->flags & BFD_DECOMPRESS);
}

static bool
handle_compression(bfd *abfd, asection *newsect, const char *name)
{
  if (should_compress(abfd, newsect))
    {
      if (!bfd_init_section_compress_status(abfd, newsect))
        {
          _bfd_error_handler(_("%pB: unable to compress section %s"), abfd, name);
          return false;
        }
    }
  else if (should_decompress(abfd, newsect))
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
  
  return true;
}

static bool
make_a_section_from_file(bfd *abfd,
                        struct internal_scnhdr *hdr,
                        unsigned int target_index)
{
  asection *newsect;
  char *name;
  bool result = true;
  flagword flags;
  
  name = get_section_name(abfd, hdr);
  if (name == NULL)
    return false;
  
  newsect = bfd_make_section_anyway(abfd, name);
  if (newsect == NULL)
    return false;
  
  initialize_section_properties(newsect, hdr, target_index);
  bfd_coff_set_alignment_hook(abfd, newsect, hdr);
  
  if (!bfd_coff_styp_to_sec_flags_hook(abfd, hdr, name, newsect, &flags))
    result = false;
  
  if ((flags & SEC_COFF_SHARED_LIBRARY) != 0)
    newsect->lineno_count = 0;
  
  flags = compute_section_flags(hdr, flags);
  newsect->flags = flags;
  
  if ((flags & SEC_DEBUGGING) != 0
      && (flags & SEC_HAS_CONTENTS) != 0
      && is_debug_section(name))
    {
      if (!handle_compression(abfd, newsect, name))
        return false;
    }
  
  return result;
}

void
coff_object_cleanup (bfd *abfd)
{
  struct coff_tdata *td = coff_data (abfd);
  if (td == NULL)
    return;

  if (td->section_by_index)
    htab_delete (td->section_by_index);
  
  if (td->section_by_target_index)
    htab_delete (td->section_by_target_index);
  
  if (obj_pe (abfd) && pe_data (abfd)->comdat_hash)
    htab_delete (pe_data (abfd)->comdat_hash);
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
  void * tdata;
  bfd_size_type readsize;
  unsigned int scnhsz;
  char *external_sections;

  set_abfd_flags(abfd, internal_f);
  set_abfd_symcount(abfd, internal_f);
  set_abfd_start_address(abfd, internal_a);

  tdata = bfd_coff_mkobject_hook (abfd, (void *) internal_f, (void *) internal_a);
  if (tdata == NULL)
    goto fail2;

  scnhsz = bfd_coff_scnhsz (abfd);
  readsize = (bfd_size_type) nscns * scnhsz;
  external_sections = (char *) _bfd_alloc_and_read (abfd, readsize, readsize);
  if (!external_sections)
    goto fail;

  if (! bfd_coff_set_arch_mach_hook (abfd, (void *) internal_f))
    goto fail;

  if (!process_sections(abfd, nscns, external_sections, scnhsz))
    goto fail;

  _bfd_coff_free_symbols (abfd);
  return coff_object_cleanup;

 fail:
  cleanup_on_failure(abfd, tdata);
 fail2:
  restore_original_state(abfd, oflags, ostart);
  return NULL;
}

static void
set_abfd_flags(bfd *abfd, struct internal_filehdr *internal_f)
{
  if (!(internal_f->f_flags & F_RELFLG))
    abfd->flags |= HAS_RELOC;
  if ((internal_f->f_flags & F_EXEC))
    abfd->flags |= EXEC_P;
  if (!(internal_f->f_flags & F_LNNO))
    abfd->flags |= HAS_LINENO;
  if (!(internal_f->f_flags & F_LSYMS))
    abfd->flags |= HAS_LOCALS;
  if ((internal_f->f_flags & F_EXEC) != 0)
    abfd->flags |= D_PAGED;
}

static void
set_abfd_symcount(bfd *abfd, struct internal_filehdr *internal_f)
{
  abfd->symcount = internal_f->f_nsyms;
  if (internal_f->f_nsyms)
    abfd->flags |= HAS_SYMS;
}

static void
set_abfd_start_address(bfd *abfd, struct internal_aouthdr *internal_a)
{
  if (internal_a != (struct internal_aouthdr *) NULL)
    abfd->start_address = internal_a->entry;
  else
    abfd->start_address = 0;
}

static bfd_boolean
process_sections(bfd *abfd, unsigned int nscns, char *external_sections, unsigned int scnhsz)
{
  unsigned int i;
  
  if (nscns == 0)
    return TRUE;
    
  for (i = 0; i < nscns; i++)
    {
      struct internal_scnhdr tmp;
      bfd_coff_swap_scnhdr_in (abfd,
                               (void *) (external_sections + i * scnhsz),
                               (void *) & tmp);
      if (! make_a_section_from_file (abfd, &tmp, i + 1))
        return FALSE;
    }
  return TRUE;
}

static void
cleanup_on_failure(bfd *abfd, void *tdata)
{
  coff_object_cleanup (abfd);
  _bfd_coff_free_symbols (abfd);
  bfd_release (abfd, tdata);
}

static void
restore_original_state(bfd *abfd, flagword oflags, bfd_vma ostart)
{
  abfd->flags = oflags;
  abfd->start_address = ostart;
}

/* Turn a COFF file into a BFD, but fail with bfd_error_wrong_format if it is
   not a COFF file.  This is also used by ECOFF.  */

bfd_cleanup
coff_object_p (bfd *abfd)
{
  struct internal_filehdr internal_f;
  struct internal_aouthdr internal_a;
  
  if (!read_and_validate_file_header(abfd, &internal_f))
    return NULL;
  
  if (internal_f.f_opthdr && !read_optional_header(abfd, &internal_f, &internal_a))
    return NULL;
  
  return coff_real_object_p(abfd, internal_f.f_nscns, &internal_f,
                           internal_f.f_opthdr != 0 ? &internal_a : NULL);
}

static int read_and_validate_file_header(bfd *abfd, struct internal_filehdr *internal_f)
{
  bfd_size_type filhsz = bfd_coff_filhsz(abfd);
  void *filehdr = _bfd_alloc_and_read(abfd, filhsz, filhsz);
  
  if (filehdr == NULL)
    {
      if (bfd_get_error() != bfd_error_system_call)
        bfd_set_error(bfd_error_wrong_format);
      return 0;
    }
  
  bfd_coff_swap_filehdr_in(abfd, filehdr, internal_f);
  bfd_release(abfd, filehdr);
  
  if (!bfd_coff_bad_format_hook(abfd, internal_f) || 
      internal_f->f_opthdr > bfd_coff_aoutsz(abfd))
    {
      bfd_set_error(bfd_error_wrong_format);
      return 0;
    }
  
  return 1;
}

static int read_optional_header(bfd *abfd, struct internal_filehdr *internal_f, 
                                struct internal_aouthdr *internal_a)
{
  bfd_size_type aoutsz = bfd_coff_aoutsz(abfd);
  void *opthdr = _bfd_alloc_and_read(abfd, aoutsz, internal_f->f_opthdr);
  
  if (opthdr == NULL)
    return 0;
  
  if (internal_f->f_opthdr < aoutsz)
    memset(((char *)opthdr) + internal_f->f_opthdr, 0, 
           aoutsz - internal_f->f_opthdr);
  
  bfd_coff_swap_aouthdr_in(abfd, opthdr, (void *)internal_a);
  bfd_release(abfd, opthdr);
  
  return 1;
}

static hashval_t
htab_hash_section_target_index (const void * entry)
{
  const struct bfd_section * sec = entry;
  return sec->target_index;
}

static int
htab_eq_section_target_index (const void * e1, const void * e2)
{
  const struct bfd_section * sec1 = e1;
  const struct bfd_section * sec2 = e2;
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

  htab_t table = get_or_create_section_table(abfd);
  if (table == NULL)
    return bfd_und_section_ptr;

  if (htab_elements (table) == 0)
    populate_section_table(abfd, table);

  struct bfd_section *answer = find_section_in_table(table, section_index);
  if (answer != NULL)
    return answer;

  answer = find_and_add_new_section(abfd, table, section_index);
  if (answer != NULL)
    return answer;

  return bfd_und_section_ptr;
}

static htab_t
get_or_create_section_table(bfd *abfd)
{
  htab_t table = coff_data (abfd)->section_by_target_index;
  
  if (!table)
    {
      #define INITIAL_TABLE_SIZE 10
      table = htab_create (INITIAL_TABLE_SIZE, htab_hash_section_target_index,
                          htab_eq_section_target_index, NULL);
      if (table != NULL)
        coff_data (abfd)->section_by_target_index = table;
    }
  
  return table;
}

static void
populate_section_table(bfd *abfd, htab_t table)
{
  struct bfd_section *section;
  for (section = abfd->sections; section; section = section->next)
    {
      void **slot = htab_find_slot (table, section, INSERT);
      if (slot == NULL)
        return;
      *slot = section;
    }
}

static struct bfd_section *
find_section_in_table(htab_t table, int section_index)
{
  struct bfd_section needle;
  needle.target_index = section_index;
  return htab_find (table, &needle);
}

static struct bfd_section *
find_and_add_new_section(bfd *abfd, htab_t table, int section_index)
{
  struct bfd_section *section;
  for (section = abfd->sections; section; section = section->next)
    {
      if (section->target_index == section_index)
        {
          void **slot = htab_find_slot (table, section, INSERT);
          if (slot != NULL)
            *slot = section;
          return section;
        }
    }
  return NULL;
}

/* Get the upper bound of a COFF symbol table.  */

long
coff_get_symtab_upper_bound (bfd *abfd)
{
  if (!bfd_coff_slurp_symbol_table (abfd))
    return -1;

  return (bfd_get_symcount (abfd) + 1) * (sizeof (coff_symbol_type *));
}

/* Canonicalize a COFF symbol table.  */

long
coff_canonicalize_symtab (bfd *abfd, asymbol **alocation)
{
  coff_symbol_type *symbase;
  coff_symbol_type **location = (coff_symbol_type **) alocation;
  unsigned int symcount;
  unsigned int i;

  if (!bfd_coff_slurp_symbol_table (abfd))
    return -1;

  symbase = obj_symbols (abfd);
  symcount = bfd_get_symcount (abfd);
  
  for (i = 0; i < symcount; i++)
    location[i] = &symbase[i];

  location[symcount] = NULL;

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

  return _bfd_coff_get_string_from_table (abfd, sym->_n._n_n._n_offset);
}

static const char *
_bfd_coff_get_string_from_table (bfd *abfd, unsigned long offset)
{
  const char *strings;

  BFD_ASSERT (offset >= STRING_SIZE_SIZE);
  
  strings = _bfd_coff_get_strings (abfd);
  if (strings == NULL)
    return NULL;

  if (offset >= obj_coff_strings_len (abfd))
    return NULL;

  return strings + offset;
}

static const char *
_bfd_coff_get_strings (bfd *abfd)
{
  const char *strings = obj_coff_strings (abfd);
  
  if (strings == NULL)
    strings = _bfd_coff_read_string_table (abfd);
    
  return strings;
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
  bfd_size_type relsz;
  bfd_byte *free_external = NULL;
  struct internal_reloc *free_internal = NULL;
  bfd_byte *erel;
  bfd_byte *erel_end;
  struct internal_reloc *irel;
  bfd_size_type amt;

  if (sec->reloc_count == 0)
    return internal_relocs;

  if (coff_section_data (abfd, sec) != NULL
      && coff_section_data (abfd, sec)->relocs != NULL)
    return handle_existing_relocs(abfd, sec, require_internal, internal_relocs);

  relsz = bfd_coff_relsz (abfd);
  amt = sec->reloc_count * relsz;

  if (!allocate_external_relocs(&external_relocs, &free_external, amt))
    goto error_return;

  if (!read_external_relocs(abfd, sec, external_relocs, amt))
    goto error_return;

  if (!allocate_internal_relocs(&internal_relocs, &free_internal, sec->reloc_count))
    goto error_return;

  swap_relocs(abfd, external_relocs, internal_relocs, relsz, sec->reloc_count);

  free (free_external);
  free_external = NULL;

  if (cache && free_internal != NULL)
    {
      if (!cache_internal_relocs(abfd, sec, free_internal))
        goto error_return;
    }

  return internal_relocs;

 error_return:
  free (free_external);
  free (free_internal);
  return NULL;
}

static struct internal_reloc *
handle_existing_relocs(bfd *abfd, asection *sec, bool require_internal,
                      struct internal_reloc *internal_relocs)
{
  struct internal_reloc *existing_relocs = coff_section_data (abfd, sec)->relocs;
  
  if (!require_internal)
    return existing_relocs;
    
  memcpy (internal_relocs, existing_relocs,
          sec->reloc_count * sizeof (struct internal_reloc));
  return internal_relocs;
}

static bool
allocate_external_relocs(bfd_byte **external_relocs, bfd_byte **free_external,
                        bfd_size_type amt)
{
  if (*external_relocs != NULL)
    return true;
    
  *free_external = (bfd_byte *) bfd_malloc (amt);
  if (*free_external == NULL)
    return false;
    
  *external_relocs = *free_external;
  return true;
}

static bool
read_external_relocs(bfd *abfd, asection *sec, bfd_byte *external_relocs,
                    bfd_size_type amt)
{
  if (bfd_seek (abfd, sec->rel_filepos, SEEK_SET) != 0)
    return false;
    
  if (bfd_read (external_relocs, amt, abfd) != amt)
    return false;
    
  return true;
}

static bool
allocate_internal_relocs(struct internal_reloc **internal_relocs,
                        struct internal_reloc **free_internal,
                        bfd_size_type reloc_count)
{
  bfd_size_type amt;
  
  if (*internal_relocs != NULL)
    return true;
    
  amt = reloc_count * sizeof (struct internal_reloc);
  *free_internal = (struct internal_reloc *) bfd_malloc (amt);
  if (*free_internal == NULL)
    return false;
    
  *internal_relocs = *free_internal;
  return true;
}

static void
swap_relocs(bfd *abfd, bfd_byte *external_relocs,
           struct internal_reloc *internal_relocs,
           bfd_size_type relsz, bfd_size_type reloc_count)
{
  bfd_byte *erel = external_relocs;
  bfd_byte *erel_end = erel + relsz * reloc_count;
  struct internal_reloc *irel = internal_relocs;
  
  for (; erel < erel_end; erel += relsz, irel++)
    bfd_coff_swap_reloc_in (abfd, (void *) erel, (void *) irel);
}

static bool
cache_internal_relocs(bfd *abfd, asection *sec,
                     struct internal_reloc *free_internal)
{
  if (coff_section_data (abfd, sec) == NULL)
    {
      if (!allocate_section_data(abfd, sec))
        return false;
    }
  coff_section_data (abfd, sec)->relocs = free_internal;
  return true;
}

static bool
allocate_section_data(bfd *abfd, asection *sec)
{
  bfd_size_type amt = sizeof (struct coff_section_tdata);
  sec->used_by_bfd = bfd_zalloc (abfd, amt);
  if (sec->used_by_bfd == NULL)
    return false;
  coff_section_data (abfd, sec)->contents = NULL;
  return true;
}

/* Set lineno_count for the output sections of a COFF file.  */

int
coff_count_linenumbers (bfd *abfd)
{
  unsigned int limit = bfd_get_symcount (abfd);
  
  if (limit == 0)
    return coff_count_section_linenumbers(abfd);

  coff_assert_zero_lineno_counts(abfd);
  return coff_count_symbol_linenumbers(abfd, limit);
}

static int
coff_count_section_linenumbers (bfd *abfd)
{
  int total = 0;
  asection *s;
  
  for (s = abfd->sections; s != NULL; s = s->next)
    total += s->lineno_count;
  
  return total;
}

static void
coff_assert_zero_lineno_counts (bfd *abfd)
{
  asection *s;
  
  for (s = abfd->sections; s != NULL; s = s->next)
    BFD_ASSERT (s->lineno_count == 0);
}

static int
coff_count_symbol_linenumbers (bfd *abfd, unsigned int limit)
{
  unsigned int i;
  int total = 0;
  asymbol **p;
  
  for (p = abfd->outsymbols, i = 0; i < limit; i++, p++)
    total += coff_process_symbol_linenumbers(*p);
  
  return total;
}

static int
coff_process_symbol_linenumbers (asymbol *q_maybe)
{
  if (!coff_is_valid_symbol(q_maybe))
    return 0;
    
  coff_symbol_type *q = coffsymbol (q_maybe);
  
  if (!coff_has_valid_linenumbers(q))
    return 0;
  
  return coff_update_linenumber_counts(q);
}

static int
coff_is_valid_symbol (asymbol *q_maybe)
{
  return bfd_asymbol_bfd (q_maybe) != NULL
      && bfd_family_coff (bfd_asymbol_bfd (q_maybe));
}

static int
coff_has_valid_linenumbers (coff_symbol_type *q)
{
  return q->lineno != NULL
      && q->symbol.section->owner != NULL;
}

static int
coff_update_linenumber_counts (coff_symbol_type *q)
{
  alent *l = q->lineno;
  int total = 0;
  
  do
    {
      asection * sec = q->symbol.section->output_section;
      
      if (!bfd_is_const_section (sec))
        sec->lineno_count++;
      
      total++;
      l++;
    }
  while (l->line_number != 0);
  
  return total;
}

static void set_undefined_symbol(struct internal_syment *syment, bfd_vma value)
{
    syment->n_scnum = N_UNDEF;
    syment->n_value = value;
}

static void set_debugging_symbol_value(coff_symbol_type *coff_symbol_ptr, 
                                       struct internal_syment *syment)
{
    syment->n_value = coff_symbol_ptr->symbol.value;
}

static void set_section_symbol_value(bfd *abfd,
                                     coff_symbol_type *coff_symbol_ptr,
                                     struct internal_syment *syment)
{
    asection *section = coff_symbol_ptr->symbol.section;
    
    syment->n_scnum = section->output_section->target_index;
    syment->n_value = coff_symbol_ptr->symbol.value + section->output_offset;
    
    if (!obj_pe(abfd))
    {
        bfd_vma offset = (syment->n_sclass == C_STATLAB) 
                        ? section->output_section->lma 
                        : section->output_section->vma;
        syment->n_value += offset;
    }
}

static void set_absolute_symbol(coff_symbol_type *coff_symbol_ptr,
                                struct internal_syment *syment)
{
    BFD_ASSERT(0);
    syment->n_scnum = N_ABS;
    syment->n_value = coff_symbol_ptr->symbol.value;
}

static void fixup_symbol_value(bfd *abfd,
                               coff_symbol_type *coff_symbol_ptr,
                               struct internal_syment *syment)
{
    asection *section = coff_symbol_ptr->symbol.section;
    
    if (section && bfd_is_com_section(section))
    {
        set_undefined_symbol(syment, coff_symbol_ptr->symbol.value);
        return;
    }
    
    if ((coff_symbol_ptr->symbol.flags & BSF_DEBUGGING) != 0 &&
        (coff_symbol_ptr->symbol.flags & BSF_DEBUGGING_RELOC) == 0)
    {
        set_debugging_symbol_value(coff_symbol_ptr, syment);
        return;
    }
    
    if (bfd_is_und_section(section))
    {
        set_undefined_symbol(syment, 0);
        return;
    }
    
    if (section)
    {
        set_section_symbol_value(abfd, coff_symbol_ptr, syment);
    }
    else
    {
        set_absolute_symbol(coff_symbol_ptr, syment);
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
  asymbol **symbol_ptr_ptr = bfd_ptr->outsymbols;
  unsigned int native_index = 0;
  struct internal_syment *last_file = NULL;
  unsigned int symbol_index;

  if (!sort_symbols_for_coff(bfd_ptr, symbol_ptr_ptr, symbol_count, first_undef))
    return false;

  symbol_ptr_ptr = bfd_ptr->outsymbols;

  for (symbol_index = 0; symbol_index < symbol_count; symbol_index++)
    {
      process_symbol_at_index(bfd_ptr, symbol_ptr_ptr, symbol_index, 
                             &native_index, &last_file);
    }

  obj_conv_table_size (bfd_ptr) = native_index;

  return true;
}

static bool
sort_symbols_for_coff(bfd *bfd_ptr, asymbol **symbol_ptr_ptr, 
                      unsigned int symbol_count, int *first_undef)
{
  asymbol **newsyms;
  asymbol **current_pos;
  unsigned int i;
  bfd_size_type amt;

  amt = sizeof (asymbol *) * ((bfd_size_type) symbol_count + 1);
  newsyms = (asymbol **) bfd_alloc (bfd_ptr, amt);
  if (!newsyms)
    return false;

  bfd_ptr->outsymbols = newsyms;
  current_pos = newsyms;

  current_pos = add_primary_symbols(symbol_ptr_ptr, symbol_count, current_pos);
  current_pos = add_global_symbols(symbol_ptr_ptr, symbol_count, current_pos);
  
  *first_undef = current_pos - bfd_ptr->outsymbols;
  
  current_pos = add_undefined_symbols(symbol_ptr_ptr, symbol_count, current_pos);
  *current_pos = (asymbol *) NULL;

  return true;
}

static asymbol **
add_primary_symbols(asymbol **symbol_ptr_ptr, unsigned int symbol_count, 
                    asymbol **newsyms)
{
  unsigned int i;
  for (i = 0; i < symbol_count; i++)
    if (is_primary_symbol(symbol_ptr_ptr[i]))
      *newsyms++ = symbol_ptr_ptr[i];
  return newsyms;
}

static asymbol **
add_global_symbols(asymbol **symbol_ptr_ptr, unsigned int symbol_count,
                  asymbol **newsyms)
{
  unsigned int i;
  for (i = 0; i < symbol_count; i++)
    if (is_global_defined_symbol(symbol_ptr_ptr[i]))
      *newsyms++ = symbol_ptr_ptr[i];
  return newsyms;
}

static asymbol **
add_undefined_symbols(asymbol **symbol_ptr_ptr, unsigned int symbol_count,
                     asymbol **newsyms)
{
  unsigned int i;
  for (i = 0; i < symbol_count; i++)
    if (is_undefined_symbol(symbol_ptr_ptr[i]))
      *newsyms++ = symbol_ptr_ptr[i];
  return newsyms;
}

static bool
is_primary_symbol(asymbol *sym)
{
  return (sym->flags & BSF_NOT_AT_END) != 0
      || (!bfd_is_und_section (sym->section)
          && !bfd_is_com_section (sym->section)
          && ((sym->flags & BSF_FUNCTION) != 0
              || ((sym->flags & (BSF_GLOBAL | BSF_WEAK)) == 0)));
}

static bool
is_global_defined_symbol(asymbol *sym)
{
  return (sym->flags & BSF_NOT_AT_END) == 0
      && !bfd_is_und_section (sym->section)
      && (bfd_is_com_section (sym->section)
          || ((sym->flags & BSF_FUNCTION) == 0
              && ((sym->flags & (BSF_GLOBAL | BSF_WEAK)) != 0)));
}

static bool
is_undefined_symbol(asymbol *sym)
{
  return (sym->flags & BSF_NOT_AT_END) == 0
      && bfd_is_und_section (sym->section);
}

static void
process_symbol_at_index(bfd *bfd_ptr, asymbol **symbol_ptr_ptr,
                       unsigned int symbol_index, unsigned int *native_index,
                       struct internal_syment **last_file)
{
  coff_symbol_type *coff_symbol_ptr;

  coff_symbol_ptr = coff_symbol_from (symbol_ptr_ptr[symbol_index]);
  symbol_ptr_ptr[symbol_index]->udata.i = symbol_index;
  
  if (coff_symbol_ptr && coff_symbol_ptr->native)
    {
      process_native_symbol(bfd_ptr, coff_symbol_ptr, native_index, last_file);
    }
  else
    {
      (*native_index)++;
    }
}

static void
process_native_symbol(bfd *bfd_ptr, coff_symbol_type *coff_symbol_ptr,
                     unsigned int *native_index, struct internal_syment **last_file)
{
  combined_entry_type *s = coff_symbol_ptr->native;
  int i;

  BFD_ASSERT (s->is_sym);
  
  if (s->u.syment.n_sclass == C_FILE)
    {
      update_file_symbol(last_file, &(s->u.syment), *native_index);
    }
  else
    {
      fixup_symbol_value (bfd_ptr, coff_symbol_ptr, &(s->u.syment));
    }

  for (i = 0; i < s->u.syment.n_numaux + 1; i++)
    s[i].offset = (*native_index)++;
}

static void
update_file_symbol(struct internal_syment **last_file, 
                  struct internal_syment *current_file,
                  unsigned int native_index)
{
  if (*last_file != NULL)
    (*last_file)->n_value = native_index;
  *last_file = current_file;
}

/* Run thorough the symbol table again, and fix it so that all
   pointers to entries are changed to the entries' index in the output
   symbol table.  */

void
coff_mangle_symbols (bfd *bfd_ptr)
{
  unsigned int symbol_count = bfd_get_symcount (bfd_ptr);
  asymbol **symbol_ptr_ptr = bfd_ptr->outsymbols;
  unsigned int symbol_index;

  for (symbol_index = 0; symbol_index < symbol_count; symbol_index++)
    {
      process_symbol(bfd_ptr, symbol_ptr_ptr[symbol_index]);
    }
}

static void
process_symbol(bfd *bfd_ptr, asymbol *symbol)
{
  coff_symbol_type *coff_symbol_ptr = coff_symbol_from(symbol);
  
  if (!coff_symbol_ptr || !coff_symbol_ptr->native)
    return;
    
  combined_entry_type *s = coff_symbol_ptr->native;
  BFD_ASSERT(s->is_sym);
  
  fix_symbol_value(bfd_ptr, coff_symbol_ptr, s);
  process_auxiliary_entries(s);
}

static void
fix_symbol_value(bfd *bfd_ptr, coff_symbol_type *coff_symbol_ptr, combined_entry_type *s)
{
  if (s->fix_value)
    {
      s->u.syment.n_value =
        (uintptr_t) ((combined_entry_type *)
                     (uintptr_t) s->u.syment.n_value)->offset;
      s->fix_value = 0;
    }
    
  if (s->fix_line)
    {
      s->u.syment.n_value =
        (coff_symbol_ptr->symbol.section->output_section->line_filepos
         + s->u.syment.n_value * bfd_coff_linesz (bfd_ptr));
      coff_symbol_ptr->symbol.section =
        coff_section_from_bfd_index (bfd_ptr, N_DEBUG);
      BFD_ASSERT (coff_symbol_ptr->symbol.flags & BSF_DEBUGGING);
    }
}

static void
process_auxiliary_entries(combined_entry_type *s)
{
  int i;
  
  for (i = 0; i < s->u.syment.n_numaux; i++)
    {
      combined_entry_type *a = s + i + 1;
      BFD_ASSERT(!a->is_sym);
      fix_auxiliary_entry(a);
    }
}

static void
fix_auxiliary_entry(combined_entry_type *a)
{
  if (a->fix_tag)
    {
      a->u.auxent.x_sym.x_tagndx.u32 =
        a->u.auxent.x_sym.x_tagndx.p->offset;
      a->fix_tag = 0;
    }
    
  if (a->fix_end)
    {
      a->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32 =
        a->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p->offset;
      a->fix_end = 0;
    }
    
  if (a->fix_scnlen)
    {
      a->u.auxent.x_csect.x_scnlen.u64 =
        a->u.auxent.x_csect.x_scnlen.p->offset;
      a->fix_scnlen = 0;
    }
}

static bool
add_string_to_strtab(struct bfd_strtab_hash *strtab,
                     const char *str,
                     union internal_auxent *auxent,
                     bool hash)
{
    bfd_size_type indx = _bfd_stringtab_add(strtab, str, hash, false);
    if (indx == (bfd_size_type) -1)
        return false;
    
    auxent->x_file.x_n.x_n.x_offset = STRING_SIZE_SIZE + indx;
    auxent->x_file.x_n.x_n.x_zeroes = 0;
    return true;
}

static void
copy_filename_to_auxent(union internal_auxent *auxent,
                        const char *str,
                        unsigned int filnmlen)
{
    strncpy(auxent->x_file.x_n.x_fname, str, filnmlen);
}

static bool
handle_long_filename(union internal_auxent *auxent,
                     const char *str,
                     unsigned int str_length,
                     unsigned int filnmlen,
                     struct bfd_strtab_hash *strtab,
                     bool hash)
{
    if (str_length <= filnmlen) {
        copy_filename_to_auxent(auxent, str, filnmlen);
        return true;
    }
    
    return add_string_to_strtab(strtab, str, auxent, hash);
}

static void
handle_short_filename(union internal_auxent *auxent,
                     char *str,
                     unsigned int str_length,
                     unsigned int filnmlen)
{
    copy_filename_to_auxent(auxent, str, filnmlen);
    if (str_length > filnmlen)
        str[filnmlen] = '\0';
}

static bool
coff_write_auxent_fname(bfd *abfd,
                       char *str,
                       union internal_auxent *auxent,
                       struct bfd_strtab_hash *strtab,
                       bool hash)
{
    unsigned int str_length = strlen(str);
    unsigned int filnmlen = bfd_coff_filnmlen(abfd);
    
    if (bfd_coff_long_filenames(abfd))
        return handle_long_filename(auxent, str, str_length, filnmlen, strtab, hash);
    
    handle_short_filename(auxent, str, str_length, filnmlen);
    return true;
}

static bool
ensure_symbol_name(asymbol *symbol)
{
  if (symbol->name == NULL)
    symbol->name = "strange";
  return true;
}

static bool
add_string_to_strtab(struct bfd_strtab_hash *strtab, const char *str, 
                     bool hash, combined_entry_type *native)
{
  bfd_size_type indx = _bfd_stringtab_add(strtab, str, hash, false);
  if (indx == (bfd_size_type) -1)
    return false;
  
  native->u.syment._n._n_n._n_offset = STRING_SIZE_SIZE + indx;
  native->u.syment._n._n_n._n_zeroes = 0;
  return true;
}

static bool
handle_file_symbol(bfd *abfd, const char *name, combined_entry_type *native,
                  struct bfd_strtab_hash *strtab, bool hash)
{
  if (bfd_coff_force_symnames_in_strings(abfd))
  {
    if (!add_string_to_strtab(strtab, ".file", hash, native))
      return false;
  }
  else
  {
    strncpy(native->u.syment._n._n_name, ".file", SYMNMLEN);
  }
  
  BFD_ASSERT(!(native + 1)->is_sym);
  return coff_write_auxent_fname(abfd, name, &(native + 1)->u.auxent, strtab, hash);
}

static bool
write_debug_string_prefix(bfd *abfd, int prefix_len, unsigned int name_length, bfd_byte *buf)
{
  if (prefix_len == 4)
    bfd_put_32(abfd, (bfd_vma)(name_length + 1), buf);
  else
    bfd_put_16(abfd, (bfd_vma)(name_length + 1), buf);
  return true;
}

static bool
write_to_debug_section(bfd *abfd, asection *debug_section, void *data,
                      file_ptr offset, bfd_size_type size)
{
  return bfd_set_section_contents(abfd, debug_section, data, offset, size);
}

static bool
handle_debug_section_name(bfd *abfd, asymbol *symbol, combined_entry_type *native,
                         asection **debug_string_section_p, bfd_size_type *debug_string_size_p)
{
  unsigned int name_length = strlen(symbol->name);
  int prefix_len = bfd_coff_debug_string_prefix_length(abfd);
  bfd_byte buf[4];
  file_ptr filepos;
  
  if (*debug_string_section_p == NULL)
    *debug_string_section_p = bfd_get_section_by_name(abfd, ".debug");
  
  filepos = bfd_tell(abfd);
  write_debug_string_prefix(abfd, prefix_len, name_length, buf);
  
  if (!write_to_debug_section(abfd, *debug_string_section_p, buf,
                              *debug_string_size_p, prefix_len))
    abort();
  
  if (!write_to_debug_section(abfd, *debug_string_section_p, (void *)symbol->name,
                              *debug_string_size_p + prefix_len, name_length + 1))
    abort();
  
  if (bfd_seek(abfd, filepos, SEEK_SET) != 0)
    abort();
  
  native->u.syment._n._n_n._n_offset = *debug_string_size_p + prefix_len;
  native->u.syment._n._n_n._n_zeroes = 0;
  *debug_string_size_p += name_length + 1 + prefix_len;
  
  return true;
}

static bool
handle_regular_symbol(bfd *abfd, asymbol *symbol, combined_entry_type *native,
                     struct bfd_strtab_hash *strtab, bool hash,
                     asection **debug_string_section_p, bfd_size_type *debug_string_size_p)
{
  unsigned int name_length = strlen(symbol->name);
  
  if (name_length <= SYMNMLEN && !bfd_coff_force_symnames_in_strings(abfd))
  {
    strncpy(native->u.syment._n._n_name, symbol->name, SYMNMLEN);
    return true;
  }
  
  if (!bfd_coff_symname_in_debug(abfd, &native->u.syment))
  {
    return add_string_to_strtab(strtab, symbol->name, hash, native);
  }
  
  return handle_debug_section_name(abfd, symbol, native, 
                                   debug_string_section_p, debug_string_size_p);
}

static bool
coff_fix_symbol_name(bfd *abfd, asymbol *symbol, combined_entry_type *native,
                    struct bfd_strtab_hash *strtab, bool hash,
                    asection **debug_string_section_p, bfd_size_type *debug_string_size_p)
{
  ensure_symbol_name(symbol);
  BFD_ASSERT(native->is_sym);
  
  if (native->u.syment.n_sclass == C_FILE && native->u.syment.n_numaux > 0)
  {
    return handle_file_symbol(abfd, symbol->name, native, strtab, hash);
  }
  
  return handle_regular_symbol(abfd, symbol, native, strtab, hash,
                               debug_string_section_p, debug_string_size_p);
}

/* We need to keep track of the symbol index so that when we write out
   the relocs we can get the index for a symbol.  This method is a
   hack.  FIXME.  */

#define set_index(symbol, idx)	((symbol)->udata.i = (idx))

/* Write a symbol out to a COFF file.  */

static bool
write_symbol_data(bfd *abfd, combined_entry_type *native, void *buf, bfd_size_type symesz)
{
  bfd_coff_swap_sym_out(abfd, &native->u.syment, buf);
  if (bfd_write(buf, symesz, abfd) != symesz)
    return false;
  return true;
}

static bool
write_aux_entry(bfd *abfd, combined_entry_type *native, int j, int type, int n_sclass,
                void *buf, bfd_size_type auxesz, struct bfd_strtab_hash *strtab, bool hash)
{
  combined_entry_type *aux_entry = native + j + 1;
  
  BFD_ASSERT(!aux_entry->is_sym);
  
  if (native->u.syment.n_sclass == C_FILE &&
      aux_entry->u.auxent.x_file.x_ftype &&
      aux_entry->extrap)
  {
    coff_write_auxent_fname(abfd, (char *)aux_entry->extrap,
                           &aux_entry->u.auxent, strtab, hash);
  }
  
  bfd_coff_swap_aux_out(abfd, &aux_entry->u.auxent, type, n_sclass,
                       j, native->u.syment.n_numaux, buf);
  
  if (bfd_write(buf, auxesz, abfd) != auxesz)
    return false;
    
  return true;
}

static bool
write_auxiliary_entries(bfd *abfd, combined_entry_type *native, int type, int n_sclass,
                       struct bfd_strtab_hash *strtab, bool hash)
{
  if (native->u.syment.n_numaux == 0)
    return true;
    
  bfd_size_type auxesz = bfd_coff_auxesz(abfd);
  void *buf = bfd_alloc(abfd, auxesz);
  if (!buf)
    return false;
    
  for (unsigned int j = 0; j < native->u.syment.n_numaux; j++)
  {
    if (!write_aux_entry(abfd, native, j, type, n_sclass, buf, auxesz, strtab, hash))
      return false;
  }
  
  bfd_release(abfd, buf);
  return true;
}

static void
set_section_number(asymbol *symbol, combined_entry_type *native)
{
  if (native->u.syment.n_sclass == C_FILE)
    symbol->flags |= BSF_DEBUGGING;
    
  if (symbol->flags & BSF_DEBUGGING && bfd_is_abs_section(symbol->section))
    native->u.syment.n_scnum = N_DEBUG;
  else if (bfd_is_abs_section(symbol->section))
    native->u.syment.n_scnum = N_ABS;
  else if (bfd_is_und_section(symbol->section))
    native->u.syment.n_scnum = N_UNDEF;
  else
  {
    asection *output_section = symbol->section->output_section
                                ? symbol->section->output_section
                                : symbol->section;
    native->u.syment.n_scnum = output_section->target_index;
  }
}

static bool
coff_write_symbol(bfd *abfd,
                 asymbol *symbol,
                 combined_entry_type *native,
                 bfd_vma *written,
                 struct bfd_strtab_hash *strtab,
                 bool hash,
                 asection **debug_string_section_p,
                 bfd_size_type *debug_string_size_p)
{
  BFD_ASSERT(native->is_sym);
  
  set_section_number(symbol, native);
  
  if (!coff_fix_symbol_name(abfd, symbol, native, strtab, hash,
                           debug_string_section_p, debug_string_size_p))
    return false;
    
  bfd_size_type symesz = bfd_coff_symesz(abfd);
  void *buf = bfd_alloc(abfd, symesz);
  if (!buf)
    return false;
    
  if (!write_symbol_data(abfd, native, buf, symesz))
    return false;
    
  bfd_release(abfd, buf);
  
  if (!write_auxiliary_entries(abfd, native, native->u.syment.n_type,
                               native->u.syment.n_sclass, strtab, hash))
    return false;
    
  set_index(symbol, *written);
  *written += native->u.syment.n_numaux + 1;
  
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
  combined_entry_type *native;
  combined_entry_type dummy[2];
  asection *output_section = symbol->section->output_section
			       ? symbol->section->output_section
			       : symbol->section;
  struct bfd_link_info *link_info = coff_data (abfd)->link_info;
  bool ret;

  if (should_skip_discarded_symbol(link_info, symbol))
    {
      clear_symbol_data(symbol, isym);
      return true;
    }

  native = initialize_native_entry(dummy);

  if (should_skip_debugging_symbol(symbol))
    {
      clear_symbol_data(symbol, isym);
      return true;
    }

  set_native_section_info(native, symbol, output_section, abfd);
  set_native_storage_class(native, symbol, abfd);

  ret = coff_write_symbol (abfd, symbol, native, written, strtab, hash,
			   debug_string_section_p, debug_string_size_p);
  if (isym != NULL)
    *isym = native->u.syment;
  return ret;
}

static bool
should_skip_discarded_symbol(struct bfd_link_info *link_info, asymbol *symbol)
{
  return ((!link_info || link_info->strip_discarded)
          && !bfd_is_abs_section (symbol->section)
          && symbol->section->output_section == bfd_abs_section_ptr);
}

static void
clear_symbol_data(asymbol *symbol, struct internal_syment *isym)
{
  symbol->name = "";
  if (isym != NULL)
    memset (isym, 0, sizeof (*isym));
}

static combined_entry_type *
initialize_native_entry(combined_entry_type *dummy)
{
  memset (dummy, 0, sizeof (combined_entry_type) * 2);
  dummy->is_sym = true;
  dummy[1].is_sym = false;
  dummy->u.syment.n_type = T_NULL;
  dummy->u.syment.n_flags = 0;
  dummy->u.syment.n_numaux = 0;
  return dummy;
}

static bool
should_skip_debugging_symbol(asymbol *symbol)
{
  return (symbol->flags & BSF_DEBUGGING) != 0;
}

static void
set_native_section_info(combined_entry_type *native, asymbol *symbol,
                        asection *output_section, bfd *abfd)
{
  if (bfd_is_und_section (symbol->section))
    {
      native->u.syment.n_scnum = N_UNDEF;
      native->u.syment.n_value = symbol->value;
    }
  else if (bfd_is_com_section (symbol->section))
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
      set_regular_section_info(native, symbol, output_section, abfd);
    }
}

static void
set_regular_section_info(combined_entry_type *native, asymbol *symbol,
                         asection *output_section, bfd *abfd)
{
  native->u.syment.n_scnum = output_section->target_index;
  native->u.syment.n_value = (symbol->value
                              + symbol->section->output_offset);
  if (! obj_pe (abfd))
    native->u.syment.n_value += output_section->vma;

  copy_file_header_flags(native, symbol);
  set_function_size_info(native, symbol);
}

static void
copy_file_header_flags(combined_entry_type *native, asymbol *symbol)
{
  coff_symbol_type *c = coff_symbol_from (symbol);
  if (c != (coff_symbol_type *) NULL)
    native->u.syment.n_flags = bfd_asymbol_bfd (&c->symbol)->flags;
}

static void
set_function_size_info(combined_entry_type *native, asymbol *symbol)
{
  const elf_symbol_type *elfsym = elf_symbol_from (symbol);
  if (elfsym
      && (symbol->flags & BSF_FUNCTION)
      && elfsym->internal_elf_sym.st_size)
    {
      native->u.syment.n_type = DT_FCN << 4;
      native->u.syment.n_numaux = 1;
      native[1].u.auxent.x_sym.x_misc.x_fsize
        = elfsym->internal_elf_sym.st_size;
    }
}

static void
set_native_storage_class(combined_entry_type *native, asymbol *symbol, bfd *abfd)
{
  if (symbol->flags & BSF_FILE)
    native->u.syment.n_sclass = C_FILE;
  else if (symbol->flags & BSF_LOCAL)
    native->u.syment.n_sclass = C_STAT;
  else if (symbol->flags & BSF_WEAK)
    native->u.syment.n_sclass = obj_pe (abfd) ? C_NT_WEAK : C_WEAKEXT;
  else
    native->u.syment.n_sclass = C_EXT;
}

/* Write a native symbol to a COFF file.  */

static bool
should_discard_symbol (bfd *abfd, coff_symbol_type *symbol)
{
  struct bfd_link_info *link_info = coff_data (abfd)->link_info;
  
  if (!link_info && !link_info->strip_discarded)
    return false;
    
  if (bfd_is_abs_section (symbol->symbol.section))
    return false;
    
  return symbol->symbol.section->output_section == bfd_abs_section_ptr;
}

static void
update_auxent_line_pointer (combined_entry_type *native, asection *output_section)
{
  if (!native->u.syment.n_numaux)
    return;
    
  union internal_auxent *a = &((native + 1)->u.auxent);
  a->x_sym.x_fcnary.x_fcn.x_lnnoptr = output_section->moving_line_filepos;
}

static unsigned int
process_line_numbers (alent *lineno, bfd_vma written, asection *section)
{
  unsigned int count = 0;
  
  lineno[count].u.offset = written;
  count++;
  
  while (lineno[count].line_number != 0)
    {
      lineno[count].u.offset += 
        (section->output_section->vma + section->output_offset);
      count++;
    }
  
  return count;
}

static void
update_moving_line_filepos (asection *output_section, unsigned int count, bfd *abfd)
{
  if (bfd_is_const_section (output_section))
    return;
    
  output_section->moving_line_filepos += count * bfd_coff_linesz (abfd);
}

static bool
process_symbol_line_numbers (bfd *abfd, coff_symbol_type *symbol, 
                            bfd_vma *written, combined_entry_type *native)
{
  alent *lineno = symbol->lineno;
  
  if (!lineno || symbol->done_lineno || symbol->symbol.section->owner == NULL)
    return true;
    
  unsigned int count = process_line_numbers (lineno, *written, symbol->symbol.section);
  
  update_auxent_line_pointer (native, symbol->symbol.section->output_section);
  
  symbol->done_lineno = true;
  
  update_moving_line_filepos (symbol->symbol.section->output_section, count, abfd);
  
  return true;
}

static bool
coff_write_native_symbol (bfd *abfd,
                         coff_symbol_type *symbol,
                         bfd_vma *written,
                         struct bfd_strtab_hash *strtab,
                         asection **debug_string_section_p,
                         bfd_size_type *debug_string_size_p)
{
  combined_entry_type *native = symbol->native;
  
  if (should_discard_symbol (abfd, symbol))
    {
      symbol->symbol.name = "";
      return true;
    }
  
  BFD_ASSERT (native->is_sym);
  
  process_symbol_line_numbers (abfd, symbol, written, native);
  
  return coff_write_symbol (abfd, &(symbol->symbol), native, written,
                           strtab, true, debug_string_section_p,
                           debug_string_size_p);
}

static void
null_error_handler (const char *fmt ATTRIBUTE_UNUSED,
		    va_list ap ATTRIBUTE_UNUSED)
{
}

/* Write out the COFF symbols.  */

bool
coff_write_symbols (bfd *abfd)
{
  struct bfd_strtab_hash *strtab;
  asection *debug_string_section;
  bfd_size_type debug_string_size;
  unsigned int i;
  unsigned int limit = bfd_get_symcount (abfd);
  bfd_vma written = 0;
  asymbol **p;

  debug_string_section = NULL;
  debug_string_size = 0;

  strtab = _bfd_stringtab_init ();
  if (strtab == NULL)
    return false;

  if (!add_long_section_names_to_strtab (abfd, strtab))
    return false;

  if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
    return false;

  written = 0;
  for (p = abfd->outsymbols, i = 0; i < limit; i++, p++)
    {
      if (!write_single_symbol (abfd, *p, &written, strtab, 
                                &debug_string_section, &debug_string_size))
        return false;
    }

  obj_raw_syment_count (abfd) = written;

  if (!write_string_table (abfd, strtab))
    {
      _bfd_stringtab_free (strtab);
      return false;
    }

  _bfd_stringtab_free (strtab);

  verify_debug_section_size (debug_string_size, debug_string_section);

  return true;
}

static bool
add_long_section_names_to_strtab (bfd *abfd, struct bfd_strtab_hash *strtab)
{
  asection *o;

  if (!bfd_coff_long_section_names (abfd))
    return true;

  for (o = abfd->sections; o != NULL; o = o->next)
    {
      if (strlen (o->name) > SCNNMLEN)
        {
          if (_bfd_stringtab_add (strtab, o->name, false, false) == (bfd_size_type) -1)
            return false;
        }
    }
  return true;
}

static bool
write_single_symbol (bfd *abfd, asymbol *symbol, bfd_vma *written,
                     struct bfd_strtab_hash *strtab, 
                     asection **debug_string_section,
                     bfd_size_type *debug_string_size)
{
  coff_symbol_type *c_symbol = coff_symbol_from (symbol);

  if (c_symbol == NULL || c_symbol->native == NULL)
    {
      return coff_write_alien_symbol (abfd, symbol, NULL, written,
                                      strtab, true, debug_string_section,
                                      debug_string_size);
    }

  update_symbol_class_if_needed (abfd, symbol, c_symbol);

  return coff_write_native_symbol (abfd, c_symbol, written,
                                   strtab, debug_string_section,
                                   debug_string_size);
}

static void
update_symbol_class_if_needed (bfd *abfd, asymbol *symbol, 
                               coff_symbol_type *c_symbol)
{
  enum coff_symbol_classification sym_class;
  unsigned char *n_sclass;

  if (coff_backend_info (abfd)->_bfd_coff_classify_symbol == NULL)
    return;

  sym_class = get_symbol_classification (abfd, c_symbol);
  n_sclass = &c_symbol->native->u.syment.n_sclass;

  if (symbol->flags & BSF_WEAK)
    {
      *n_sclass = obj_pe (abfd) ? C_NT_WEAK : C_WEAKEXT;
    }
  else if (symbol->flags & BSF_LOCAL && sym_class != COFF_SYMBOL_LOCAL)
    {
      *n_sclass = C_STAT;
    }
  else if (should_set_global_class (symbol, sym_class, *n_sclass))
    {
      *n_sclass = C_EXT;
    }
}

static enum coff_symbol_classification
get_symbol_classification (bfd *abfd, coff_symbol_type *c_symbol)
{
  bfd_error_handler_type current_error_handler;
  enum coff_symbol_classification sym_class;

  current_error_handler = bfd_set_error_handler (null_error_handler);
  BFD_ASSERT (c_symbol->native->is_sym);
  sym_class = bfd_coff_classify_symbol (abfd, &c_symbol->native->u.syment);
  bfd_set_error_handler (current_error_handler);

  return sym_class;
}

static bool
should_set_global_class (asymbol *symbol, 
                         enum coff_symbol_classification sym_class,
                         unsigned char n_sclass)
{
  if (!(symbol->flags & BSF_GLOBAL))
    return false;

  if (sym_class != COFF_SYMBOL_GLOBAL)
    return true;

#ifdef COFF_WITH_PE
  if (n_sclass == C_NT_WEAK)
    return true;
#endif

  return n_sclass == C_WEAKEXT;
}

static bool
write_string_table (bfd *abfd, struct bfd_strtab_hash *strtab)
{
  bfd_byte buffer[STRING_SIZE_SIZE];

#if STRING_SIZE_SIZE == 4
  H_PUT_32 (abfd, _bfd_stringtab_size (strtab) + STRING_SIZE_SIZE, buffer);
#else
 #error Change H_PUT_32
#endif

  if (bfd_write (buffer, sizeof (buffer), abfd) != sizeof (buffer))
    return false;

  return _bfd_stringtab_emit (abfd, strtab);
}

static void
verify_debug_section_size (bfd_size_type debug_string_size, 
                          asection *debug_string_section)
{
  BFD_ASSERT (debug_string_size == 0
              || (debug_string_section != NULL
                  && (BFD_ALIGN (debug_string_size,
                                1 << debug_string_section->alignment_power)
                      == debug_string_section->size)));
}

bool
coff_write_linenumbers (bfd *abfd)
{
  asection *s;
  bfd_size_type linesz;
  void * buff;

  linesz = bfd_coff_linesz (abfd);
  buff = bfd_alloc (abfd, linesz);
  if (!buff)
    return false;
    
  for (s = abfd->sections; s != (asection *) NULL; s = s->next)
    {
      if (!s->lineno_count)
        continue;
        
      if (!write_section_linenumbers(abfd, s, buff, linesz))
        {
          bfd_release (abfd, buff);
          return false;
        }
    }
    
  bfd_release (abfd, buff);
  return true;
}

static bool
write_section_linenumbers (bfd *abfd, asection *s, void *buff, bfd_size_type linesz)
{
  asymbol **q = abfd->outsymbols;
  
  if (bfd_seek (abfd, s->line_filepos, SEEK_SET) != 0)
    return false;
    
  while (*q)
    {
      if (!process_symbol_linenumbers(abfd, *q, s, buff, linesz))
        return false;
      q++;
    }
    
  return true;
}

static bool
process_symbol_linenumbers (bfd *abfd, asymbol *p, asection *s, void *buff, bfd_size_type linesz)
{
  if (p->section->output_section != s)
    return true;
    
  alent *l = BFD_SEND (bfd_asymbol_bfd (p), _get_lineno,
                       (bfd_asymbol_bfd (p), p));
  if (!l)
    return true;
    
  return write_lineno_entries(abfd, l, buff, linesz);
}

static bool
write_lineno_entries (bfd *abfd, alent *l, void *buff, bfd_size_type linesz)
{
  struct internal_lineno out;
  
  memset ((void *) & out, 0, sizeof (out));
  out.l_lnno = 0;
  out.l_addr.l_symndx = l->u.offset;
  
  if (!write_single_lineno(abfd, &out, buff, linesz))
    return false;
    
  l++;
  
  while (l->line_number)
    {
      out.l_lnno = l->line_number;
      out.l_addr.l_symndx = l->u.offset;
      
      if (!write_single_lineno(abfd, &out, buff, linesz))
        return false;
        
      l++;
    }
    
  return true;
}

static bool
write_single_lineno (bfd *abfd, struct internal_lineno *out, void *buff, bfd_size_type linesz)
{
  bfd_coff_swap_lineno_out (abfd, out, buff);
  return bfd_write (buff, linesz, abfd) == linesz;
}

static alent *
coff_get_lineno (bfd *ignore_abfd ATTRIBUTE_UNUSED, asymbol *symbol)
{
  return coffsymbol (symbol)->lineno;
}

/* This function transforms the offsets into the symbol table into
   pointers to syments.  */

static int should_skip_pointerization(unsigned int n_sclass, unsigned int type)
{
    return (n_sclass == C_STAT && type == T_NULL) ||
           n_sclass == C_FILE ||
           n_sclass == C_DWARF;
}

static int needs_function_end_fixup(unsigned int type, unsigned int n_sclass)
{
    return ISFCN(type) || ISTAG(n_sclass) || 
           n_sclass == C_BLOCK || n_sclass == C_FCN;
}

static void fixup_function_end_index(combined_entry_type *auxent,
                                     combined_entry_type *table_base,
                                     unsigned int raw_syment_count)
{
    unsigned int endndx = auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32;
    
    if (endndx > 0 && endndx < raw_syment_count)
    {
        auxent->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p = table_base + endndx;
        auxent->fix_end = 1;
    }
}

static void fixup_tag_index(combined_entry_type *auxent,
                            combined_entry_type *table_base,
                            unsigned int raw_syment_count)
{
    unsigned int tagndx = auxent->u.auxent.x_sym.x_tagndx.u32;
    
    if (tagndx < raw_syment_count)
    {
        auxent->u.auxent.x_sym.x_tagndx.p = table_base + tagndx;
        auxent->fix_tag = 1;
    }
}

static void
coff_pointerize_aux (bfd *abfd,
		     combined_entry_type *table_base,
		     combined_entry_type *symbol,
		     unsigned int indaux,
		     combined_entry_type *auxent)
{
  unsigned int type = symbol->u.syment.n_type;
  unsigned int n_sclass = symbol->u.syment.n_sclass;
  unsigned int raw_syment_count = obj_raw_syment_count(abfd);

  BFD_ASSERT (symbol->is_sym);
  
  if (coff_backend_info (abfd)->_bfd_coff_pointerize_aux_hook)
    {
      if ((*coff_backend_info (abfd)->_bfd_coff_pointerize_aux_hook)
	  (abfd, table_base, symbol, indaux, auxent))
	return;
    }

  if (should_skip_pointerization(n_sclass, type))
    return;

  BFD_ASSERT (! auxent->is_sym);

#define N_TMASK coff_data  (abfd)->local_n_tmask
#define N_BTSHFT coff_data (abfd)->local_n_btshft

  if (needs_function_end_fixup(type, n_sclass))
    {
      fixup_function_end_index(auxent, table_base, raw_syment_count);
    }

  fixup_tag_index(auxent, table_base, raw_syment_count);
}

/* Allocate space for the ".debug" section, and read it.
   We did not read the debug section until now, because
   we didn't want to go to the trouble until someone needed it.  */

static char *
build_debug_section (bfd *abfd, asection ** sect_return)
{
  asection *sect = bfd_get_section_by_name (abfd, ".debug");

  if (!sect)
    {
      bfd_set_error (bfd_error_no_debug_section);
      return NULL;
    }

  file_ptr position = bfd_tell (abfd);
  if (bfd_seek (abfd, sect->filepos, SEEK_SET) != 0)
    return NULL;

  bfd_size_type sec_size = sect->size;
  char *debug_section = (char *) _bfd_alloc_and_read (abfd, sec_size + 1, sec_size);
  if (debug_section == NULL)
    return NULL;
  
  debug_section[sec_size] = 0;

  if (bfd_seek (abfd, position, SEEK_SET) != 0)
    return NULL;

  *sect_return = sect;
  return debug_section;
}

/* Return a pointer to a malloc'd copy of 'name'.  'name' may not be
   \0-terminated, but will not exceed 'maxlen' characters.  The copy *will*
   be \0-terminated.  */

static char *
copy_name (bfd *abfd, char *name, size_t maxlen)
{
  size_t len = strnlen(name, maxlen);
  char *newname = (char *) bfd_alloc (abfd, (bfd_size_type) len + 1);
  
  if (newname == NULL)
    return NULL;

  strncpy (newname, name, len);
  newname[len] = '\0';
  return newname;
}

/* Read in the external symbols.  */

bool
_bfd_coff_get_external_symbols (bfd *abfd)
{
  size_t symesz;
  size_t size;
  void * syms;
  ufile_ptr filesize;

  if (obj_coff_external_syms (abfd) != NULL)
    return true;

  symesz = bfd_coff_symesz (abfd);
  if (_bfd_mul_overflow (obj_raw_syment_count (abfd), symesz, &size))
    {
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  if (size == 0)
    return true;

  if (!validate_file_position (abfd, size))
    {
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
    return false;
  
  syms = _bfd_malloc_and_read (abfd, size, size);
  obj_coff_external_syms (abfd) = syms;
  return syms != NULL;
}

static bool
validate_file_position (bfd *abfd, size_t size)
{
  ufile_ptr filesize = bfd_get_file_size (abfd);
  
  if (filesize == 0)
    return true;
    
  if ((ufile_ptr) obj_sym_filepos (abfd) > filesize)
    return false;
    
  if (size > filesize - obj_sym_filepos (abfd))
    return false;
    
  return true;
}

/* Read in the external strings.  The strings are not loaded until
   they are needed.  This is because we have no simple way of
   detecting a missing string table in an archive.  If the strings
   are loaded then the STRINGS and STRINGS_LEN fields in the
   coff_tdata structure will be set.  */

const char *
_bfd_coff_read_string_table (bfd *abfd)
{
  if (obj_coff_strings (abfd) != NULL)
    return obj_coff_strings (abfd);

  if (obj_sym_filepos (abfd) == 0)
    {
      bfd_set_error (bfd_error_no_symbols);
      return NULL;
    }

  ufile_ptr string_table_pos = calculate_string_table_position(abfd);
  if (string_table_pos == 0)
    return NULL;

  if (bfd_seek (abfd, string_table_pos, SEEK_SET) != 0)
    return NULL;

  bfd_size_type strsize = read_string_table_size(abfd);
  if (strsize == 0)
    return NULL;

  if (!validate_string_table_size(abfd, strsize))
    return NULL;

  char *strings = allocate_and_read_strings(abfd, strsize);
  if (strings == NULL)
    return NULL;

  obj_coff_strings (abfd) = strings;
  obj_coff_strings_len (abfd) = strsize;
  strings[strsize] = 0;
  return strings;
}

static ufile_ptr
calculate_string_table_position(bfd *abfd)
{
  size_t symesz = bfd_coff_symesz (abfd);
  ufile_ptr pos = obj_sym_filepos (abfd);
  size_t size;
  
  if (_bfd_mul_overflow (obj_raw_syment_count (abfd), symesz, &size)
      || pos + size < pos)
    {
      bfd_set_error (bfd_error_file_truncated);
      return 0;
    }
  
  return pos + size;
}

static bfd_size_type
read_string_table_size(bfd *abfd)
{
  char extstrsize[STRING_SIZE_SIZE];
  
  if (bfd_read (extstrsize, sizeof extstrsize, abfd) != sizeof extstrsize)
    {
      if (bfd_get_error () != bfd_error_file_truncated)
        return 0;
      return STRING_SIZE_SIZE;
    }
  
#if STRING_SIZE_SIZE == 4
  return H_GET_32 (abfd, extstrsize);
#else
 #error Change H_GET_32
#endif
}

static bool
validate_string_table_size(bfd *abfd, bfd_size_type strsize)
{
  ufile_ptr filesize = bfd_get_file_size (abfd);
  
  if (strsize < STRING_SIZE_SIZE || (filesize != 0 && strsize > filesize))
    {
      _bfd_error_handler
        (_("%pB: bad string table size %" PRIu64), abfd, (uint64_t) strsize);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  
  return true;
}

static char *
allocate_and_read_strings(bfd *abfd, bfd_size_type strsize)
{
  char *strings = (char *) bfd_malloc (strsize + 1);
  if (strings == NULL)
    return NULL;

  memset (strings, 0, STRING_SIZE_SIZE);

  bfd_size_type read_size = strsize - STRING_SIZE_SIZE;
  if (bfd_read (strings + STRING_SIZE_SIZE, read_size, abfd) != read_size)
    {
      free (strings);
      return NULL;
    }

  return strings;
}

/* Free up the external symbols and strings read from a COFF file.  */

bool
_bfd_coff_free_symbols (bfd *abfd)
{
  if (! bfd_family_coff (abfd))
    return false;

  free_external_syms_if_needed(abfd);
  free_strings_if_needed(abfd);

  return true;
}

static void
free_external_syms_if_needed (bfd *abfd)
{
  if (obj_coff_external_syms (abfd) == NULL)
    return;
    
  if (obj_coff_keep_syms (abfd))
    return;
    
  free (obj_coff_external_syms (abfd));
  obj_coff_external_syms (abfd) = NULL;
}

static void
free_strings_if_needed (bfd *abfd)
{
  if (obj_coff_strings (abfd) == NULL)
    return;
    
  if (obj_coff_keep_strings (abfd))
    return;
    
  free (obj_coff_strings (abfd));
  obj_coff_strings (abfd) = NULL;
  obj_coff_strings_len (abfd) = 0;
}

/* Read a symbol table into freshly bfd_allocated memory, swap it, and
   knit the symbol names into a normalized form.  By normalized here I
   mean that all symbols have an n_offset pointer that points to a null-
   terminated string.  */

combined_entry_type *
coff_get_normalized_symtab (bfd *abfd)
{
  combined_entry_type *internal;
  combined_entry_type *internal_ptr;
  size_t symesz;
  char *raw_src;
  char *raw_end;
  const char *string_table = NULL;
  asection * debug_sec = NULL;
  char *debug_sec_data = NULL;
  bfd_size_type size;

  if (obj_raw_syments (abfd) != NULL)
    return obj_raw_syments (abfd);

  if (! _bfd_coff_get_external_symbols (abfd))
    return NULL;

  size = obj_raw_syment_count (abfd);
  if (size > (bfd_size_type) -1 / sizeof (combined_entry_type))
    return NULL;
  size *= sizeof (combined_entry_type);
  internal = (combined_entry_type *) bfd_zalloc (abfd, size);
  if (internal == NULL && size != 0)
    return NULL;

  raw_src = (char *) obj_coff_external_syms (abfd);
  symesz = bfd_coff_symesz (abfd);
  raw_end = PTR_ADD (raw_src, obj_raw_syment_count (abfd) * symesz);

  for (internal_ptr = internal;
       raw_src < raw_end;
       raw_src += symesz, internal_ptr++)
    {
      if (!process_symbol_entry(abfd, &raw_src, &internal_ptr, internal, 
                               raw_end, symesz, &string_table, 
                               &debug_sec, &debug_sec_data))
        return NULL;
    }

  free_external_syms(abfd);

  obj_raw_syments (abfd) = internal;
  BFD_ASSERT (obj_raw_syment_count (abfd)
	      == (size_t) (internal_ptr - internal));

  return internal;
}

static bool
process_symbol_entry(bfd *abfd, char **raw_src_ptr, 
                    combined_entry_type **internal_ptr_ptr,
                    combined_entry_type *internal,
                    char *raw_end, size_t symesz,
                    const char **string_table,
                    asection **debug_sec,
                    char **debug_sec_data)
{
  combined_entry_type *internal_ptr = *internal_ptr_ptr;
  char *raw_src = *raw_src_ptr;
  
  bfd_coff_swap_sym_in (abfd, (void *) raw_src,
                       (void *) & internal_ptr->u.syment);
  internal_ptr->is_sym = true;
  combined_entry_type *sym = internal_ptr;

  if (sym->u.syment.n_numaux > ((raw_end - 1) - raw_src) / symesz)
    return false;

  if (!process_aux_entries(abfd, sym, &internal_ptr, &raw_src, 
                          internal, symesz))
    return false;

  if (sym->u.syment.n_sclass == C_FILE && sym->u.syment.n_numaux > 0)
    {
      if (!process_file_symbol(abfd, sym, string_table, raw_src, symesz))
        return false;
    }
  else
    {
      if (!normalize_symbol_name(abfd, sym, string_table, 
                                debug_sec, debug_sec_data))
        return false;
    }

  *raw_src_ptr = raw_src;
  *internal_ptr_ptr = internal_ptr;
  return true;
}

static bool
process_aux_entries(bfd *abfd, combined_entry_type *sym,
                   combined_entry_type **internal_ptr_ptr,
                   char **raw_src_ptr,
                   combined_entry_type *internal,
                   size_t symesz)
{
  combined_entry_type *internal_ptr = *internal_ptr_ptr;
  char *raw_src = *raw_src_ptr;
  
  for (unsigned int i = 0; i < sym->u.syment.n_numaux; i++)
    {
      internal_ptr++;
      raw_src += symesz;

      bfd_coff_swap_aux_in (abfd, (void *) raw_src,
                           sym->u.syment.n_type,
                           sym->u.syment.n_sclass,
                           (int) i, sym->u.syment.n_numaux,
                           &(internal_ptr->u.auxent));

      internal_ptr->is_sym = false;
      coff_pointerize_aux (abfd, internal, sym, i, internal_ptr);
    }
  
  *internal_ptr_ptr = internal_ptr;
  *raw_src_ptr = raw_src;
  return true;
}

static bool
process_file_symbol(bfd *abfd, combined_entry_type *sym,
                   const char **string_table_ptr,
                   char *raw_src, size_t symesz)
{
  combined_entry_type * aux = sym + 1;
  BFD_ASSERT (! aux->is_sym);

  if (!process_primary_filename(abfd, sym, aux, string_table_ptr, 
                               raw_src, symesz))
    return false;

  if (!obj_pe (abfd))
    {
      if (!process_additional_filenames(abfd, sym, string_table_ptr))
        return false;
    }
  
  return true;
}

static bool
process_primary_filename(bfd *abfd, combined_entry_type *sym,
                        combined_entry_type *aux,
                        const char **string_table_ptr,
                        char *raw_src, size_t symesz)
{
  if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0)
    {
      if (!ensure_string_table(abfd, string_table_ptr))
        return false;
      
      set_long_filename(sym, aux, *string_table_ptr, abfd);
    }
  else
    {
      set_short_filename(abfd, sym, aux, raw_src, symesz);
    }
  return true;
}

static void
set_long_filename(combined_entry_type *sym, combined_entry_type *aux,
                 const char *string_table, bfd *abfd)
{
  if ((bfd_size_type) aux->u.auxent.x_file.x_n.x_n.x_offset
      >= obj_coff_strings_len (abfd))
    sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
  else
    sym->u.syment._n._n_n._n_offset =
      (uintptr_t) (string_table + aux->u.auxent.x_file.x_n.x_n.x_offset);
}

static void
set_short_filename(bfd *abfd, combined_entry_type *sym,
                  combined_entry_type *aux,
                  char *raw_src, size_t symesz)
{
  size_t len;
  char *src;
  
  if (sym->u.syment.n_numaux > 1 && obj_pe (abfd))
    {
      len = sym->u.syment.n_numaux * symesz;
      src = raw_src - (len - symesz);
    }
  else
    {
      len = bfd_coff_filnmlen (abfd);
      src = aux->u.auxent.x_file.x_n.x_fname;
    }
  sym->u.syment._n._n_n._n_offset = (uintptr_t) copy_name (abfd, src, len);
}

static bool
process_additional_filenames(bfd *abfd, combined_entry_type *sym,
                            const char **string_table_ptr)
{
  for (int numaux = 1; numaux < sym->u.syment.n_numaux; numaux++)
    {
      combined_entry_type *aux = sym + numaux + 1;
      BFD_ASSERT (! aux->is_sym);

      if (!process_aux_filename(abfd, aux, string_table_ptr))
        return false;
    }
  return true;
}

static bool
process_aux_filename(bfd *abfd, combined_entry_type *aux,
                    const char **string_table_ptr)
{
  if (aux->u.auxent.x_file.x_n.x_n.x_zeroes == 0)
    {
      if (!ensure_string_table(abfd, string_table_ptr))
        return false;
      
      set_aux_long_string(aux, *string_table_ptr, abfd);
    }
  else
    {
      aux->u.auxent.x_file.x_n.x_n.x_offset =
        (uintptr_t) copy_name (abfd, aux->u.auxent.x_file.x_n.x_fname,
                              bfd_coff_filnmlen (abfd));
    }
  return true;
}

static void
set_aux_long_string(combined_entry_type *aux, const char *string_table,
                   bfd *abfd)
{
  if ((bfd_size_type) aux->u.auxent.x_file.x_n.x_n.x_offset
      >= obj_coff_strings_len (abfd))
    aux->u.auxent.x_file.x_n.x_n.x_offset = (uintptr_t) bfd_symbol_error_name;
  else
    aux->u.auxent.x_file.x_n.x_n.x_offset =
      (uintptr_t) (string_table + aux->u.auxent.x_file.x_n.x_n.x_offset);
}

static bool
normalize_symbol_name(bfd *abfd, combined_entry_type *sym,
                     const char **string_table_ptr,
                     asection **debug_sec,
                     char **debug_sec_data)
{
  if (sym->u.syment._n._n_n._n_zeroes != 0)
    {
      return convert_short_name(abfd, sym);
    }
  
  if (sym->u.syment._n._n_n._n_offset == 0)
    {
      sym->u.syment._n._n_n._n_offset = (uintptr_t) "";
      return true;
    }
  
  if (!bfd_coff_symname_in_debug (abfd, &sym->u.syment))
    {
      return set_long_symbol_name(abfd, sym, string_table_ptr);
    }
  
  return set_debug_symbol_name(abfd, sym, debug_sec, debug_sec_data);
}

static bool
convert_short_name(bfd *abfd, combined_entry_type *sym)
{
  unsigned int i;
  char *newstring;

  for (i = 0; i < SYMNMLEN; ++i)
    if (sym->u.syment._n._n_name[i] == '\0')
      break;

  newstring = bfd_alloc (abfd, i + 1);
  if (newstring == NULL)
    return false;
  
  memcpy (newstring, sym->u.syment._n._n_name, i);
  newstring[i] = 0;
  sym->u.syment._n._n_n._n_offset = (uintptr_t) newstring;
  sym->u.syment._n._n_n._n_zeroes = 0;
  return true;
}

static bool
set_long_symbol_name(bfd *abfd, combined_entry_type *sym,
                    const char **string_table_ptr)
{
  if (!ensure_string_table(abfd, string_table_ptr))
    return false;
  
  if (sym->u.syment._n._n_n._n_offset >= obj_coff_strings_len (abfd))
    sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
  else
    sym->u.syment._n._n_n._n_offset =
      (uintptr_t) (*string_table_ptr + sym->u.syment._n._n_n._n_offset);
  
  return true;
}

static bool
set_debug_symbol_name(bfd *abfd, combined_entry_type *sym,
                     asection **debug_sec,
                     char **debug_sec_data)
{
  if (*debug_sec_data == NULL)
    {
      *debug_sec_data = build_debug_section (abfd, debug_sec);
      if (*debug_sec_data == NULL)
        return false;
    }
  
  if (sym->u.syment._n._n_n._n_offset >= (*debug_sec)->size)
    sym->u.syment._n._n_n._n_offset = (uintptr_t) bfd_symbol_error_name;
  else
    sym->u.syment._n._n_n._n_offset =
      (uintptr_t) (*debug_sec_data + sym->u.syment._n._n_n._n_offset);
  
  return true;
}

static bool
ensure_string_table(bfd *abfd, const char **string_table_ptr)
{
  if (*string_table_ptr == NULL)
    {
      *string_table_ptr = _bfd_coff_read_string_table (abfd);
      if (*string_table_ptr == NULL)
        return false;
    }
  return true;
}

static void
free_external_syms(bfd *abfd)
{
  if (obj_coff_external_syms (abfd) != NULL
      && ! obj_coff_keep_syms (abfd))
    {
      free (obj_coff_external_syms (abfd));
      obj_coff_external_syms (abfd) = NULL;
    }
}

long
coff_get_reloc_upper_bound (bfd *abfd, sec_ptr asect)
{
  size_t count, raw;

  count = asect->reloc_count;
  
  if (!validate_reloc_count(count, abfd, &raw))
    return -1;
    
  if (!validate_file_size(abfd, raw))
    return -1;
    
  return (count + 1) * sizeof (arelent *);
}

static bool
validate_reloc_count(size_t count, bfd *abfd, size_t *raw)
{
  if (count >= LONG_MAX / sizeof (arelent *)
      || _bfd_mul_overflow (count, bfd_coff_relsz (abfd), raw))
    {
      bfd_set_error (bfd_error_file_too_big);
      return false;
    }
  return true;
}

static bool
validate_file_size(bfd *abfd, size_t raw)
{
  if (!bfd_write_p (abfd))
    {
      ufile_ptr filesize = bfd_get_file_size (abfd);
      if (filesize != 0 && raw > filesize)
        {
          bfd_set_error (bfd_error_file_truncated);
          return false;
        }
    }
  return true;
}

asymbol *
coff_make_empty_symbol (bfd *abfd)
{
  size_t amt = sizeof (coff_symbol_type);
  coff_symbol_type *new_symbol = (coff_symbol_type *) bfd_zalloc (abfd, amt);

  if (new_symbol == NULL)
    return NULL;
  new_symbol->symbol.section = 0;
  new_symbol->native = NULL;
  new_symbol->lineno = NULL;
  new_symbol->done_lineno = false;
  new_symbol->symbol.the_bfd = abfd;

  return & new_symbol->symbol;
}

/* Make a debugging symbol.  */

#define MAX_AUX_ENTRIES 10

static coff_symbol_type *allocate_coff_symbol(bfd *abfd)
{
    size_t amt = sizeof(coff_symbol_type);
    return (coff_symbol_type *) bfd_alloc(abfd, amt);
}

static combined_entry_type *allocate_native_entries(bfd *abfd)
{
    size_t amt = sizeof(combined_entry_type) * MAX_AUX_ENTRIES;
    return (combined_entry_type *) bfd_zalloc(abfd, amt);
}

static void initialize_symbol_fields(coff_symbol_type *new_symbol, bfd *abfd)
{
    new_symbol->native->is_sym = true;
    new_symbol->symbol.section = bfd_abs_section_ptr;
    new_symbol->symbol.flags = BSF_DEBUGGING;
    new_symbol->lineno = NULL;
    new_symbol->done_lineno = false;
    new_symbol->symbol.the_bfd = abfd;
}

asymbol *
coff_bfd_make_debug_symbol(bfd *abfd)
{
    coff_symbol_type *new_symbol = allocate_coff_symbol(abfd);
    if (new_symbol == NULL)
        return NULL;

    new_symbol->native = allocate_native_entries(abfd);
    if (!new_symbol->native)
        return NULL;

    initialize_symbol_fields(new_symbol, abfd);

    return &new_symbol->symbol;
}

void
coff_get_symbol_info (bfd *abfd, asymbol *symbol, symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);

  if (!coffsymbol (symbol)->native)
    return;

  if (!coffsymbol (symbol)->native->fix_value)
    return;

  if (!coffsymbol (symbol)->native->is_sym)
    return;

  uintptr_t symbol_value = (uintptr_t) coffsymbol (symbol)->native->u.syment.n_value;
  uintptr_t raw_syments = (uintptr_t) obj_raw_syments (abfd);
  ret->value = (symbol_value - raw_syments) / sizeof (combined_entry_type);
}

/* Print out information about COFF symbol.  */

void
coff_print_symbol (bfd *abfd,
		   void * filep,
		   asymbol *symbol,
		   bfd_print_symbol_type how)
{
  FILE * file = (FILE *) filep;
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
      print_symbol_all(abfd, file, symbol, symname);
      break;
    }
}

static void
print_symbol_all(bfd *abfd, FILE *file, asymbol *symbol, const char *symname)
{
  if (coffsymbol (symbol)->native)
    print_native_symbol(abfd, file, symbol, symname);
  else
    print_non_native_symbol(abfd, file, symbol, symname);
}

static void
print_native_symbol(bfd *abfd, FILE *file, asymbol *symbol, const char *symname)
{
  combined_entry_type *combined = coffsymbol (symbol)->native;
  combined_entry_type *root = obj_raw_syments (abfd);
  
  fprintf (file, "[%3ld]", (long) (combined - root));
  
  if (!is_valid_combined_entry(abfd, combined))
    {
      fprintf (file, _("<corrupt info> %s"), symname);
      return;
    }
  
  print_symbol_header(abfd, file, combined, root, symname);
  print_aux_entries(abfd, file, combined, root);
  print_line_numbers(abfd, file, symbol);
}

static int
is_valid_combined_entry(bfd *abfd, combined_entry_type *combined)
{
  return combined >= obj_raw_syments (abfd) 
         && combined < obj_raw_syments (abfd) + obj_raw_syment_count (abfd);
}

static void
print_symbol_header(bfd *abfd, FILE *file, combined_entry_type *combined, 
                   combined_entry_type *root, const char *symname)
{
  bfd_vma val;
  
  BFD_ASSERT (combined->is_sym);
  
  if (! combined->fix_value)
    val = (bfd_vma) combined->u.syment.n_value;
  else
    val = (((uintptr_t) combined->u.syment.n_value - (uintptr_t) root)
           / sizeof (combined_entry_type));
  
  fprintf (file, "(sec %2d)(fl 0x%02x)(ty %4x)(scl %3d) (nx %d) 0x",
           combined->u.syment.n_scnum,
           combined->u.syment.n_flags,
           combined->u.syment.n_type,
           combined->u.syment.n_sclass,
           combined->u.syment.n_numaux);
  bfd_fprintf_vma (abfd, file, val);
  fprintf (file, " %s", symname);
}

static void
print_aux_entries(bfd *abfd, FILE *file, combined_entry_type *combined, 
                 combined_entry_type *root)
{
  unsigned int aux;
  
  for (aux = 0; aux < combined->u.syment.n_numaux; aux++)
    {
      combined_entry_type *auxp = combined + aux + 1;
      
      BFD_ASSERT (! auxp->is_sym);
      
      fprintf (file, "\n");
      
      if (bfd_coff_print_aux (abfd, file, root, combined, auxp, aux))
        continue;
      
      print_aux_entry_details(file, combined, auxp, root);
    }
}

static void
print_aux_entry_details(FILE *file, combined_entry_type *combined, 
                       combined_entry_type *auxp, combined_entry_type *root)
{
  long tagndx = get_tag_index(auxp, root);
  
  switch (combined->u.syment.n_sclass)
    {
    case C_FILE:
      print_file_aux(file, auxp);
      break;
      
    case C_DWARF:
      print_dwarf_aux(file, auxp);
      break;
      
    case C_STAT:
      if (combined->u.syment.n_type == T_NULL)
        {
          print_section_aux(file, auxp);
          break;
        }
      /* Fall through */
      
    case C_EXT:
    case C_AIX_WEAKEXT:
      if (ISFCN (combined->u.syment.n_type))
        {
          print_function_aux(file, auxp, root, tagndx);
          break;
        }
      /* Fall through */
      
    default:
      print_default_aux(file, auxp, root, tagndx);
      break;
    }
}

static long
get_tag_index(combined_entry_type *auxp, combined_entry_type *root)
{
  if (auxp->fix_tag)
    return auxp->u.auxent.x_sym.x_tagndx.p - root;
  return auxp->u.auxent.x_sym.x_tagndx.u32;
}

static void
print_file_aux(FILE *file, combined_entry_type *auxp)
{
  fprintf (file, "File ");
  if (auxp->u.auxent.x_file.x_ftype)
    fprintf (file, "ftype %d fname \"%s\"",
             auxp->u.auxent.x_file.x_ftype,
             (char *) auxp->u.auxent.x_file.x_n.x_n.x_offset);
}

static void
print_dwarf_aux(FILE *file, combined_entry_type *auxp)
{
  fprintf (file, "AUX scnlen %#" PRIx64 " nreloc %" PRId64,
           auxp->u.auxent.x_sect.x_scnlen,
           auxp->u.auxent.x_sect.x_nreloc);
}

static void
print_section_aux(FILE *file, combined_entry_type *auxp)
{
  fprintf (file, "AUX scnlen 0x%lx nreloc %d nlnno %d",
           (unsigned long) auxp->u.auxent.x_scn.x_scnlen,
           auxp->u.auxent.x_scn.x_nreloc,
           auxp->u.auxent.x_scn.x_nlinno);
  
  if (auxp->u.auxent.x_scn.x_checksum != 0
      || auxp->u.auxent.x_scn.x_associated != 0
      || auxp->u.auxent.x_scn.x_comdat != 0)
    fprintf (file, " checksum 0x%x assoc %d comdat %d",
             auxp->u.auxent.x_scn.x_checksum,
             auxp->u.auxent.x_scn.x_associated,
             auxp->u.auxent.x_scn.x_comdat);
}

static void
print_function_aux(FILE *file, combined_entry_type *auxp, 
                   combined_entry_type *root, long tagndx)
{
  long next;
  
  if (auxp->fix_end)
    next = auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p - root;
  else
    next = auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.u32;
  
  fprintf (file,
           "AUX tagndx %ld ttlsiz 0x%lx lnnos %ld next %ld",
           tagndx,
           (unsigned long) auxp->u.auxent.x_sym.x_misc.x_fsize,
           auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_lnnoptr,
           next);
}

static void
print_default_aux(FILE *file, combined_entry_type *auxp, 
                 combined_entry_type *root, long tagndx)
{
  fprintf (file, "AUX lnno %d size 0x%x tagndx %ld",
           auxp->u.auxent.x_sym.x_misc.x_lnsz.x_lnno,
           auxp->u.auxent.x_sym.x_misc.x_lnsz.x_size,
           tagndx);
  
  if (auxp->fix_end)
    fprintf (file, " endndx %ld",
             ((long)(auxp->u.auxent.x_sym.x_fcnary.x_fcn.x_endndx.p - root)));
}

static void
print_line_numbers(bfd *abfd, FILE *file, asymbol *symbol)
{
  struct lineno_cache_entry *l = coffsymbol (symbol)->lineno;
  
  if (!l)
    return;
  
  fprintf (file, "\n%s :",
           l->u.sym->name != bfd_symbol_error_name
           ? l->u.sym->name : _("<corrupt>"));
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
print_non_native_symbol(bfd *abfd, FILE *file, asymbol *symbol, const char *symname)
{
  bfd_print_symbol_vandf (abfd, (void *) file, symbol);
  fprintf (file, " %-5s %s %s %s",
           symbol->section->name,
           coffsymbol (symbol)->native ? "n" : "g",
           coffsymbol (symbol)->lineno ? "l" : " ",
           symname);
}

/* Return whether a symbol name implies a local symbol.  In COFF,
   local symbols generally start with ``.L''.  Most targets use this
   function for the is_local_label_name entry point, but some may
   override it.  */

bool
_bfd_coff_is_local_label_name (bfd *abfd ATTRIBUTE_UNUSED,
                               const char *name)
{
  const char LOCAL_LABEL_PREFIX = '.';
  const char LOCAL_LABEL_SUFFIX = 'L';
  
  return name[0] == LOCAL_LABEL_PREFIX && name[1] == LOCAL_LABEL_SUFFIX;
}

/* Provided a BFD, a section and an offset (in bytes, not octets) into the
   section, calculate and return the name of the source file and the line
   nearest to the wanted location.  */

#define LINE_NUMBER_SLOP 0x100

static bool try_stab_section_lookup(bfd *abfd, asymbol **symbols, asection *section,
                                   bfd_vma offset, const char **filename_ptr,
                                   const char **functionname_ptr, unsigned int *line_ptr)
{
    bool found;
    if (!_bfd_stab_section_find_nearest_line(abfd, symbols, section, offset,
                                            &found, filename_ptr,
                                            functionname_ptr, line_ptr,
                                            &coff_data(abfd)->line_info))
        return false;
    return found;
}

static bool try_dwarf2_lookup(bfd *abfd, asymbol **symbols, asection *section,
                            bfd_vma offset, const char **filename_ptr,
                            const char **functionname_ptr, unsigned int *line_ptr,
                            const struct dwarf_debug_section *debug_sections)
{
    return _bfd_dwarf2_find_nearest_line(abfd, symbols, NULL, section, offset,
                                        filename_ptr, functionname_ptr,
                                        line_ptr, NULL, debug_sections,
                                        &coff_data(abfd)->dwarf2_find_line_info);
}

static struct coff_section_tdata* ensure_section_data(bfd *abfd, asection *section)
{
    if (section->used_by_bfd != NULL || section->owner != abfd)
        return section->used_by_bfd;
    
    size_t amt = sizeof(struct coff_section_tdata);
    section->used_by_bfd = bfd_zalloc(abfd, amt);
    return (struct coff_section_tdata *)section->used_by_bfd;
}

static bfd_signed_vma get_dwarf_bias(asymbol **symbols, struct coff_section_tdata *sec_data,
                                    coff_data_type *cof)
{
    if (sec_data != NULL && sec_data->saved_bias)
        return sec_data->bias;
    
    if (!symbols)
        return 0;
    
    bfd_signed_vma bias = _bfd_dwarf2_find_symbol_bias(symbols,
                                                      &cof->dwarf2_find_line_info);
    if (sec_data) {
        sec_data->saved_bias = true;
        sec_data->bias = bias;
    }
    return bias;
}

static bool try_dwarf2_with_bias(bfd *abfd, asymbol **symbols, asection *section,
                                bfd_vma offset, const char **filename_ptr,
                                const char **functionname_ptr, unsigned int *line_ptr,
                                const struct dwarf_debug_section *debug_sections)
{
    coff_data_type *cof = coff_data(abfd);
    if (cof->dwarf2_find_line_info == NULL)
        return false;
    
    struct coff_section_tdata *sec_data = coff_section_data(abfd, section);
    if (sec_data == NULL)
        sec_data = ensure_section_data(abfd, section);
    
    bfd_signed_vma bias = get_dwarf_bias(symbols, sec_data, cof);
    if (!bias)
        return false;
    
    return _bfd_dwarf2_find_nearest_line(abfd, symbols, NULL, section,
                                        offset + bias, filename_ptr,
                                        functionname_ptr, line_ptr, NULL,
                                        debug_sections,
                                        &cof->dwarf2_find_line_info);
}

static void reset_output_parameters(const char **filename_ptr,
                                   const char **functionname_ptr,
                                   unsigned int *line_ptr)
{
    *filename_ptr = 0;
    *functionname_ptr = 0;
    *line_ptr = 0;
}

static combined_entry_type* find_first_file_symbol(coff_data_type *cof)
{
    if (!cof || !cof->raw_syments)
        return NULL;
    
    combined_entry_type *p = cof->raw_syments;
    combined_entry_type *pend = p + cof->raw_syment_count;
    
    while (p < pend) {
        BFD_ASSERT(p->is_sym);
        if (p->u.syment.n_sclass == C_FILE)
            return p;
        p += 1 + p->u.syment.n_numaux;
    }
    return NULL;
}

static combined_entry_type* find_next_relevant_symbol(combined_entry_type *start,
                                                     combined_entry_type *pend,
                                                     asection *section, bfd *abfd)
{
    combined_entry_type *p2 = start;
    
    for (; p2 < pend; p2 += 1 + p2->u.syment.n_numaux) {
        BFD_ASSERT(p2->is_sym);
        if (p2->u.syment.n_scnum > 0 &&
            section == coff_section_from_bfd_index(abfd, p2->u.syment.n_scnum))
            break;
        if (p2->u.syment.n_sclass == C_FILE) {
            p2 = pend;
            break;
        }
    }
    return p2;
}

static bfd_vma get_symbol_file_address(combined_entry_type *p2, bfd *abfd)
{
    bfd_vma file_addr = (bfd_vma)p2->u.syment.n_value;
    if (p2->u.syment.n_scnum > 0)
        file_addr += coff_section_from_bfd_index(abfd, p2->u.syment.n_scnum)->vma;
    return file_addr;
}

static combined_entry_type* advance_to_next_file(combined_entry_type *p, coff_data_type *cof)
{
    if (p->u.syment.n_value >= cof->raw_syment_count)
        return NULL;
    if (p >= cof->raw_syments + p->u.syment.n_value)
        return NULL;
    
    combined_entry_type *next = cof->raw_syments + p->u.syment.n_value;
    if (!next->is_sym || next->u.syment.n_sclass != C_FILE)
        return NULL;
    return next;
}

static void find_best_file_symbol(bfd *abfd, asection *section, bfd_vma offset,
                                 const char **filename_ptr, coff_data_type *cof)
{
    combined_entry_type *p = find_first_file_symbol(cof);
    if (!p)
        return;
    
    combined_entry_type *pend = cof->raw_syments + cof->raw_syment_count;
    bfd_vma sec_vma = bfd_section_vma(section);
    *filename_ptr = (char *)p->u.syment._n._n_n._n_offset;
    bfd_vma maxdiff = (bfd_vma)0 - (bfd_vma)1;
    
    while (p) {
        combined_entry_type *p2 = find_next_relevant_symbol(p + 1 + p->u.syment.n_numaux,
                                                           pend, section, abfd);
        if (p2 >= pend)
            break;
        
        bfd_vma file_addr = get_symbol_file_address(p2, abfd);
        
        if (p2 < pend && offset + sec_vma >= file_addr &&
            offset + sec_vma - file_addr <= maxdiff) {
            *filename_ptr = (char *)p->u.syment._n._n_n._n_offset;
            maxdiff = offset + sec_vma - p2->u.syment.n_value;
        }
        
        p = advance_to_next_file(p, cof);
    }
}

static void initialize_line_search(struct coff_section_tdata *sec_data, bfd_vma offset,
                                  unsigned int *i, const char **functionname_ptr,
                                  unsigned int *line_base)
{
    if (sec_data != NULL && sec_data->i > 0 && offset >= sec_data->offset) {
        *i = sec_data->i;
        *functionname_ptr = sec_data->function;
        *line_base = sec_data->line_base;
    } else {
        *i = 0;
        *line_base = 0;
    }
}

static unsigned int get_line_base_from_symbol(coff_symbol_type *coff, bfd *abfd)
{
    if (!coff->native)
        return 0;
    
    combined_entry_type *s = coff->native;
    BFD_ASSERT(s->is_sym);
    s = s + 1 + s->u.syment.n_numaux;
    
    if (((size_t)((char *)s - (char *)obj_raw_syments(abfd))
         < obj_raw_syment_count(abfd) * sizeof(*s))
        && s->u.syment.n_scnum == N_DEBUG)
        s = s + 1 + s->u.syment.n_numaux;
    
    if (((size_t)((char *)s - (char *)obj_raw_syments(abfd))
         < obj_raw_syment_count(abfd) * sizeof(*s))
        && s->u.syment.n_numaux) {
        union internal_auxent *a = &((s + 1)->u.auxent);
        return a->x_sym.x_misc.x_lnsz.x_lnno;
    }
    return 0;
}

static void process_line_number_entry(alent *l, bfd_vma offset,
                                     const char **functionname_ptr,
                                     unsigned int *line_ptr, unsigned int *line_base,
                                     bfd_vma *last_value, bfd *abfd)
{
    if (l->line_number == 0) {
        coff_symbol_type *coff = (coff_symbol_type *)(l->u.sym);
        if (coff->symbol.value <= offset) {
            *functionname_ptr = coff->symbol.name;
            *last_value = coff->symbol.value;
            unsigned int new_line_base = get_line_base_from_symbol(coff, abfd);
            if (new_line_base) {
                *line_base = new_line_base;
                *line_ptr = *line_base;
            }
        }
    } else {
        if (l->u.offset <= offset)
            *line_ptr = l->line_number + *line_base - 1;
    }
}

static void search_line_numbers(asection *section, bfd_vma offset,
                               const char **functionname_ptr, unsigned int *line_ptr,
                               unsigned int *i, unsigned int *line_base, bfd *abfd)
{
    if (section->lineno == NULL)
        return;
    
    bfd_vma last_value = 0;
    alent *l = &section->lineno[*i];
    
    for (; *i < section->lineno_count; (*i)++) {
        if (l->line_number == 0 && l->u.sym &&
            ((coff_symbol_type *)(l->u.sym))->symbol.value > offset)
            break;
        if (l->line_number != 0 && l->u.offset > offset)
            break;
        
        process_line_number_entry(l, offset, functionname_ptr, line_ptr,
                                line_base, &last_value, abfd);
        l++;
    }
    
    if (*i >= section->lineno_count && last_value != 0 &&
        offset - last_value > LINE_NUMBER_SLOP) {
        *functionname_ptr = NULL;
        *line_ptr = 0;
    }
}

static void cache_results(bfd *abfd, asection *section, bfd_vma offset,
                        unsigned int i, const char *functionname,
                        unsigned int line_base)
{
    struct coff_section_tdata *sec_data = coff_section_data(abfd, section);
    if (sec_data == NULL)
        sec_data = ensure_section_data(abfd, section);
    
    if (sec_data != NULL) {
        sec_data->offset = offset;
        sec_data->i = i - 1;
        sec_data->function = functionname;
        sec_data->line_base = line_base;
    }
}

bool coff_find_nearest_line_with_names(bfd *abfd, asymbol **symbols,
                                      asection *section, bfd_vma offset,
                                      const char **filename_ptr,
                                      const char **functionname_ptr,
                                      unsigned int *line_ptr,
                                      const struct dwarf_debug_section *debug_sections)
{
    if (try_stab_section_lookup(abfd, symbols, section, offset,
                               filename_ptr, functionname_ptr, line_ptr))
        return true;
    
    if (try_dwarf2_lookup(abfd, symbols, section, offset,
                         filename_ptr, functionname_ptr, line_ptr, debug_sections))
        return true;
    
    if (try_dwarf2_with_bias(abfd, symbols, section, offset,
                            filename_ptr, functionname_ptr, line_ptr, debug_sections))
        return true;
    
    reset_output_parameters(filename_ptr, functionname_ptr, line_ptr);
    
    if (!bfd_family_coff(abfd))
        return false;
    
    coff_data_type *cof = coff_data(abfd);
    if (!cof)
        return false;
    
    find_best_file_symbol(abfd, section, offset, filename_ptr, cof);
    
    if (section->lineno_count == 0) {
        *functionname_ptr = NULL;
        *line_ptr = 0;
        return true;
    }
    
    unsigned int i, line_base;
    struct coff_section_tdata *sec_data = coff_section_data(abfd, section);
    initialize_line_search(sec_data, offset, &i, functionname_ptr, &line_base);
    
    search_line_numbers(section, offset, functionname_ptr, line_ptr,
                       &i, &line_base, abfd);
    
    cache_results(abfd, section, offset, i, *functionname_ptr, line_base);
    
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
  if (discriminator_ptr)
    *discriminator_ptr = 0;
  return coff_find_nearest_line_with_names (abfd, symbols, section, offset,
					    filename_ptr, functionname_ptr,
					    line_ptr, dwarf_debug_sections);
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
  size_t size = bfd_coff_filhsz (abfd);

  if (!bfd_link_relocatable (info))
    size += bfd_coff_aoutsz (abfd);

  size += abfd->section_count * bfd_coff_scnhsz (abfd);
  return size;
}

/* Change the class of a coff symbol held by BFD.  */

bool
bfd_coff_set_symbol_class (bfd *	 abfd,
			   asymbol *	 symbol,
			   unsigned int	 symbol_class)
{
  coff_symbol_type * csym;

  csym = coff_symbol_from (symbol);
  if (csym == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }
  
  if (csym->native == NULL)
    {
      if (!create_native_entry_for_alien_symbol(abfd, symbol, csym, symbol_class))
        return false;
    }
  else
    {
      csym->native->u.syment.n_sclass = symbol_class;
    }

  return true;
}

static bool
create_native_entry_for_alien_symbol(bfd *abfd, 
                                     asymbol *symbol,
                                     coff_symbol_type *csym,
                                     unsigned int symbol_class)
{
  combined_entry_type * native;
  size_t amt = sizeof (* native);

  native = (combined_entry_type *) bfd_zalloc (abfd, amt);
  if (native == NULL)
    return false;

  initialize_native_entry(native, symbol_class);
  set_native_section_values(abfd, symbol, native, csym);
  
  csym->native = native;
  return true;
}

static void
initialize_native_entry(combined_entry_type *native, unsigned int symbol_class)
{
  native->is_sym = true;
  native->u.syment.n_type   = T_NULL;
  native->u.syment.n_sclass = symbol_class;
}

static void
set_native_section_values(bfd *abfd, 
                         asymbol *symbol,
                         combined_entry_type *native,
                         coff_symbol_type *csym)
{
  if (bfd_is_und_section (symbol->section) || bfd_is_com_section (symbol->section))
    {
      native->u.syment.n_scnum = N_UNDEF;
      native->u.syment.n_value = symbol->value;
    }
  else
    {
      set_regular_section_values(abfd, symbol, native, csym);
    }
}

static void
set_regular_section_values(bfd *abfd,
                           asymbol *symbol,
                           combined_entry_type *native,
                           coff_symbol_type *csym)
{
  native->u.syment.n_scnum = symbol->section->output_section->target_index;
  native->u.syment.n_value = symbol->value + symbol->section->output_offset;
  
  if (!obj_pe (abfd))
    native->u.syment.n_value += symbol->section->output_section->vma;

  native->u.syment.n_flags = bfd_asymbol_bfd (&csym->symbol)->flags;
}

bool
_bfd_coff_section_already_linked (bfd *abfd,
				  asection *sec,
				  struct bfd_link_info *info)
{
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

  name = bfd_section_name (sec);
  s_comdat = bfd_coff_get_comdat_section (abfd, sec);

  key = get_section_key(name, s_comdat);

  already_linked_list = bfd_section_already_linked_table_lookup (key);
  if (!already_linked_list)
    {
      info->callbacks->fatal (_("%P: already_linked_table: %E\n"));
      return false;
    }

  l = find_matching_linked_section(already_linked_list, sec, name, s_comdat);
  if (l != NULL)
    return _bfd_handle_already_linked (sec, l, info);

  if (!bfd_section_already_linked_table_insert (already_linked_list, sec))
    {
      info->callbacks->fatal (_("%P: already_linked_table: %E\n"));
    }
  return false;
}

static const char *
get_section_key(const char *name, struct coff_comdat_info *s_comdat)
{
  const char *key;
  
  if (s_comdat != NULL)
    return s_comdat->name;

  if (startswith (name, ".gnu.linkonce.")
      && (key = strchr (name + sizeof (".gnu.linkonce.") - 1, '.')) != NULL)
    return key + 1;
  
  return name;
}

static struct bfd_section_already_linked *
find_matching_linked_section(struct bfd_section_already_linked_hash_entry *already_linked_list,
                              asection *sec,
                              const char *name,
                              struct coff_comdat_info *s_comdat)
{
  struct bfd_section_already_linked *l;

  for (l = already_linked_list->entry; l != NULL; l = l->next)
    {
      if (sections_match(l, sec, name, s_comdat))
        return l;
    }
  return NULL;
}

static bool
sections_match(struct bfd_section_already_linked *l,
               asection *sec,
               const char *name,
               struct coff_comdat_info *s_comdat)
{
  struct coff_comdat_info *l_comdat;

  l_comdat = bfd_coff_get_comdat_section (l->sec->owner, l->sec);

  if ((l->sec->owner->flags & BFD_PLUGIN) != 0)
    return true;
  
  if ((sec->owner->flags & BFD_PLUGIN) != 0)
    return true;

  return ((s_comdat != NULL) == (l_comdat != NULL)
          && strcmp (name, l->sec->name) == 0);
}

/* Initialize COOKIE for input bfd ABFD. */

static bool
init_reloc_cookie (struct coff_reloc_cookie *cookie,
		   struct bfd_link_info *info ATTRIBUTE_UNUSED,
		   bfd *abfd)
{
  bfd_coff_slurp_symbol_table (abfd);

  cookie->abfd = abfd;
  cookie->sym_hashes = obj_coff_sym_hashes (abfd);
  cookie->symbols = obj_symbols (abfd);

  return true;
}

/* Free the memory allocated by init_reloc_cookie, if appropriate.  */

static void
fini_reloc_cookie (struct coff_reloc_cookie *cookie ATTRIBUTE_UNUSED,
		   bfd *abfd ATTRIBUTE_UNUSED)
{
}

/* Initialize the relocation information in COOKIE for input section SEC
   of input bfd ABFD.  */

static void init_empty_cookie(struct coff_reloc_cookie *cookie)
{
    cookie->rels = NULL;
    cookie->relend = NULL;
    cookie->rel = NULL;
}

static void init_cookie_pointers(struct coff_reloc_cookie *cookie, unsigned int reloc_count)
{
    cookie->rel = cookie->rels;
    cookie->relend = cookie->rels + reloc_count;
}

static bool
init_reloc_cookie_rels (struct coff_reloc_cookie *cookie,
			struct bfd_link_info *info ATTRIBUTE_UNUSED,
			bfd *abfd,
			asection *sec)
{
  if (sec->reloc_count == 0)
    {
      init_empty_cookie(cookie);
      return true;
    }

  cookie->rels = _bfd_coff_read_internal_relocs (abfd, sec, false, NULL,
						 0, NULL);

  if (cookie->rels == NULL)
    return false;

  init_cookie_pointers(cookie, sec->reloc_count);
  return true;
}

/* Free the memory allocated by init_reloc_cookie_rels,
   if appropriate.  */

static void
fini_reloc_cookie_rels (struct coff_reloc_cookie *cookie,
			asection *sec)
{
  if (!cookie->rels) {
    return;
  }
  
  if (!coff_section_data (NULL, sec)) {
    return;
  }
  
  if (coff_section_data (NULL, sec)->relocs == cookie->rels) {
    return;
  }
  
  free (cookie->rels);
}

/* Initialize the whole of COOKIE for input section SEC.  */

static bool
init_reloc_cookie_for_section (struct coff_reloc_cookie *cookie,
			       struct bfd_link_info *info,
			       asection *sec)
{
  if (!init_reloc_cookie (cookie, info, sec->owner))
    return false;

  if (!init_reloc_cookie_rels (cookie, info, sec->owner, sec))
    {
      fini_reloc_cookie (cookie, sec->owner);
      return false;
    }
  return true;
}

/* Free the memory allocated by init_reloc_cookie_for_section,
   if appropriate.  */

static void
fini_reloc_cookie_for_section (struct coff_reloc_cookie *cookie,
			       asection *sec)
{
  fini_reloc_cookie_rels (cookie, sec);
  fini_reloc_cookie (cookie, sec->owner);
}

static asection *
get_defined_section(struct coff_link_hash_entry *h)
{
  return h->root.u.def.section;
}

static asection *
get_common_section(struct coff_link_hash_entry *h)
{
  return h->root.u.c.p->section;
}

static asection *
get_weak_external_section(struct coff_link_hash_entry *h)
{
  struct coff_link_hash_entry *h2;
  
  if (h->symbol_class != C_NT_WEAK || h->numaux != 1)
    return NULL;
    
  h2 = h->auxbfd->tdata.coff_obj_data->sym_hashes[h->aux->x_sym.x_tagndx.u32];
  
  if (h2 && h2->root.type != bfd_link_hash_undefined)
    return h2->root.u.def.section;
    
  return NULL;
}

static asection *
get_section_from_hash(struct coff_link_hash_entry *h)
{
  switch (h->root.type)
    {
    case bfd_link_hash_defined:
    case bfd_link_hash_defweak:
      return get_defined_section(h);
      
    case bfd_link_hash_common:
      return get_common_section(h);
      
    case bfd_link_hash_undefweak:
      return get_weak_external_section(h);
      
    case bfd_link_hash_undefined:
    default:
      return NULL;
    }
}

static asection *
_bfd_coff_gc_mark_hook (asection *sec,
			struct bfd_link_info *info ATTRIBUTE_UNUSED,
			struct internal_reloc *rel ATTRIBUTE_UNUSED,
			struct coff_link_hash_entry *h,
			struct internal_syment *sym)
{
  if (h != NULL)
    return get_section_from_hash(h);
    
  return coff_section_from_bfd_index (sec->owner, sym->n_scnum);
}

/* COOKIE->rel describes a relocation against section SEC, which is
   a section we've decided to keep.  Return the section that contains
   the relocation symbol, or NULL if no section contains it.  */

static struct coff_link_hash_entry *
resolve_indirect_hash_entry(struct coff_link_hash_entry *h)
{
  while (h->root.type == bfd_link_hash_indirect
         || h->root.type == bfd_link_hash_warning)
    h = (struct coff_link_hash_entry *) h->root.u.i.link;
  return h;
}

static struct internal_syment *
get_native_symbol(asection *sec, struct coff_reloc_cookie *cookie)
{
  return &(cookie->symbols
           + obj_convert (sec->owner)[cookie->rel->r_symndx])->native->u.syment;
}

static asection *
_bfd_coff_gc_mark_rsec (struct bfd_link_info *info, asection *sec,
			coff_gc_mark_hook_fn gc_mark_hook,
			struct coff_reloc_cookie *cookie)
{
  struct coff_link_hash_entry *h;

  h = cookie->sym_hashes[cookie->rel->r_symndx];
  if (h != NULL)
    {
      h = resolve_indirect_hash_entry(h);
      return (*gc_mark_hook) (sec, info, cookie->rel, h, NULL);
    }

  return (*gc_mark_hook) (sec, info, cookie->rel, NULL,
                         get_native_symbol(sec, cookie));
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
    return true;
    
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

  if (!has_relocations(sec))
    return true;

  return process_section_relocations(info, sec, gc_mark_hook);
}

static bool
has_relocations(asection *sec)
{
  return (sec->flags & SEC_RELOC) != 0 && sec->reloc_count > 0;
}

static bool
process_section_relocations(struct bfd_link_info *info,
			    asection *sec,
			    coff_gc_mark_hook_fn gc_mark_hook)
{
  struct coff_reloc_cookie cookie;

  if (!init_reloc_cookie_for_section(&cookie, info, sec))
    return false;

  bool ret = mark_all_relocations(info, sec, gc_mark_hook, &cookie);
  fini_reloc_cookie_for_section(&cookie, sec);
  
  return ret;
}

static bool
mark_all_relocations(struct bfd_link_info *info,
		     asection *sec,
		     coff_gc_mark_hook_fn gc_mark_hook,
		     struct coff_reloc_cookie *cookie)
{
  for (; cookie->rel < cookie->relend; cookie->rel++)
    {
      if (!_bfd_coff_gc_mark_reloc(info, sec, gc_mark_hook, cookie))
	return false;
    }
  
  return true;
}

static bool
is_coff_flavour(bfd *ibfd)
{
    return bfd_get_flavour(ibfd) == bfd_target_coff_flavour;
}

static bool
is_linker_created_section(asection *isec)
{
    return (isec->flags & SEC_LINKER_CREATED) != 0;
}

static bool
is_debug_or_special_section(asection *isec)
{
    return (isec->flags & SEC_DEBUGGING) != 0 ||
           (isec->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0;
}

static bool
mark_linker_sections_and_check_kept(bfd *ibfd)
{
    asection *isec;
    bool some_kept = false;
    
    for (isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
        if (is_linker_created_section(isec))
            isec->gc_mark = 1;
        else if (isec->gc_mark)
            some_kept = true;
    }
    
    return some_kept;
}

static void
mark_debug_and_special_sections(bfd *ibfd)
{
    asection *isec;
    
    for (isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
        if (is_debug_or_special_section(isec))
            isec->gc_mark = 1;
    }
}

static void
process_bfd_sections(bfd *ibfd)
{
    if (!is_coff_flavour(ibfd))
        return;
    
    bool some_kept = mark_linker_sections_and_check_kept(ibfd);
    
    if (!some_kept)
        return;
    
    mark_debug_and_special_sections(ibfd);
}

static bool
_bfd_coff_gc_mark_extra_sections (struct bfd_link_info *info,
                                  coff_gc_mark_hook_fn mark_hook ATTRIBUTE_UNUSED)
{
    bfd *ibfd;
    
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
        process_bfd_sections(ibfd);
    }
    
    return true;
}

/* Sweep symbols in swept sections.  Called via coff_link_hash_traverse.  */

static bool
coff_gc_sweep_symbol (struct coff_link_hash_entry *h,
		      void *data ATTRIBUTE_UNUSED)
{
  if (h->root.type == bfd_link_hash_warning)
    h = (struct coff_link_hash_entry *) h->root.u.i.link;

  if (!should_hide_symbol(h))
    return true;

  hide_symbol(h);
  return true;
}

static bool
should_hide_symbol(struct coff_link_hash_entry *h)
{
  return is_defined_symbol(h) 
         && !h->root.u.def.section->gc_mark
         && !is_dynamic_section(h);
}

static bool
is_defined_symbol(struct coff_link_hash_entry *h)
{
  return h->root.type == bfd_link_hash_defined
         || h->root.type == bfd_link_hash_defweak;
}

static bool
is_dynamic_section(struct coff_link_hash_entry *h)
{
  return h->root.u.def.section->owner->flags & DYNAMIC;
}

static void
hide_symbol(struct coff_link_hash_entry *h)
{
  h->root.u.def.section = bfd_und_section_ptr;
  h->symbol_class = C_HIDDEN;
}

/* The sweep phase of garbage collection.  Remove all garbage sections.  */

typedef bool (*gc_sweep_hook_fn)
  (bfd *, struct bfd_link_info *, asection *, const struct internal_reloc *);

static inline bool
is_subsection (const char *str, const char *prefix)
{
  size_t n = strlen (prefix);
  if (strncmp (str, prefix, n) != 0)
    return false;
  if (str[n] == 0)
    return true;
  if (str[n] != '$')
    return false;
  return ISDIGIT (str[n + 1]) && str[n + 2] == 0;
}

static bool should_mark_section(asection *o)
{
    if ((o->flags & (SEC_DEBUGGING | SEC_LINKER_CREATED)) != 0)
        return true;
    
    if ((o->flags & (SEC_ALLOC | SEC_LOAD | SEC_RELOC)) == 0)
        return true;
    
    if (startswith(o->name, ".idata"))
        return true;
    
    if (startswith(o->name, ".pdata"))
        return true;
    
    if (startswith(o->name, ".xdata"))
        return true;
    
    if (is_subsection(o->name, ".didat"))
        return true;
    
    if (startswith(o->name, ".rsrc"))
        return true;
    
    return false;
}

static void mark_section_if_needed(asection *o)
{
    if (should_mark_section(o))
        o->gc_mark = 1;
}

static bool should_skip_section(asection *o)
{
    return o->gc_mark || (o->flags & SEC_EXCLUDE);
}

static void exclude_section(asection *o, bfd *sub, struct bfd_link_info *info)
{
    o->flags |= SEC_EXCLUDE;
    
    if (info->print_gc_sections && o->size != 0)
        _bfd_error_handler(_("removing unused section '%pA' in file '%pB'"), o, sub);
}

static void process_section(asection *o, bfd *sub, struct bfd_link_info *info)
{
    mark_section_if_needed(o);
    
    if (should_skip_section(o))
        return;
    
    exclude_section(o, sub, info);
}

static void process_coff_bfd(bfd *sub, struct bfd_link_info *info)
{
    asection *o;
    
    for (o = sub->sections; o != NULL; o = o->next)
        process_section(o, sub, info);
}

static bool coff_gc_sweep(bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
    bfd *sub;
    
    for (sub = info->input_bfds; sub != NULL; sub = sub->link.next)
    {
        if (bfd_get_flavour(sub) != bfd_target_coff_flavour)
            continue;
        
        process_coff_bfd(sub, info);
    }
    
    coff_link_hash_traverse(coff_hash_table(info), coff_gc_sweep_symbol, NULL);
    
    return true;
}

/* Keep all sections containing symbols undefined on the command-line,
   and the section containing the entry symbol.  */

static bool is_hash_entry_defined(struct coff_link_hash_entry *h)
{
    return h->root.type == bfd_link_hash_defined || 
           h->root.type == bfd_link_hash_defweak;
}

static bool should_keep_section(struct coff_link_hash_entry *h)
{
    return h != NULL && 
           is_hash_entry_defined(h) && 
           !bfd_is_abs_section(h->root.u.def.section);
}

static void mark_section_as_kept(struct coff_link_hash_entry *h)
{
    h->root.u.def.section->flags |= SEC_KEEP;
}

static void process_symbol(struct bfd_link_info *info, const char *name)
{
    struct coff_link_hash_entry *h;
    
    h = coff_link_hash_lookup(coff_hash_table(info), name,
                              false, false, false);
    
    if (should_keep_section(h))
        mark_section_as_kept(h);
}

static void
_bfd_coff_gc_keep(struct bfd_link_info *info)
{
    struct bfd_sym_chain *sym;
    
    for (sym = info->gc_sym_list; sym != NULL; sym = sym->next)
        process_symbol(info, sym->name);
}

/* Do mark and sweep of unused sections.  */

bool
bfd_coff_gc_sections (bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  bfd *sub;

#if 0
  const bfd_coff_backend_data *bed = coff_backend_info (abfd);

  if (!bed->can_gc_sections
      || !is_coff_hash_table (info->hash))
    {
      _bfd_error_handler(_("warning: gc-sections option ignored"));
      return true;
    }
#endif

  _bfd_coff_gc_keep (info);

  for (sub = info->input_bfds; sub != NULL; sub = sub->link.next)
    {
      if (!process_coff_sections (sub, info))
        return false;
    }

  _bfd_coff_gc_mark_extra_sections (info, _bfd_coff_gc_mark_hook);

  return coff_gc_sweep (abfd, info);
}

static bool
process_coff_sections (bfd *sub, struct bfd_link_info *info)
{
  asection *o;

  if (bfd_get_flavour (sub) != bfd_target_coff_flavour)
    return true;

  for (o = sub->sections; o != NULL; o = o->next)
    {
      if (!mark_section_if_needed (o, info))
        return false;
    }

  return true;
}

static bool
mark_section_if_needed (asection *o, struct bfd_link_info *info)
{
  if (!should_mark_section (o))
    return true;

  return _bfd_coff_gc_mark (info, o, _bfd_coff_gc_mark_hook);
}

static bool
should_mark_section (asection *o)
{
  if (o->gc_mark)
    return false;

  if ((o->flags & (SEC_EXCLUDE | SEC_KEEP)) == SEC_KEEP)
    return true;

  return is_special_section_name (o->name);
}

static bool
is_special_section_name (const char *name)
{
  return startswith (name, ".vectors")
      || startswith (name, ".ctors")
      || startswith (name, ".dtors");
}

/* Return name used to identify a comdat group.  */

const char *
bfd_coff_group_name (bfd *abfd, const asection *sec)
{
  struct coff_comdat_info *ci = bfd_coff_get_comdat_section (abfd, sec);
  return (ci != NULL) ? ci->name : NULL;
}

bool
_bfd_coff_free_cached_info (bfd *abfd)
{
  struct coff_tdata *tdata;

  if (!is_valid_coff_object(abfd))
    return _bfd_generic_bfd_free_cached_info (abfd);

  tdata = coff_data (abfd);
  if (tdata == NULL)
    return _bfd_generic_bfd_free_cached_info (abfd);

  cleanup_section_hashes(tdata);
  cleanup_pe_comdat_hash(abfd);
  cleanup_debug_info(abfd, tdata);
  _bfd_coff_free_symbols (abfd);
  cleanup_raw_syms(abfd);

  return _bfd_generic_bfd_free_cached_info (abfd);
}

static bool
is_valid_coff_object(bfd *abfd)
{
  bfd_format format;
  
  if (!bfd_family_coff (abfd))
    return false;
    
  format = bfd_get_format (abfd);
  return format == bfd_object || format == bfd_core;
}

static void
cleanup_section_hashes(struct coff_tdata *tdata)
{
  delete_hash_table(&tdata->section_by_index);
  delete_hash_table(&tdata->section_by_target_index);
}

static void
delete_hash_table(void **hash_table)
{
  if (*hash_table)
    {
      htab_delete (*hash_table);
      *hash_table = NULL;
    }
}

static void
cleanup_pe_comdat_hash(bfd *abfd)
{
  if (!obj_pe (abfd))
    return;
    
  if (pe_data (abfd)->comdat_hash)
    {
      htab_delete (pe_data (abfd)->comdat_hash);
      pe_data (abfd)->comdat_hash = NULL;
    }
}

static void
cleanup_debug_info(bfd *abfd, struct coff_tdata *tdata)
{
  _bfd_dwarf2_cleanup_debug_info (abfd, &tdata->dwarf2_find_line_info);
  _bfd_stab_cleanup (abfd, &tdata->line_info);
}

static void
cleanup_raw_syms(bfd *abfd)
{
  if (obj_coff_keep_raw_syms (abfd) || !obj_raw_syments (abfd))
    return;
    
  bfd_release (abfd, obj_raw_syments (abfd));
  obj_raw_syments (abfd) = NULL;
  obj_symbols (abfd) = NULL;
  obj_convert (abfd) = NULL;
}
