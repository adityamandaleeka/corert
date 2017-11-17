// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "common.h"
#include "daccess.h"

#define UNW_STEP_SUCCESS 1
#define UNW_STEP_END     0

////// fix paths
#include <libunwind.h>
#include "../../libunwind/src/config.h"
#include "../../libunwind/src/Registers.hpp"
#include "../../libunwind/src/AddressSpace.hpp"
#include "../../libunwind/src/UnwindCursor.hpp"

using libunwind::Registers_x86_64;
using libunwind::LocalAddressSpace;
using libunwind::CFI_Parser;
using libunwind::EHHeaderParser;
using libunwind::DwarfFDECache;
using libunwind::DwarfInstructions;
using libunwind::UnwindInfoSections;

#include "../regdisplay.h"
#include "UnwindHelpers.h"

// typedef LocalAddressSpace::pint_t pint_t;

LocalAddressSpace _addressSpace;
// __thread unw_proc_info_t  _info;

// template <typename R> // type of regs
// class SimplifiedUnwindCursor {
// public:
//     bool getInfoFromDwarfSection(pint_t pc,
//                                  const UnwindInfoSections &sects,
//                                  uint32_t fdeSectionOffsetHint);

//     #if _LIBUNWIND_SUPPORT_DWARF_UNWIND
//       compact_unwind_encoding_t dwarfEncoding() {
//         R dummy;
//         return dwarfEncoding(dummy);
//       }

//     #if defined(_LIBUNWIND_TARGET_X86_64)
//       compact_unwind_encoding_t dwarfEncoding(Registers_x86_64 &) {
//         return UNWIND_X86_64_MODE_DWARF;
//       }
//     #endif

//     #if defined(_LIBUNWIND_TARGET_I386)
//       compact_unwind_encoding_t dwarfEncoding(Registers_x86 &) {
//         return UNWIND_X86_MODE_DWARF;
//       }
//     #endif

//     #if defined(_LIBUNWIND_TARGET_AARCH64)
//       compact_unwind_encoding_t dwarfEncoding(Registers_arm64 &) {
//         return UNWIND_ARM64_MODE_DWARF;
//       }
//     #endif
//     #endif // _LIBUNWIND_SUPPORT_DWARF_UNWIND
// };

// template <typename R>
// bool SimplifiedUnwindCursor<R>::getInfoFromDwarfSection(pint_t pc,
//                                               const UnwindInfoSections &sects,
//                                               uint32_t fdeSectionOffsetHint) {
//   CFI_Parser<LocalAddressSpace>::FDE_Info fdeInfo;
//   CFI_Parser<LocalAddressSpace>::CIE_Info cieInfo;
//   bool foundFDE = false;
//   bool foundInCache = false;
//   // If compact encoding table gave offset into dwarf section, go directly there
//   if (fdeSectionOffsetHint != 0) {
//     foundFDE = CFI_Parser<LocalAddressSpace>::findFDE(_addressSpace, pc, sects.dwarf_section,
//                                     (uint32_t)sects.dwarf_section_length,
//                                     sects.dwarf_section + fdeSectionOffsetHint,
//                                     &fdeInfo, &cieInfo);
//   }
// #if _LIBUNWIND_SUPPORT_DWARF_INDEX
//   if (!foundFDE && (sects.dwarf_index_section != 0)) {
//     foundFDE = EHHeaderParser<LocalAddressSpace>::findFDE(
//         _addressSpace, pc, sects.dwarf_index_section,
//         (uint32_t)sects.dwarf_index_section_length, &fdeInfo, &cieInfo);
//   }
// #endif
//   if (!foundFDE) {
//     // otherwise, search cache of previously found FDEs.
//     pint_t cachedFDE = DwarfFDECache<LocalAddressSpace>::findFDE(sects.dso_base, pc);
//     if (cachedFDE != 0) {
//       foundFDE =
//           CFI_Parser<LocalAddressSpace>::findFDE(_addressSpace, pc, sects.dwarf_section,
//                                  (uint32_t)sects.dwarf_section_length,
//                                  cachedFDE, &fdeInfo, &cieInfo);
//       foundInCache = foundFDE;
//     }
//   }
//   if (!foundFDE) {
//     // Still not found, do full scan of __eh_frame section.
//     foundFDE = CFI_Parser<LocalAddressSpace>::findFDE(_addressSpace, pc, sects.dwarf_section,
//                                       (uint32_t)sects.dwarf_section_length, 0,
//                                       &fdeInfo, &cieInfo);
//   }
//   if (foundFDE) {
//     typename CFI_Parser<LocalAddressSpace>::PrologInfo prolog;
//     if (CFI_Parser<LocalAddressSpace>::parseFDEInstructions(_addressSpace, fdeInfo, cieInfo, pc,
//                                             &prolog)) {
//       // Save off parsed FDE info
//       _info.start_ip          = fdeInfo.pcStart;
//       _info.end_ip            = fdeInfo.pcEnd;
//       _info.lsda              = fdeInfo.lsda;
//       _info.handler           = cieInfo.personality;
//       _info.gp                = prolog.spExtraArgSize;
//       _info.flags             = 0;
//       _info.format            = dwarfEncoding();
//       _info.unwind_info       = fdeInfo.fdeStart;
//       _info.unwind_info_size  = (uint32_t)fdeInfo.fdeLength;
//       _info.extra             = (unw_word_t) sects.dso_base;

//       // Add to cache (to make next lookup faster) if we had no hint
//       // and there was no index.
//       if (!foundInCache && (fdeSectionOffsetHint == 0)) {
//   #if _LIBUNWIND_SUPPORT_DWARF_INDEX
//         if (sects.dwarf_index_section == 0)
//   #endif
//         DwarfFDECache<LocalAddressSpace>::add(sects.dso_base, fdeInfo.pcStart, fdeInfo.pcEnd,
//                               fdeInfo.fdeStart);
//       }
//       return true;
//     }
//   }
//   //_LIBUNWIND_DEBUG_LOG("can't find/use FDE for pc=0x%llX", (uint64_t)pc);
//   return false;
// }

#ifdef __APPLE__
    #include <mach-o/getsect.h>
    struct dyld_unwind_sections
    {
        const struct mach_header*   mh;
        const void*                 dwarf_section;
        uintptr_t                   dwarf_section_length;
        const void*                 compact_unwind_section;
        uintptr_t                   compact_unwind_section_length;
    };
#else 

/// these are used in libunwind
#if !defined(Elf_Half)
typedef ElfW(Half) Elf_Half;
#endif
#if !defined(Elf_Phdr)
typedef ElfW(Phdr) Elf_Phdr;
#endif

// Passed to the callback function called by dl_iterate_phdr
struct dl_iterate_cb_data
{
    UnwindInfoSections *sects;
    uintptr_t targetAddr;
};

// Callback called by dl_iterate_phdr. Locates unwind info sections for the target
// address.
static int LocateSectionsCallback(struct dl_phdr_info *info, size_t size, void *data)
{
    // info is a pointer to a structure containing information about the shared object
    //
    // struct dl_phdr_info {
    //     ElfW(Addr)        dlpi_addr;  /* Base address of object */
    //     const char       *dlpi_name;  /* (Null-terminated) name of
    //                                      object */
    //     const ElfW(Phdr) *dlpi_phdr;  /* Pointer to array of
    //                                      ELF program headers
    //                                      for this object */
    //     ElfW(Half)        dlpi_phnum; /* # of items in dlpi_phdr */
    // };

    // printf("Shared Object Name=%s (%d segments)\n", info->dlpi_name, info->dlpi_phnum);

    dl_iterate_cb_data* cbdata = static_cast<dl_iterate_cb_data*>(data);
    uintptr_t addrOfInterest = (uintptr_t)cbdata->targetAddr;

    size_t object_length;
    bool found_obj = false;
    bool found_hdr = false;

    // If the base address of the SO is past the address we care about, move on.
    if (info->dlpi_addr > addrOfInterest)
    {
        // printf("This SO is past our address of interest (%p).\n", addrOfInterest);
        return 0;
    }

    // typedef struct {
    //     Elf32_Word  p_type;    /* Segment type */
    //     Elf32_Off   p_offset;  /* Segment file offset */
    //     Elf32_Addr  p_vaddr;   /* Segment virtual address */
    //     Elf32_Addr  p_paddr;   /* Segment physical address */
    //     Elf32_Word  p_filesz;  /* Segment size in file */
    //     Elf32_Word  p_memsz;   /* Segment size in memory */
    //     Elf32_Word  p_flags;   /* Segment flags */
    //     Elf32_Word  p_align;   /* Segment alignment */
    // } Elf32_Phdr;

    // Iterate through the program headers for this SO
    for (Elf_Half i = 0; i < info->dlpi_phnum; i++)
    {
        const Elf_Phdr *phdr = &info->dlpi_phdr[i];

        if (phdr->p_type == PT_LOAD) // loadable entry. Loader loads all segments of this type
        {
            uintptr_t begin = info->dlpi_addr + phdr->p_vaddr; // this calculates the location of the header in virtual memory
            uintptr_t end = begin + phdr->p_memsz;

            if (addrOfInterest >= begin && addrOfInterest < end)
            {
                // printf("The section that overlaps our address of interest is %p - %p\n", begin, end);
                cbdata->sects->dso_base = begin;
                object_length = phdr->p_memsz;
                found_obj = true;
            }
        }
        else if (phdr->p_type == PT_GNU_EH_FRAME) // sorted table of unwind information
        {
            // This element specifies the location and size of the exception handling 
            // information as defined by the .eh_frame_hdr section.

            EHHeaderParser<LocalAddressSpace>::EHHeaderInfo hdrInfo;

            uintptr_t eh_frame_hdr_start = info->dlpi_addr + phdr->p_vaddr;
            cbdata->sects->dwarf_index_section = eh_frame_hdr_start;
            cbdata->sects->dwarf_index_section_length = phdr->p_memsz;

            EHHeaderParser<LocalAddressSpace> ehp;
            ehp.decodeEHHdr(_addressSpace, eh_frame_hdr_start, phdr->p_memsz, hdrInfo);

            cbdata->sects->dwarf_section = hdrInfo.eh_frame_ptr;
            found_hdr = true;
        }
    }

    return 0;
}
#endif

bool DoTheStep(uintptr_t pc, UnwindInfoSections uwInfoSections, REGDISPLAY *regs)
{
    // SimplifiedUnwindCursor<Registers_x86_64> uc; //////// make this cross arch

    libunwind::UnwindCursor<LocalAddressSpace, Registers_x86_64> uc(_addressSpace);

    bool retVal = uc.getInfoFromDwarfSection(pc, uwInfoSections, 0 /* fdeSectionOffsetHint */);
    if (!retVal)
    {
        printf("ZZZZZFAILED TO GET DWARF INFO!!!!!!!! PC: %p\n", pc);
        return false;
    }
    
    unw_proc_info_t procInfo;
    uc.getInfo(&procInfo);

    DwarfInstructions<LocalAddressSpace, REGDISPLAY> dwarfInst;

    int stepRet = dwarfInst.stepWithDwarf(_addressSpace, pc, procInfo.unwind_info, *regs);
    if (stepRet != 1 /* UNW_STEP_SUCCESS */)
    {
        printf("ZZZZZ STEP FAILED \n");
        return false;
    }

    /////this is done in UnwindCursorToRegDisplay as well
    regs->pIP = PTR_PCODE(regs->SP - sizeof(TADDR));

    return true;
}

UnwindInfoSections LocateUnwindSections(uintptr_t pc)
{
    UnwindInfoSections uwInfoSections;

#ifdef __APPLE__
    // On macOS, we can use a dyld function from libSystem in order
    // to find the unwind sections.

    libunwind::dyld_unwind_sections dyldInfo;

  if (libunwind::_dyld_find_unwind_sections((void *)pc, &dyldInfo))
    {
        uwInfoSections.dso_base                      = (uintptr_t)dyldInfo.mh;

        uwInfoSections.dwarf_section                 = (uintptr_t)dyldInfo.dwarf_section;
        uwInfoSections.dwarf_section_length          = dyldInfo.dwarf_section_length;

        uwInfoSections.compact_unwind_section        = (uintptr_t)dyldInfo.compact_unwind_section;
        uwInfoSections.compact_unwind_section_length = dyldInfo.compact_unwind_section_length;
    }
#else // __APPLE__

    dl_iterate_cb_data cb_data = {&uwInfoSections, pc };
    dl_iterate_phdr(LocateSectionsCallback, &cb_data);

#endif

    return uwInfoSections;
}

bool UnwindHelpers::StepFrame(uintptr_t pc, REGDISPLAY *regs)
{
    UnwindInfoSections uwInfoSections = LocateUnwindSections(pc);
    if (uwInfoSections.dwarf_section == NULL)
    {
        printf("ZZZZZZZ FAILED TO GET DWARF EH INFO!!!!!\n");
        return false;
    }

    return DoTheStep(pc, uwInfoSections, regs);
}
