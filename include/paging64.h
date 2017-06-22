/**
* MIT License
*
* Copyright (c) 2017 Viral Security Group
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* @file		paging64.h
* @section	Intel x64 Page Tables structures and constants
*			See Intel's: Software Developers Manual Vol 3A, Section 4.5 IA-32E PAGING
*/

#ifndef __INTEL_PAGING64_H__
#define __INTEL_PAGING64_H__

#include <ntddk.h>
#include <intrin.h>

#include "msr64.h"
#include "cr64.h"

#define PAGING64_PML4E_COUNT	512
#define PAGING64_PDPTE_COUNT	512
#define PAGING64_PDE_COUNT		512
#define PAGING64_PTE_COUNT		512

#define PAGE_SIZE_4KB	PAGE_SIZE
#define PAGE_SIZE_2MB	(0x1000 * 512)
#define PAGE_SIZE_1GB	(0x1000 * 512 * 512)

#define PAGE_SHIFT_1GB 30L // PAGE_SIZE_1GB == 1 << 30
#define PAGE_SHIFT_2MB 21L // PAGE_SIZE_2MB == 1 << 21
#define PAGE_SHIFT_4KB 12L // PAGE_SIZE_4KB == 1 << 12

//  The ROUND_TO_PAGES macro takes a size in bytes and rounds it up to a
//  multiple of the page size.
//  NOTE: This macro fails for values 0xFFFFFFFF - (PAGE_SIZE - 1).
#define ROUND_TO_PAGES_1GB(Size)  (((UINT64)(Size) + PAGE_SIZE_1GB - 1) & ~(PAGE_SIZE_1GB - 1))
#define ROUND_TO_PAGES_2MB(Size)  (((UINT64)(Size) + PAGE_SIZE_2MB - 1) & ~(PAGE_SIZE_2MB - 1))
#define ROUND_TO_PAGES_4KB(Size)  (((UINT64)(Size) + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1))

// The BYTES_TO_PAGES macro takes the size in bytes and calculates the
// number of pages required to contain the bytes.
#define BYTES_TO_PAGES_1GB(Size)  (((Size) >> PAGE_SHIFT_1GB) + \
                                  (((Size) & (PAGE_SIZE_1GB - 1)) != 0))
#define BYTES_TO_PAGES_2MB(Size)  (((Size) >> PAGE_SHIFT_2MB) + \
                                  (((Size) & (PAGE_SIZE_2MB - 1)) != 0))
#define BYTES_TO_PAGES_4KB(Size)  (((Size) >> PAGE_SHIFT_4KB) + \
                                  (((Size) & (PAGE_SIZE_4KB - 1)) != 0))
// The BYTE_OFFSET macro takes a virtual address and returns the byte offset
// of that address within the page.
#define BYTE_OFFSET_1GB(Va) ((UINT64)(Va) & (PAGE_SIZE_1GB - 1))
#define BYTE_OFFSET_2MB(Va) ((UINT64)(Va) & (PAGE_SIZE_2MB - 1))
#define BYTE_OFFSET_4KB(Va) ((UINT64)(Va) & (PAGE_SIZE_4KB - 1))

// The PAGE_ALIGN macro takes a virtual address and returns a page-aligned
// virtual address for that page.
#define PAGE_ALIGN_1GB(Va) ((VOID*)((UINT64)(Va) & ~(PAGE_SIZE_1GB - 1)))
#define PAGE_ALIGN_2MB(Va) ((VOID*)((UINT64)(Va) & ~(PAGE_SIZE_2MB - 1)))
#define PAGE_ALIGN_4KB(Va) ((VOID*)((UINT64)(Va) & ~(PAGE_SIZE_4KB - 1)))

// The ADDRESS_AND_SIZE_TO_SPAN_PAGES macro takes a virtual address and
// size and returns the number of pages spanned by the size.
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_1GB(Va,Size) \
    ((BYTE_OFFSET_1GB(Va) + ((UINT64) (Size)) + (PAGE_SIZE_1GB - 1)) >> PAGE_SHIFT_1GB)
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_2MB(Va,Size) \
    ((BYTE_OFFSET_2MB(Va) + ((UINT64) (Size)) + (PAGE_SIZE_2MB - 1)) >> PAGE_SHIFT_2MB)
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_4KB(Va,Size) \
    ((BYTE_OFFSET_4KB(Va) + ((UINT64) (Size)) + (PAGE_SIZE_4KB - 1)) >> PAGE_SHIFT_4KB)

typedef enum _PAGE_TYPE64 {
	PAGE_TYPE_FIRST = 0,
	PAGE_TYPE_1GB = PAGE_TYPE_FIRST,
	PAGE_TYPE_2MB,
	PAGE_TYPE_4KB,
	PAGE_TYPES_COUNT // Must be last!
} PAGE_TYPE64, *PPAGE_TYPE64;

typedef union _VA_ADDRESS64
{
	UINT64 qwValue;

	// Figure 4-8. Linear-Address Translation to a 4-KByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 12;
		UINT64 PteIndex : 9;
		UINT64 PdeIndex : 9;
		UINT64 PdpteIndex : 9;
		UINT64 Pml4eIndex : 9;
		UINT64 reserved0 : 12;
	} FourKb;
	// Figure 4-9. Linear-Address Translation to a 2-MByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 21;
		UINT64 PdeIndex : 9;
		UINT64 PdpteIndex : 9;
		UINT64 Pml4eIndex : 9;
		UINT64 reserved0 : 12;
	} TwoMb;
	// Figure 4-10. Linear-Address Translation to a 1-GByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 30;
		UINT64 PdpteIndex : 9;
		UINT64 Pml4eIndex : 9;
		UINT64 reserved0 : 12;
	} OneGb;
} VA_ADDRESS64, *PVA_ADDRESS64;
C_ASSERT(sizeof(UINT64) == sizeof(VA_ADDRESS64));

// Table 4-14. Format of an IA-32e PML4 Entry (PML4E) that References a Page-Directory-Pointer Table
typedef struct _PML4E64
{
	UINT64 p : 1;			// 0 Present
	UINT64 rw : 1;			// 1 Read/write; if 0, writes are not allowed
	UINT64 us : 1;			// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt : 1;			// 3 Page-level write-through
	UINT64 pcd : 1;			// 4 Page-level cache disable
	UINT64 a : 1;			// 5 Accessed; indicates whether software has accessed the page
	UINT64 ignored0 : 1;	// 6 Dirty; indicates whether software has written to the page
	UINT64 ps : 1;			// 7 Page-Size; must be 0
	UINT64 ignored1 : 4;	// 8-11
	UINT64 addr : 39;		// 12-50 Physical address that the entry points to
	UINT64 ignored1 : 12;	// 51-62
	UINT64 xd : 1;			// 63 If IA32_EFER.NXE = 1, execute-disable
} PML4E64, *PPML4E64;
C_ASSERT(sizeof(UINT64) == sizeof(PML4E64));

// Table 4-15. Format of an IA-32e Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page
typedef struct _PDPTE1G64
{
	UINT64 p : 1;			// 0 Present
	UINT64 rw : 1;			// 1 Read/write; if 0, writes are not allowed
	UINT64 us : 1;			// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt : 1;			// 3 Page-level write-through
	UINT64 pcd : 1;			// 4 Page-level cache disable
	UINT64 a : 1;			// 5 Accessed; indicates whether software has accessed the page
	UINT64 d : 1;			// 6 Dirty; indicates whether software has written to the page
	UINT64 ps : 1;			// 7 Page-Size; Must be 1 for 1GB pages
	UINT64 g : 1;			// 8 Global; if CR4.PGE = 1, determines whether the translation is global
	UINT64 ignored0 : 3;	// 9-11
	UINT64 pat : 1;			// 12 Page Attribute Table;
	UINT64 reserved0 : 17;	// 13-29
	UINT64 addr : 21;		// 30-50 Physical address that the entry points to
	UINT64 ignored1 : 8;	// 51-58
	UINT64 protkey : 4;		// 59-62 Protection key; if CR4.PKE = 1, determines the 
							// protection key of the page
	UINT64 xd : 1;			// 63 If IA32_EFER.NXE = 1, execute-disable
} PDPTE1G64, *PPDPTE1G64;
C_ASSERT(sizeof(UINT64) == sizeof(PDPTE1G64));

// Table 4-16. Format of an IA-32e Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory
typedef struct _PDPTE64
{
	UINT64 p			: 1;	// 0 Present
	UINT64 rw			: 1;	// 1 Read/write; if 0, writes are not allowed
	UINT64 us			: 1;	// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt			: 1;	// 3 Page-level write-through
	UINT64 pcd			: 1;	// 4 Page-level cache disable
	UINT64 a			: 1;	// 5 Accessed; indicates whether software has accessed the page
	UINT64 d			: 1;	// 6 Dirty; indicates whether software has written to the page
	UINT64 ps			: 1;	// 7 Page-Size; must be 0 to refernce PDE
	UINT64 reserved1	: 3;	// 8-11
	UINT64 addr			: 39;	// 12-50 Physical address that the entry points to
	UINT64 reserved2	: 12;	// 51-62
	UINT64 xd			: 1;	// 63 If IA32_EFER.NXE = 1, execute-disable
} PDPTE64, *PPDPTE64;
C_ASSERT(sizeof(UINT64) == sizeof(PDPTE64));

// Table 4-17. Format of an IA-32e Page-Directory Entry that Maps a 2-MByte Page
typedef struct _PDE2MB64
{
	UINT64 p : 1;			// 0 Present
	UINT64 rw : 1;			// 1 Read/write; if 0, writes are not allowed
	UINT64 us : 1;			// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt : 1;			// 3 Page-level write-through
	UINT64 pcd : 1;			// 4 Page-level cache disable
	UINT64 a : 1;			// 5 Accessed; indicates whether software has accessed the page
	UINT64 d : 1;			// 6 Dirty; indicates whether software has written to the page
	UINT64 ps : 1;			// 7 Page-Size; must be 1 for 2MB pages
	UINT64 g : 1;			// 8 Global; if CR4.PGE = 1, determines whether the translation is global
	UINT64 ignored0 : 3;	// 9-11
	UINT64 pat : 1;			// 12 Page Attribute Table;
	UINT64 reserved0 : 8;	// 13-20
	UINT64 addr : 30;		// 21-50 Physical address that the entry points to
	UINT64 ignored1 : 8;	// 51-58
	UINT64 protkey : 4;		// 59-62 Protection key; if CR4.PKE = 1, determines the 
							// protection key of the page
	UINT64 xd : 1;			// 63 If IA32_EFER.NXE = 1, execute-disable
} PDE2MB64, *PPDE2MB64;
C_ASSERT(sizeof(UINT64) == sizeof(PDE2MB64));

// Table 4-18. Format of an IA-32e Page-Directory Entry that References a Page Table
typedef struct _PDE64
{
	UINT64 p : 1;			// 0 Present
	UINT64 rw : 1;			// 1 Read/write; if 0, writes are not allowed
	UINT64 us : 1;			// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt : 1;			// 3 Page-level write-through
	UINT64 pcd : 1;			// 4 Page-level cache disable
	UINT64 a : 1;			// 5 Accessed; indicates whether software has accessed the page
	UINT64 reserved0 : 1;	// 6
	UINT64 ps : 1;			// 7 Page-Size; must be 0 to reference PTE
	UINT64 reserved1 : 4;	// 8-11
	UINT64 addr : 39;		// 12-50 Physical address that the entry points to
	UINT64 reserved2 : 12;	// 51-62
	UINT64 xd : 1;			// 63 If IA32_EFER.NXE = 1, execute-disable
} PDE64, *PPDE64;
C_ASSERT(sizeof(UINT64) == sizeof(PDE64));

// Table 4-19. Format of an IA-32e Page-Table Entry that Maps a 4-KByte Page
typedef struct _PTE64
{
	UINT64 p : 1;			// 0 Present
	UINT64 rw : 1;			// 1 Read/write; if 0, writes are not allowed
	UINT64 us : 1;			// 2 User/supervisor; if 0, user-mode access isn't allowed
	UINT64 pwt : 1;			// 3 Page-level write-through
	UINT64 pcd : 1;			// 4 Page-level cache disable
	UINT64 a : 1;			// 5 Accessed; indicates whether software has accessed the page
	UINT64 d : 1;			// 6 Dirty; indicates whether software has written to the page
	UINT64 pat : 1;			// 7 Page Attribute Table;
	UINT64 g : 1;			// 8 Global; if CR4.PGE = 1, determines whether the translation is global
	UINT64 ignored0 : 3;	// 9-11
	UINT64 addr : 39;		// 12-50 Physical address that the entry points to
	UINT64 ignored1 : 8;	// 51-58
	UINT64 protkey : 4;		// 59-62 Protection key; if CR4.PKE = 1, determines the 
							// protection key of the page
	UINT64 xd : 1;			// 63 If IA32_EFER.NXE = 1, execute-disable
} PTE64, *PPTE64;
C_ASSERT(sizeof(UINT64) == sizeof(PTE64));

// Page table example (sizeof(PAGE_TABLE64) is about ~2MB)
typedef struct _PAGE_TABLE64
{
	DECLSPEC_ALIGN(PAGE_SIZE) PML4E64 atPml4[PAGING64_PML4E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) PDPTE64 atPdpt[PAGING64_PDPTE_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) PDE64 atPde[PAGING64_PDE_COUNT][PAGING64_PTE_COUNT];
	UINT64 qwPhysicalAddress;
} PAGE_TABLE64, *PPAGE_TABLE64;

#endif  /* __INTEL_MSR64_H__ */
