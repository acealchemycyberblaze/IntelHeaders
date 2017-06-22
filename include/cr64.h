/**
* @file		cr64.h
* @section	Intel x64 Control Registers
*/

#ifndef __INTEL_CR64_H__
#define __INTEL_CR64_H__

#include <ntddk.h>

// Figure 2-7. Control Registers
typedef union _CR0_REG
{
	UINT32 dwValue;
	struct {
		UINT32 pe : 1;			// 0 		protected mode enable
		UINT32 mp : 1;			// 1 		monitor co - processor
		UINT32 em : 1;			// 2 		emulation
		UINT32 ts : 1;			// 3 		task switched
		UINT32 et : 1;			// 4 		extension type
		UINT32 ne : 1;			// 5 		numeric error
		UINT32 reserved0 : 10;	// 6-15	
		UINT32 wp : 1;			// 16 		write protect
		UINT32 reserved1 : 1;	// 17	
		UINT32 am : 1;			// 18 		alignment mask
		UINT32 reserved2 : 10;	// 19-28
		UINT32 nw : 1;			// 29 		not- write through
		UINT32 cd : 1;			// 30 		cache disable
		UINT32 pg : 1;			// 31 		paging
	};
} CR0_REG, *PCR0_REG;
C_ASSERT(sizeof(UINT32) == sizeof(CR0_REG));

// Figure 2-7. Control Registers
typedef union _CR4_REG
{
	UINT32 dwValue;
	struct {
		UINT32 vme : 1;			// 0 		virtual 8086 mode extensions
		UINT32 pvi : 1;			// 1 		protected mode virtual interrupts
		UINT32 tsd : 1;			// 2 		time stamp disable
		UINT32 de : 1;			// 3 		debugging extensions
		UINT32 pse : 1;			// 4 		page size extension
		UINT32 pae : 1;			// 5 		physical address extension
		UINT32 mce : 1;			// 6 		machine check exception
		UINT32 pge : 1;			// 7 		page global enable
		UINT32 pce : 1;			// 8 		performance monitoring counter enable
		UINT32 osfxsr : 1;		// 9 		os support for fxsave and fxrstor instructions
		UINT32 osxmmexcpt : 1;	// 10 		os support for unmasked simd floating point exceptions
		UINT32 reserved0 : 2;	// 11-12
		UINT32 vmxe : 1;		// 13 		virtual machine extensions enable
		UINT32 smxe : 1;		// 14 		safer mode extensions enable
		UINT32 reserved1 : 2;	// 15-16
		UINT32 pcide : 1;		// 17 		pcid enable
		UINT32 osxsave : 1;		// 18 		xsave and processor extended states enable
		UINT32 reserved2 : 1;	// 19
		UINT32 smep : 1;		// 20 		supervisor mode executions protection enable
		UINT32 smap : 1;		// 21 		supervisor mode access protection enable
		UINT32 pke : 1;			// 22		associate each linear address with a protection 
								//			key (PKRU)
		UINT32 reserved3 : 9;	// 23-31
	};
} CR4_REG, *PCR4_REG;
C_ASSERT(sizeof(UINT32) == sizeof(CR4_REG));

typedef union _CR3_REG
{
	UINT64 qwValue;

	// Table 4-12. Use of CR3 with IA-32e Paging and CR4.PCIDE = 0
	struct {
		UINT64 reserved0 : 3;	// 0-2
		UINT64 pwt : 1;			// 3		Page-level Write-Through
		UINT64 pcd : 1;			// 4		Page-level Cache Disable 
		UINT64 reserved1 : 7;	// 5-11
		UINT64 Pml4 : 52;		// 12-63	PML4 table physical address
	} NOPCID;

	// Table 4-13. Use of CR3 with IA-32e Paging and CR4.PCIDE = 1
	struct {
		UINT64 pcid : 12;		// 5-11
		UINT64 Pml4 : 52;		// 12-63	PML4 table physical address
	} PCID;
} CR3_REG, *PCR3_REG;
C_ASSERT(sizeof(UINT64) == sizeof(CR3_REG));

#endif /* __INTEL_CR64_H__ */
