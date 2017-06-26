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
* @file		Faults.h
* @section	Intel fault codes
*/

#ifndef __INTEL_FAULTS_H__
#define __INTEL_FAULTS_H__

// http://wiki.osdev.org/Exceptions
typedef enum _FAULT_CODE
{
	DE_FAULT = 0,		// Divide by zero Error #DE
	DB_FAULT = 1,		// Debug Fault/Trap #DB
	NMI_FAULT = 2,		// Non Maskable Interrupt
	BP_FAULT = 3,		// Breakpoint #BP
	OF_FAULT = 4,		// Overflow #OF
	BR_FAULT = 5,		// Bound Range Exceeded #BR
	UD_FAULT = 6,		// Invalid Opcode #UD
	NM_FAULT = 7,		// Device Not Available #NM
	DF_FAULT = 8,		// Double Fault #DF
	CSO_FAULT = 9,		// Coprocessor Segment Overrun Fault
	TS_FAULT = 10,		// Invalid TSS #TS
	NP_FAULT = 11,		// Segment Not Present #NP
	SS_FAULT = 12,		// Stack Segment Fault #SS
	GP_FAULT = 13,		// General Protection Fault #GP
	PF_FAULT = 14,		// Page Fault #PF
	// 15 Reserved
	MF_FAULT = 16,		// x87 Floating - Point Exception #MF
	AC_FAULT = 17,		// Alignment Check Fault #AC
	MC_FAULT = 18,		// Machine Check #MC
	XM_FAULT = 19,		// SIMD Floating - Point Exception #XM / #XF
	XF_FAULT = XM_FAULT,
	VE_FAULT = 20,		// Virtualization Exception #VE
	// 21 - 29 Reserved
	SX_FAULT = 30,		// Security Exception #SX
	// 31 Reserved
} FAULT_CODE, *PFAULT_CODE;

#endif /* __INTEL_FAULTS_H__ */
