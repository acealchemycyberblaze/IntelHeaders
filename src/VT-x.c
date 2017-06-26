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
* @file		VT-x.c
* @section	Intel VT-x structures, constants and utility functions and macros
*/

#include "VT-x.h"

// Use X-Macros to define the VM instruction error messages array
static LPCSTR g_VmInstructionErrorMessages[VM_INSTRUCTION_ERROR_MAX] = {
#define X(EnumName,EnumValue,ErrorMsg) ErrorMsg,
	VM_INSTRUCTION_ERRORS
#undef X
};

LPCSTR
__inline
VTX_GetVmInstructionErrorMsg(
	_In_ const VM_INSTRUCTION_ERROR eVmError
)
{
	return g_VmInstructionErrorMessages[eVmError];
}

VOID
__inline
VmxAdjustCr0(
	_Out_ PCR0_REG ptCr0
)
{
	LARGE_INTEGER tFixed0 = { 0 };
	LARGE_INTEGER tFixed1 = { 0 };

	NT_ASSERT(NULL != ptCr0);

	tFixed0.QuadPart = __readmsr(MSR_CODE_IA32_VMX_CR0_FIXED0);
	tFixed1.QuadPart = __readmsr(MSR_CODE_IA32_VMX_CR0_FIXED1);

	ptCr0->dwValue &= tFixed1.LowPart;
	ptCr0->dwValue |= tFixed0.LowPart;
}

VOID
__inline
VmxAdjustCr4(
	_Out_ PCR4_REG ptCr4
)
{
	LARGE_INTEGER tFixed0 = { 0 };
	LARGE_INTEGER tFixed1 = { 0 };

	NT_ASSERT(NULL != ptCr4);

	tFixed0.QuadPart = __readmsr(MSR_CODE_IA32_VMX_CR4_FIXED0);
	tFixed1.QuadPart = __readmsr(MSR_CODE_IA32_VMX_CR4_FIXED1);

	ptCr4->dwValue &= tFixed1.LowPart;
	ptCr4->dwValue |= tFixed0.LowPart;
}

VOID
__inline
VmxAdjustCtl(
	_In_	const UINT32	dwAdjustMsrCode,
	_Out_	PUINT32			pdwCtlValue
)
{
	LARGE_INTEGER tAdjustMsr = { 0 };

	NT_ASSERT(NULL != pdwCtlValue);

	tAdjustMsr.QuadPart = __readmsr(dwAdjustMsrCode);
	*pdwCtlValue &= tAdjustMsr.HighPart;
	*pdwCtlValue |= tAdjustMsr.LowPart;
}
