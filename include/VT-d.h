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
* @file		VT-d.h
* @section	Intel VT-d structures and constants
*/

#ifndef __INTEL_VTD_H__
#define __INTEL_VTD_H__

#include <ntddk.h>

#pragma pack(push, 1)

#define CAP_REG							0x8
#define EX_CAP_REG						0x10
#define GLOBAL_COMMAND_REG				0x18
#define GLOBAL_STATUS_REG				0x1c
#define ROOT_TABLE_ADDRESS_REG			0x20
#define CONTEXT_COMMAND_REG				0x28
 
typedef struct _R_CAP {
	UINT64 Number_Of_Domains_Supported		: 3;
	UINT64 Advanced_Fault_Logging			: 1;
	UINT64 Required_Write_Buffer_Flush		: 1;
	UINT64 Protected_Low_Memory_Region		: 1;
	UINT64 Protected_High_Memory_Region		: 1;
	UINT64 Caching_Mode						: 1;
	UINT64 Adjucted_Guest_Address_Width		: 5;
	UINT64 Reserved1						: 3;
	UINT64 Maximum_Guest_Address_Width		: 6;
	UINT64 Zero_Length_Read					: 1;
	UINT64 Reserved2						: 1;
	UINT64 Fault_Recording_Register_Offset	: 10;
	UINT64 SL_Large_Page_Support			: 4;
	UINT64 Reserved3						: 1;
	UINT64 Page_Selective_Invalidation		: 1;
	UINT64 Number_Of_Fault_Recording_Regs	: 8;
	UINT64 Maximum_Address_Max_Value		: 6;
	UINT64 Write_Draining					: 1;
	UINT64 Read_Draining					: 1;
	UINT64 FL_One_GB_Page_Support			: 1;
	UINT64 Reserved4						: 2;
	UINT64 Posted_Interrupts_Support		: 1;
	UINT64 Reserved5						: 4;
} R_CAP, *PR_CAP;

typedef struct _R_EXT_CAP {
	UINT64 Page_Walk_Coherency				: 1;
	UINT64 Queued_Invalidation_Support		: 1;
	UINT64 Device_TLB_Support				: 1;
	UINT64 Interrupt_Remapping_Support		: 1;
	UINT64 Extended_Interrupt_Mode			: 1;
	UINT64 Reserved1						: 1;
	UINT64 Pass_Through						: 1;
	UINT64 Snoop_Control					: 1;
	UINT64 IOTLB_Reg_Offset					: 10;
	UINT64 Reserved2						: 2;
	UINT64 Maximum_Handle_Mask_Value		: 4;
	UINT64 Extended_Context_Support			: 1;
	UINT64 Memory_Type_Support				: 1;
	UINT64 Nested_Translation_Support		: 1;
	UINT64 Deferred_Invalidate_Support		: 1;
	UINT64 Reserved3						: 1;
	UINT64 Page_Request_Support				: 1;
	UINT64 Execute_Request_Support			: 1;
	UINT64 Supervisor_Request_Support		: 1;
	UINT64 Reserved4						: 1;
	UINT64 No_Write_Flag_Support			: 1;
	UINT64 Extended_Access_Flag_Support		: 1;
	UINT64 PASID_Size_Support				: 5;
	UINT64 PASID_Support					: 1;
	UINT64 Device_TLB_Invalidation_Throttle : 1;
	UINT64 Page_Request_Drain_Support		: 1;
	UINT64 Reserved5						: 21;
} R_EXT_CAP, *PR_EXT_CAP;

typedef struct _R_GLOBAL_COMMAND
{
	UINT32	Reserved							: 23;
	UINT32	Compatibility_Format_Interrupt		: 1;
	UINT32	Set_Interrupt_Remap_Table_Pointer	: 1;
	UINT32	Enable_Interrupt_Remapping			: 1;
	UINT32	Enable_Queued_Invalidation			: 1;
	UINT32	Write_Buffer_Flush					: 1;
	UINT32	Enable_Advanced_Fault_Logging		: 1;
	UINT32	Set_Fault_Log						: 1;
	UINT32	Set_Root_Table_Pointer				: 1;
	UINT32	Enable_Translation					: 1;
} R_GLOBAL_COMMAND, *PR_GLOBAL_COMMAND;

typedef struct _R_GLOBAL_STATUS
{
	UINT32	Reserved								: 23;
	UINT32	Compatibility_Format_Interrupt_Status	: 1;
	UINT32	Interrupt_Remap_Table_Pointer_Status	: 1;
	UINT32	Interrupt_Remapping_Enable_Status		: 1;
	UINT32	Queued_Invalidation_Enable_Status		: 1;
	UINT32	Write_Buffer_Flush_Status				: 1;
	UINT32	Advanced_Fault_Logging_Status			: 1;
	UINT32	Fault_Log_Status						: 1;
	UINT32	Root_Table_Pointer_Status				: 1;
	UINT32	Transition_Enable_Status				: 1;
} R_GLOBAL_STATUS, *PR_GLOBAL_STATUS;

typedef struct _R_ROOT_TABLE_ADDRESS
{
	UINT64	Reserved : 11;
	UINT64	Type : 1;
	UINT64	Address : 52;
} R_ROOT_TABLE_ADDRESS, *PR_ROOT_TABLE_ADDRESS;

typedef struct _R_IOTLB {
	UINT64 Reserved1								: 32;
	UINT64 Domain_ID								: 16;
	UINT64 Drain_Writes								: 1;
	UINT64 Drain_Reads								: 1;
	UINT64 Reserved2								: 7;
	UINT64 IOTLB_Actual_Invalidation_Granularity	: 2;
	UINT64 Reserved3								: 1;
	UINT64 IOTLB_Invalidation_Request_Granularity	: 2;
	UINT64 Reserved4								: 1;
	UINT64 Invalidate_IOTLB							: 1;
} R_IOTLB, *PR_IOTLB;

typedef struct _R_CONTEXT_CMD {
	UINT64 Domain_ID								: 16;
	UINT64 Source_ID								: 16;
	UINT64 Function_Mask							: 2;
	UINT64 Reserved1								: 25;
	UINT64 Context_Actual_Invalidation_Granularity	: 2;
	UINT64 Context_Invalidation_Request_Granularity	: 2;
	UINT64 Invalidate_Context_Cache					: 1;
} R_CONTEXT_CMD, *PR_CONTEXT_CMD;

typedef struct _ROOT_ENTRY {
	UINT64 Present						: 1;
	UINT64 Reserved1					: 11;
	UINT64 Context_Table_Pointer		: 52;
	UINT64 Reserved2;
} ROOT_ENTRY, *PROOT_ENTRY;

typedef struct _EXTENDED_ROOT_ENTRY {
	UINT64 Lower_Present				: 1;
	UINT64 Reserved1					: 11;
	UINT64 Lower_Context_Table_Pointer	: 52;
	UINT64 Upper_Present				: 1;
	UINT64 Reserved2					: 11;
	UINT64 Upper_Context_Table_Pointer	: 52;
} EXTENDED_ROOT_ENTRY, *PEXTENDED_ROOT_ENTRY;

typedef struct _CONTEXT_ENTRY {
	UINT64 Present						: 1;
	UINT64 Fault_Processing_Disable		: 1;
	UINT64 Translation_Type				: 2;
	UINT64 Reserved1					: 8;
	UINT64 SL_Page_Translation_Pointer	: 52;
	UINT64 Address_Width				: 3;
	UINT64 Ignored						: 4;
	UINT64 Reserved2					: 1;
	UINT64 Domain_Identifier			: 16;
	UINT64 Reserved3					: 40;
} CONTEXT_ENTRY, *PCONTEXT_ENTRY;

typedef struct _EXTENDED_CONTEXT_ENTRY {
	UINT64 Present						: 1;
	UINT64 Fault_Processing_Disable		: 1;
	UINT64 Translation_Type				: 3;
	UINT64 Extended_Memory_Type			: 3;
	UINT64 Deferred_Interrupt_Enable	: 1;
	UINT64 Page_Request_Enable			: 1;
	UINT64 Nested_Translation_Enable	: 1;
	UINT64 PASID_Enable					: 1;
	UINT64 SL_Page_Translation_Pointer	: 52;
	UINT64 Address_Width				: 3;
	UINT64 Page_Global_Enable			: 1;
	UINT64 No_Execute_Enable			: 1;
	UINT64 Write_Protect_Enable			: 1;
	UINT64 Cache_Disable				: 1;
	UINT64 Extended_Memory_Type_Enable	: 1;
	UINT64 Domain_Identifier			: 16;
	UINT64 SMEP							: 1;
	UINT64 Extended_Accessed_Flag_Enable: 1;
	UINT64 Execute_Requests_Enable		: 1;
	UINT64 Second_Level_Execute_Enable  : 1;
	UINT64 Reserved1					: 4;
	UINT64 PAT							: 32;
	UINT64 PASID_Table_Size				: 4;
	UINT64 Reserved2					: 8;
	UINT64 PASID_Table_Pointer			: 52;
	UINT64 Reserved3					: 12;
	UINT64 PASID_State_Table_Pointer	: 52;
} EXTENDED_CONTEXT_ENTRY, *PEXTENDED_CONTEXT_ENTRY;

typedef struct _PASID_ENTRY {
	UINT64 Present						: 1;
	UINT64 Reserved1					: 2;
	UINT64 Page_Level_Write_Through		: 1;
	UINT64 Page_Level_Cache_Disable		: 1;
	UINT64 Reserved2					: 6;
	UINT64 Supervisor_Requests_Enable	: 1;
	UINT64 FL_Page_Translation_Pointer	: 52;
} PASID_ENTRY, *PPASID_ENTRY;

typedef struct _PASID_STATE_ENTRY {
	UINT64 Reserved1					: 32;
	UINT64 Active_Reference_Count		: 16;
	UINT64 Reserved2					: 15;
	UINT64 Deferred_Invalidate			: 1;
} PASID_STATE_ENTRY, *PPASID_STATE_ENTRY;

static_assert(sizeof(R_ROOT_TABLE_ADDRESS) == sizeof(UINT64), "R_ROOT_TABLE_ADDRESS structure size mismatch!");
static_assert(sizeof(R_GLOBAL_STATUS) == sizeof(UINT32), "R_GLOBAL_STATUS structure size mismatch!");
static_assert(sizeof(R_GLOBAL_COMMAND) == sizeof(UINT32), "R_GLOBAL_COMMAND structure size mismatch!");
static_assert(sizeof(R_CAP) == sizeof(UINT64), "R_CAP structure size mismatch!");
static_assert(sizeof(R_EXT_CAP) == sizeof(UINT64), "R_EXT_CAP structure size mismatch!");
static_assert(sizeof(R_IOTLB) == sizeof(UINT64), "R_IOTLB structure size mismatch!");
static_assert(sizeof(R_CONTEXT_CMD) == sizeof(UINT64), "R_CONTEXT_CMD structure size mismatch!");
static_assert(sizeof(ROOT_ENTRY) == 2 * sizeof(UINT64), "ROOT_ENTRY structure size mismatch!");
static_assert(sizeof(EXTENDED_ROOT_ENTRY) == 2 * sizeof(UINT64), "EXTENDED_ROOT_ENTRY structure size mismatch!");
static_assert(sizeof(CONTEXT_ENTRY) == 2 * sizeof(UINT64), "CONTEXT_ENTRY structure size mismatch!");
static_assert(sizeof(EXTENDED_CONTEXT_ENTRY) == 4 * sizeof(UINT64), "EXTENDED_CONTEXT_ENTRY structure size mismatch!");
static_assert(sizeof(PASID_ENTRY) == sizeof(UINT64), "PASID_ENTRY structure size mismatch!");
static_assert(sizeof(PASID_STATE_ENTRY) == sizeof(UINT64), "PASID_STATE_ENTRY structure size mismatch!");

#pragma pack(pop)

#endif /* __INTEL_VTD_H__ */
