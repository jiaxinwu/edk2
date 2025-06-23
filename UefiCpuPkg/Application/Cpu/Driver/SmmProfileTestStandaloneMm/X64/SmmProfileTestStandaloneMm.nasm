;; @file
; This file provides assembly 64-bit memory reads/writes required for SMM Profile Test.
;
;  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
;  SPDX-License-Identifier: BSD-2-Clause-Patent
;
;;

SECTION .text

;-----------------------------------------------------------------------------
;
;  Section:     AsmReadMem64
;
;  Description: Read 64 bits from the Memory space.
;
;  @param[in] Address - Memory address.
;
;-----------------------------------------------------------------------------

;UINT64
;AsmReadMem64 (
;  IN  UINT64 Address
;  )
global ASM_PFX(AsmReadMem64)
ASM_PFX(AsmReadMem64):
   mov     rax, [rcx]         ;read
   ret
