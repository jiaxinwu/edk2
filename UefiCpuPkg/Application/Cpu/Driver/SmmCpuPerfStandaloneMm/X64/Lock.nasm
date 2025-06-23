;; @file
; Assembly code to Lock Perf test
;
; Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;;

    DEFAULT REL
    SECTION .text

%define LOCK_COMPARE_VALUE                      0
%define LOCK_EXCHANGE_VALUE                     0

;------------------------------------------------------------------------------
; VOID
; EFIAPI
; LockInc (
;   IN      volatile UINT32           *Value
;   );
;------------------------------------------------------------------------------
global ASM_PFX(LockInc)
ASM_PFX(LockInc):
    lock inc dword [rcx]
    ret

;------------------------------------------------------------------------------
; VOID
; EFIAPI
; LockXadd (
;   IN      volatile UINT32           *Value
;   );
;------------------------------------------------------------------------------
global ASM_PFX(LockXadd)
ASM_PFX(LockXadd):
    mov       eax, 1
    lock xadd dword [rcx], eax
    ret

;------------------------------------------------------------------------------
; VOID
; EFIAPI
; LockCmpxchg (
;   IN      volatile UINT32           *Value
;   );
;------------------------------------------------------------------------------
global ASM_PFX(LockCmpxchg)
ASM_PFX(LockCmpxchg):
    mov          edx, LOCK_EXCHANGE_VALUE
    mov          eax, LOCK_COMPARE_VALUE
    lock cmpxchg [rcx], edx
    ret
