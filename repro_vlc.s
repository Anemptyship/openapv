	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 26, 0	sdk_version 26, 2
	.globl	_test_8bit                      ; -- Begin function test_8bit
	.p2align	2
_test_8bit:                             ; @test_8bit
	.cfi_startproc
; %bb.0:
	ldr	w9, [x0, #24]
	ldr	w10, [x0]
	mov	w8, #32                         ; =0x20
LBB0_1:                                 ; =>This Inner Loop Header: Depth=1
	cbnz	w9, LBB0_3
; %bb.2:                                ;   in Loop: Header=BB0_1 Depth=1
	ldr	x9, [x0, #8]
	add	x10, x9, #1
	str	x10, [x0, #8]
	ldrb	w9, [x9]
	lsl	w10, w9, #24
	mov	w9, #8                          ; =0x8
LBB0_3:                                 ;   in Loop: Header=BB0_1 Depth=1
	lsl	w10, w10, #1
	str	w10, [x0]
	sub	w9, w9, #1
	str	w9, [x0, #24]
	subs	w8, w8, #1
	b.ne	LBB0_1
; %bb.4:
	ret
	.cfi_endproc
                                        ; -- End function
	.globl	_test_32bit                     ; -- Begin function test_32bit
	.p2align	2
_test_32bit:                            ; @test_32bit
	.cfi_startproc
; %bb.0:
	ldr	w10, [x0, #24]
	ldr	w9, [x0]
	mov	w8, #32                         ; =0x20
LBB1_1:                                 ; =>This Inner Loop Header: Depth=1
	cbnz	w10, LBB1_5
; %bb.2:                                ;   in Loop: Header=BB1_1 Depth=1
	ldp	x9, x11, [x0, #8]
	add	x10, x9, #4
	cmp	x10, x11
	b.ls	LBB1_4
; %bb.3:                                ;   in Loop: Header=BB1_1 Depth=1
	add	x10, x9, #1
	str	x10, [x0, #8]
	ldrb	w9, [x9]
	lsl	w9, w9, #24
	mov	w10, #8                         ; =0x8
	b	LBB1_5
LBB1_4:                                 ;   in Loop: Header=BB1_1 Depth=1
	ldr	w9, [x9]
	rev	w9, w9
	str	x10, [x0, #8]
	mov	w10, #32                        ; =0x20
LBB1_5:                                 ;   in Loop: Header=BB1_1 Depth=1
	lsl	w9, w9, #1
	str	w9, [x0]
	sub	w10, w10, #1
	str	w10, [x0, #24]
	subs	w8, w8, #1
	b.ne	LBB1_1
; %bb.6:
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
