// Bare-metal arm64 guest for the HVF VMM engine.
//
// Runs at EL1 with the MMU off. "Devices" are reached via MMIO to unmapped
// guest-physical addresses, which trap to the host (stage-2 data abort).
//
//   - prints a banner + "tick: N" lines to a PL011-style UART at 0x0900_0000
//   - at N==3 issues HVC with x0=1  -> host CHECKPOINT (snapshot + stop)
//   - after rehydration in a fresh VM, execution resumes right here and
//     continues ticking 4,5,6 (proving full CPU+RAM state was restored)
//   - at N==7 issues HVC with x0=0  -> host POWEROFF
//
// Calling convention notes: uses bl/ret (x30) only, single level deep, so no
// stack is required. x19 holds the persistent counter; x20 holds the UART base.

.global _start
.align 2
_start:
    movz x20, #0x0900, lsl #16        // UART base = 0x0900_0000
    mov  x19, #0                      // persistent tick counter

    adr  x1, banner
    bl   puts

loop:
    adr  x1, tickmsg
    bl   puts
    add  w0, w19, #48                 // ascii '0' + counter
    strb w0, [x20]                    // -> MMIO trap (UART data register)
    mov  w0, #10                      // '\n'
    strb w0, [x20]

    cmp  x19, #3                      // checkpoint exactly once, at tick 3
    b.ne 1f
    mov  x0, #1                       // x0=1 : CHECKPOINT request
    hvc  #0
1:
    add  x19, x19, #1
    cmp  x19, #7
    b.ge poweroff

    movz x9, #0x0008, lsl #16         // crude delay so output is watchable
2:  subs x9, x9, #1
    b.ne 2b
    b    loop

poweroff:
    mov  x0, #0                       // x0=0 : POWEROFF request
    hvc  #0
3:  b    3b                           // never reached

// puts(x1 = ptr to NUL-terminated string); clobbers w0, x1
puts:
4:  ldrb w0, [x1], #1
    cbz  w0, 5f
    strb w0, [x20]
    b    4b
5:  ret

.align 3
banner:  .asciz "=== arm64 guest booted under Apple Hypervisor.framework ===\n"
tickmsg: .asciz "tick: "
