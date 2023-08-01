/* Layout for the RISC-V 32 boards, used by the examples in this repository. */

MEMORY {
  /* Note that the SRAM address may need to be changed depending on
   * the kernel binary, check for the actual address of APP_MEMORY!
   * Can be found out with enabling the `debug_load_processes` feature
   * for TockOs!
   */
  FLASH (X) : ORIGIN = 0x20030000, LENGTH = 0xB0000
  RAM   (W) : ORIGIN = 0x10005294, LENGTH = 128K
}

/*
STACK_SIZE = 16384;
MPU_MIN_ALIGN = 8K;
*/

TBF_HEADER_SIZE = 0x60;
INCLUDE libtock_layout.ld
