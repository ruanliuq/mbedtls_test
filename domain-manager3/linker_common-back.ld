  /* MAGIC SECTIONS */
  /*
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .test1 :
  {
     _test1_start = .;
      *test1.o(*)
     _test1_end = .;
  }
  */
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .dm_d :
  {
      __start_dm_all = .;
      __start_dm_data = .;
      __start_dm_key = .;
      *(.dm_key)
      __stop_dm_key = .;
      *(.dm_data)
      /**(.dynbss)
      *(.bss .bss.* .gnu.linkonce.b.*)
      *(COMMON)*/

      . = ALIGN(CONSTANT (MAXPAGESIZE));
      __stop_dm_data = .;
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .dm_t :
  {
      __start_dm_code = .;
      __start_dm_utvec_table = .;
      *(.dm_utvec_table)
      __stop_dm_utvec_table = .;
      *(.dm)
      /* *(*) TODO: Currently all non-dm tagged symbols are in unprotected section (caught by the arch-specific linker script) */
      . = ALIGN(CONSTANT (MAXPAGESIZE));
      __stop_dm_code = .;
      __stop_dm_all = .;
  }

  
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _data_start = .;
  _datat_start = .;
  .datat :
  {
      *encryptiondata.o(.text)
      /* *encryptiondata_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _datat_end = .;
  _datad_start = .;
  .datad :
  {
      *encryptiondata.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _datad_end = .;
  _data_end = .;
  
  
  
  
  
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha256_start = .;
  _sha256t_start = .;
  .sha256t :
  {
      *sha256.o(.text)
      /* *sha256_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha256t_end = .;
  _sha256d_start = .;
  .sha256d :
  {
      *sha256.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha256d_end = .;
  _sha256_end = .;
  
  
  
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha512_start = .;
  _sha512t_start = .;
  .sha512t :
  {
      *sha512.o(.text)
      /* *sha512_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha512t_end = .;
  _sha512d_start = .;
  .sha512d :
  {
      *sha512.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha512d_end = .;
  _sha512_end = .;
  
  
  
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _des_start = .;
  _dest_start = .;
  .dest :
  {
      *des.o(.text)
      /* *des_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _dest_end = .;
  _desd_start = .;
  .desd :
  {
      *des.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _desd_end = .;
  _des_end = .;






  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _chacha20_start = .;
  _chacha20t_start = .;
  .chacha20t :
  {
      *chacha20.o(.text)
      /* *chacha20_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _chacha20t_end = .;
  _chacha20d_start = .;
  .chacha20d :
  {
      *chacha20.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _chacha20d_end = .;
  _chacha20_end = .;
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _poly1305_start = .;
  _poly1305t_start = .;
  .poly1305t :
  {
      *poly1305.o(.text)
      /* *poly1305_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _poly1305t_end = .;
  _poly1305d_start = .;
  .poly1305d :
  {
      *poly1305.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _poly1305d_end = .;
  _poly1305_end = .;

  /* MAGIC SECTIONS END */
