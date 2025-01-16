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
  .datat :
  {
      *encryptiondata.o(.text)
  }
  .datad :
  {
      *encryptiondata.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _data_end = .;
  
  
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha256_start = .;
  .sha256t :
  {
      *sha256.o(.text)
  }
  .sha256d :
  {
      *sha256.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha256_end = .;
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha512_start = .;
  .sha512t :
  {
      *sha512.o(.text)
  }
  .sha512d :
  {
      *sha512.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _sha512_end = .;
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _des_start = .;
  .dest :
  {
      *des.o(.text)
  }
  .desd :
  {
      *des.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _des_end = .;


  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _chacha20_start = .;
  .chacha20t :
  {
      *chacha20.o(.text)
  }
  .chacha20d :
  {
      *chacha20.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _chacha20_end = .;
  
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _poly1305_start = .;
  .poly1305t :
  {
      *poly1305.o(.text)
  }
  .poly1305d :
  {
      *poly1305.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _poly1305_end = .;
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _aes_start = .;
  .aest :
  {
      *aes.o(.text)
  }
  .aesd :
  {
      *aes.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _aes_end = .;
  
    . = ALIGN(CONSTANT (MAXPAGESIZE));
  _aaa_start = .;
  .aaat :
  {
      *mybenchmark.o(.text)
  }
  .aaad :
  {
      *mybenchmark.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _aaa_end = .;

  /* MAGIC SECTIONS END */
