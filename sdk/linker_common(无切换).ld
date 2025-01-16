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
  _test2_start = .;
  .test2t :
  {
      *test2.o(.text)
      /* *test2_ecall.S(*) */
  }
  /* . = ALIGN(CONSTANT (MAXPAGESIZE));*/
  .test2d :
  {
      *test2.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test2_end = .;


  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3_start = .;
  _test3t_start = .;
  .test3t :
  {
      *test3.o(.text)
      /* *test3_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3t_end = .;
  _test3d_start = .;
  .test3d :
  {
      *test3.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3d_end = .;
  _test3_end = .;

  /* MAGIC SECTIONS END */
