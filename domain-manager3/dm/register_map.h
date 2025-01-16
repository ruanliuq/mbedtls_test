enum CSRIndex
{
    CSR_USTATUS = 0x000,
    CSR_UIE = 0x004,
    CSR_UTVEC = 0x005,
    CSR_USCRATCH = 0x040,
    CSR_UEPC = 0x041,
    CSR_UCAUSE = 0x042,
    CSR_UTVAL = 0x043,
    CSR_UIP = 0x044,
    CSR_UPKRU = 0x048,
    CSR_FFLAGS = 0x001,
    CSR_FRM = 0x002,
    CSR_FCSR = 0x003,
    CSR_CYCLE = 0xC00,
    CSR_TIME = 0xC01,
    CSR_INSTRET = 0xC02,
    CSR_HPMCOUNTER03 = 0xC03,
    CSR_HPMCOUNTER04 = 0xC04,
    CSR_HPMCOUNTER05 = 0xC05,
    CSR_HPMCOUNTER06 = 0xC06,
    CSR_HPMCOUNTER07 = 0xC07,
    CSR_HPMCOUNTER08 = 0xC08,
    CSR_HPMCOUNTER09 = 0xC09,
    CSR_HPMCOUNTER10 = 0xC0A,
    CSR_HPMCOUNTER11 = 0xC0B,
    CSR_HPMCOUNTER12 = 0xC0C,
    CSR_HPMCOUNTER13 = 0xC0D,
    CSR_HPMCOUNTER14 = 0xC0E,
    CSR_HPMCOUNTER15 = 0xC0F,
    CSR_HPMCOUNTER16 = 0xC10,
    CSR_HPMCOUNTER17 = 0xC11,
    CSR_HPMCOUNTER18 = 0xC12,
    CSR_HPMCOUNTER19 = 0xC13,
    CSR_HPMCOUNTER20 = 0xC14,
    CSR_HPMCOUNTER21 = 0xC15,
    CSR_HPMCOUNTER22 = 0xC16,
    CSR_HPMCOUNTER23 = 0xC17,
    CSR_HPMCOUNTER24 = 0xC18,
    CSR_HPMCOUNTER25 = 0xC19,
    CSR_HPMCOUNTER26 = 0xC1A,
    CSR_HPMCOUNTER27 = 0xC1B,
    CSR_HPMCOUNTER28 = 0xC1C,
    CSR_HPMCOUNTER29 = 0xC1D,
    CSR_HPMCOUNTER30 = 0xC1E,
    CSR_HPMCOUNTER31 = 0xC1F,

    // rv32 only csr register begin
    CSR_CYCLEH = 0xC80,
    CSR_TIMEH = 0xC81,
    CSR_INSTRETH = 0xC82,
    CSR_HPMCOUNTER03H = 0xC83,
    CSR_HPMCOUNTER04H = 0xC84,
    CSR_HPMCOUNTER05H = 0xC85,
    CSR_HPMCOUNTER06H = 0xC86,
    CSR_HPMCOUNTER07H = 0xC87,
    CSR_HPMCOUNTER08H = 0xC88,
    CSR_HPMCOUNTER09H = 0xC89,
    CSR_HPMCOUNTER10H = 0xC8A,
    CSR_HPMCOUNTER11H = 0xC8B,
    CSR_HPMCOUNTER12H = 0xC8C,
    CSR_HPMCOUNTER13H = 0xC8D,
    CSR_HPMCOUNTER14H = 0xC8E,
    CSR_HPMCOUNTER15H = 0xC8F,
    CSR_HPMCOUNTER16H = 0xC90,
    CSR_HPMCOUNTER17H = 0xC91,
    CSR_HPMCOUNTER18H = 0xC92,
    CSR_HPMCOUNTER19H = 0xC93,
    CSR_HPMCOUNTER20H = 0xC94,
    CSR_HPMCOUNTER21H = 0xC95,
    CSR_HPMCOUNTER22H = 0xC96,
    CSR_HPMCOUNTER23H = 0xC97,
    CSR_HPMCOUNTER24H = 0xC98,
    CSR_HPMCOUNTER25H = 0xC99,
    CSR_HPMCOUNTER26H = 0xC9A,
    CSR_HPMCOUNTER27H = 0xC9B,
    CSR_HPMCOUNTER28H = 0xC9C,
    CSR_HPMCOUNTER29H = 0xC9D,
    CSR_HPMCOUNTER30H = 0xC9E,
    CSR_HPMCOUNTER31H = 0xC9F,
    // rv32 only csr register end

    CSR_SSTATUS = 0x100,
    CSR_SEDELEG = 0x102,
    CSR_SIDELEG = 0x103,
    CSR_SIE = 0x104,
    CSR_STVEC = 0x105,
    CSR_SCOUNTEREN = 0x106,
    CSR_SSCRATCH = 0x140,
    CSR_SEPC = 0x141,
    CSR_SCAUSE = 0x142,
    CSR_STVAL = 0x143,
    CSR_SIP = 0x144,
    CSR_SATP = 0x180,

    // custom register
    CSR_IRDI = 0xBC0,
    CSR_PIRDI = 0xBC1,

    CSR_MVENDORID = 0xF11,
    CSR_MARCHID = 0xF12,
    CSR_MIMPID = 0xF13,
    CSR_MHARTID = 0xF14,
    CSR_MSTATUS = 0x300,
    CSR_MISA = 0x301,
    CSR_MEDELEG = 0x302,
    CSR_MIDELEG = 0x303,
    CSR_MIE = 0x304,
    CSR_MTVEC = 0x305,
    CSR_MCOUNTEREN = 0x306,
    CSR_MSTATUSH = 0x310, // rv32 only
    CSR_MSCRATCH = 0x340,
    CSR_MEPC = 0x341,
    CSR_MCAUSE = 0x342,
    CSR_MTVAL = 0x343,
    CSR_MIP = 0x344,
    CSR_PMPCFG0 = 0x3A0,
    CSR_PMPCFG1 = 0x3A1, // pmpcfg1 rv32 only
    CSR_PMPCFG2 = 0x3A2,
    CSR_PMPCFG3 = 0x3A3,// pmpcfg3 rv32 only
    CSR_PMPADDR00 = 0x3B0,
    CSR_PMPADDR01 = 0x3B1,
    CSR_PMPADDR02 = 0x3B2,
    CSR_PMPADDR03 = 0x3B3,
    CSR_PMPADDR04 = 0x3B4,
    CSR_PMPADDR05 = 0x3B5,
    CSR_PMPADDR06 = 0x3B6,
    CSR_PMPADDR07 = 0x3B7,
    CSR_PMPADDR08 = 0x3B8,
    CSR_PMPADDR09 = 0x3B9,
    CSR_PMPADDR10 = 0x3BA,
    CSR_PMPADDR11 = 0x3BB,
    CSR_PMPADDR12 = 0x3BC,
    CSR_PMPADDR13 = 0x3BD,
    CSR_PMPADDR14 = 0x3BE,
    CSR_PMPADDR15 = 0x3BF,
    CSR_MCYCLE = 0xB00,
    CSR_MINSTRET = 0xB02,
    CSR_MHPMCOUNTER03 = 0xB03,
    CSR_MHPMCOUNTER04 = 0xB04,
    CSR_MHPMCOUNTER05 = 0xB05,
    CSR_MHPMCOUNTER06 = 0xB06,
    CSR_MHPMCOUNTER07 = 0xB07,
    CSR_MHPMCOUNTER08 = 0xB08,
    CSR_MHPMCOUNTER09 = 0xB09,
    CSR_MHPMCOUNTER10 = 0xB0A,
    CSR_MHPMCOUNTER11 = 0xB0B,
    CSR_MHPMCOUNTER12 = 0xB0C,
    CSR_MHPMCOUNTER13 = 0xB0D,
    CSR_MHPMCOUNTER14 = 0xB0E,
    CSR_MHPMCOUNTER15 = 0xB0F,
    CSR_MHPMCOUNTER16 = 0xB10,
    CSR_MHPMCOUNTER17 = 0xB11,
    CSR_MHPMCOUNTER18 = 0xB12,
    CSR_MHPMCOUNTER19 = 0xB13,
    CSR_MHPMCOUNTER20 = 0xB14,
    CSR_MHPMCOUNTER21 = 0xB15,
    CSR_MHPMCOUNTER22 = 0xB16,
    CSR_MHPMCOUNTER23 = 0xB17,
    CSR_MHPMCOUNTER24 = 0xB18,
    CSR_MHPMCOUNTER25 = 0xB19,
    CSR_MHPMCOUNTER26 = 0xB1A,
    CSR_MHPMCOUNTER27 = 0xB1B,
    CSR_MHPMCOUNTER28 = 0xB1C,
    CSR_MHPMCOUNTER29 = 0xB1D,
    CSR_MHPMCOUNTER30 = 0xB1E,
    CSR_MHPMCOUNTER31 = 0xB1F,

    // rv32 only csr register begin
    CSR_MCYCLEH = 0xB80,
    CSR_MINSTRETH = 0xB82,
    CSR_MHPMCOUNTER03H = 0xB83,
    CSR_MHPMCOUNTER04H = 0xB84,
    CSR_MHPMCOUNTER05H = 0xB85,
    CSR_MHPMCOUNTER06H = 0xB86,
    CSR_MHPMCOUNTER07H = 0xB87,
    CSR_MHPMCOUNTER08H = 0xB88,
    CSR_MHPMCOUNTER09H = 0xB89,
    CSR_MHPMCOUNTER10H = 0xB8A,
    CSR_MHPMCOUNTER11H = 0xB8B,
    CSR_MHPMCOUNTER12H = 0xB8C,
    CSR_MHPMCOUNTER13H = 0xB8D,
    CSR_MHPMCOUNTER14H = 0xB8E,
    CSR_MHPMCOUNTER15H = 0xB8F,
    CSR_MHPMCOUNTER16H = 0xB90,
    CSR_MHPMCOUNTER17H = 0xB91,
    CSR_MHPMCOUNTER18H = 0xB92,
    CSR_MHPMCOUNTER19H = 0xB93,
    CSR_MHPMCOUNTER20H = 0xB94,
    CSR_MHPMCOUNTER21H = 0xB95,
    CSR_MHPMCOUNTER22H = 0xB96,
    CSR_MHPMCOUNTER23H = 0xB97,
    CSR_MHPMCOUNTER24H = 0xB98,
    CSR_MHPMCOUNTER25H = 0xB99,
    CSR_MHPMCOUNTER26H = 0xB9A,
    CSR_MHPMCOUNTER27H = 0xB9B,
    CSR_MHPMCOUNTER28H = 0xB9C,
    CSR_MHPMCOUNTER29H = 0xB9D,
    CSR_MHPMCOUNTER30H = 0xB9E,
    CSR_MHPMCOUNTER31H = 0xB9F,
    // rv32 only csr register end

    CSR_MHPMEVENT03 = 0x323,
    CSR_MHPMEVENT04 = 0x324,
    CSR_MHPMEVENT05 = 0x325,
    CSR_MHPMEVENT06 = 0x326,
    CSR_MHPMEVENT07 = 0x327,
    CSR_MHPMEVENT08 = 0x328,
    CSR_MHPMEVENT09 = 0x329,
    CSR_MHPMEVENT10 = 0x32A,
    CSR_MHPMEVENT11 = 0x32B,
    CSR_MHPMEVENT12 = 0x32C,
    CSR_MHPMEVENT13 = 0x32D,
    CSR_MHPMEVENT14 = 0x32E,
    CSR_MHPMEVENT15 = 0x32F,
    CSR_MHPMEVENT16 = 0x330,
    CSR_MHPMEVENT17 = 0x331,
    CSR_MHPMEVENT18 = 0x332,
    CSR_MHPMEVENT19 = 0x333,
    CSR_MHPMEVENT20 = 0x334,
    CSR_MHPMEVENT21 = 0x335,
    CSR_MHPMEVENT22 = 0x336,
    CSR_MHPMEVENT23 = 0x337,
    CSR_MHPMEVENT24 = 0x338,
    CSR_MHPMEVENT25 = 0x339,
    CSR_MHPMEVENT26 = 0x33A,
    CSR_MHPMEVENT27 = 0x33B,
    CSR_MHPMEVENT28 = 0x33C,
    CSR_MHPMEVENT29 = 0x33D,
    CSR_MHPMEVENT30 = 0x33E,
    CSR_MHPMEVENT31 = 0x33F,

    CSR_TSELECT = 0x7A0,
    CSR_TDATA1 = 0x7A1,
    CSR_TDATA2 = 0x7A2,
    CSR_TDATA3 = 0x7A3,
    CSR_DCSR = 0x7B0,
    CSR_DPC = 0x7B1,
    CSR_DSCRATCH = 0x7B2
};