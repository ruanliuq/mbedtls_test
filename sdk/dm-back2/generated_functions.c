#include <string.h>
#include "domain_key.h"


int getRegisterIndexByName(const char* name) {

    if (strcmp(name, "CSR_USTATUS") == 0) return 0;

    if (strcmp(name, "USTATUS") == 0) return 0;

    if (strcmp(name, "ustatus") == 0) return 0;

    if (strcmp(name, "CSR_UIE") == 0) return 4;

    if (strcmp(name, "UIE") == 0) return 4;

    if (strcmp(name, "uie") == 0) return 4;

    if (strcmp(name, "CSR_UTVEC") == 0) return 5;

    if (strcmp(name, "UTVEC") == 0) return 5;

    if (strcmp(name, "utvec") == 0) return 5;

    if (strcmp(name, "CSR_USCRATCH") == 0) return 64;

    if (strcmp(name, "USCRATCH") == 0) return 64;

    if (strcmp(name, "uscratch") == 0) return 64;

    if (strcmp(name, "CSR_UEPC") == 0) return 65;

    if (strcmp(name, "UEPC") == 0) return 65;

    if (strcmp(name, "uepc") == 0) return 65;

    if (strcmp(name, "CSR_UCAUSE") == 0) return 66;

    if (strcmp(name, "UCAUSE") == 0) return 66;

    if (strcmp(name, "ucause") == 0) return 66;

    if (strcmp(name, "CSR_UTVAL") == 0) return 67;

    if (strcmp(name, "UTVAL") == 0) return 67;

    if (strcmp(name, "utval") == 0) return 67;

    if (strcmp(name, "CSR_UIP") == 0) return 68;

    if (strcmp(name, "UIP") == 0) return 68;

    if (strcmp(name, "uip") == 0) return 68;

    if (strcmp(name, "CSR_UPKRU") == 0) return 72;

    if (strcmp(name, "UPKRU") == 0) return 72;

    if (strcmp(name, "upkru") == 0) return 72;

    if (strcmp(name, "CSR_FFLAGS") == 0) return 1;

    if (strcmp(name, "FFLAGS") == 0) return 1;

    if (strcmp(name, "fflags") == 0) return 1;

    if (strcmp(name, "CSR_FRM") == 0) return 2;

    if (strcmp(name, "FRM") == 0) return 2;

    if (strcmp(name, "frm") == 0) return 2;

    if (strcmp(name, "CSR_FCSR") == 0) return 3;

    if (strcmp(name, "FCSR") == 0) return 3;

    if (strcmp(name, "fcsr") == 0) return 3;

    if (strcmp(name, "CSR_CYCLE") == 0) return 3072;

    if (strcmp(name, "CYCLE") == 0) return 3072;

    if (strcmp(name, "cycle") == 0) return 3072;

    if (strcmp(name, "CSR_TIME") == 0) return 3073;

    if (strcmp(name, "TIME") == 0) return 3073;

    if (strcmp(name, "time") == 0) return 3073;

    if (strcmp(name, "CSR_INSTRET") == 0) return 3074;

    if (strcmp(name, "INSTRET") == 0) return 3074;

    if (strcmp(name, "instret") == 0) return 3074;

    if (strcmp(name, "CSR_HPMCOUNTER03") == 0) return 3075;

    if (strcmp(name, "HPMCOUNTER03") == 0) return 3075;

    if (strcmp(name, "hpmcounter03") == 0) return 3075;

    if (strcmp(name, "CSR_HPMCOUNTER04") == 0) return 3076;

    if (strcmp(name, "HPMCOUNTER04") == 0) return 3076;

    if (strcmp(name, "hpmcounter04") == 0) return 3076;

    if (strcmp(name, "CSR_HPMCOUNTER05") == 0) return 3077;

    if (strcmp(name, "HPMCOUNTER05") == 0) return 3077;

    if (strcmp(name, "hpmcounter05") == 0) return 3077;

    if (strcmp(name, "CSR_HPMCOUNTER06") == 0) return 3078;

    if (strcmp(name, "HPMCOUNTER06") == 0) return 3078;

    if (strcmp(name, "hpmcounter06") == 0) return 3078;

    if (strcmp(name, "CSR_HPMCOUNTER07") == 0) return 3079;

    if (strcmp(name, "HPMCOUNTER07") == 0) return 3079;

    if (strcmp(name, "hpmcounter07") == 0) return 3079;

    if (strcmp(name, "CSR_HPMCOUNTER08") == 0) return 3080;

    if (strcmp(name, "HPMCOUNTER08") == 0) return 3080;

    if (strcmp(name, "hpmcounter08") == 0) return 3080;

    if (strcmp(name, "CSR_HPMCOUNTER09") == 0) return 3081;

    if (strcmp(name, "HPMCOUNTER09") == 0) return 3081;

    if (strcmp(name, "hpmcounter09") == 0) return 3081;

    if (strcmp(name, "CSR_HPMCOUNTER10") == 0) return 3082;

    if (strcmp(name, "HPMCOUNTER10") == 0) return 3082;

    if (strcmp(name, "hpmcounter10") == 0) return 3082;

    if (strcmp(name, "CSR_HPMCOUNTER11") == 0) return 3083;

    if (strcmp(name, "HPMCOUNTER11") == 0) return 3083;

    if (strcmp(name, "hpmcounter11") == 0) return 3083;

    if (strcmp(name, "CSR_HPMCOUNTER12") == 0) return 3084;

    if (strcmp(name, "HPMCOUNTER12") == 0) return 3084;

    if (strcmp(name, "hpmcounter12") == 0) return 3084;

    if (strcmp(name, "CSR_HPMCOUNTER13") == 0) return 3085;

    if (strcmp(name, "HPMCOUNTER13") == 0) return 3085;

    if (strcmp(name, "hpmcounter13") == 0) return 3085;

    if (strcmp(name, "CSR_HPMCOUNTER14") == 0) return 3086;

    if (strcmp(name, "HPMCOUNTER14") == 0) return 3086;

    if (strcmp(name, "hpmcounter14") == 0) return 3086;

    if (strcmp(name, "CSR_HPMCOUNTER15") == 0) return 3087;

    if (strcmp(name, "HPMCOUNTER15") == 0) return 3087;

    if (strcmp(name, "hpmcounter15") == 0) return 3087;

    if (strcmp(name, "CSR_HPMCOUNTER16") == 0) return 3088;

    if (strcmp(name, "HPMCOUNTER16") == 0) return 3088;

    if (strcmp(name, "hpmcounter16") == 0) return 3088;

    if (strcmp(name, "CSR_HPMCOUNTER17") == 0) return 3089;

    if (strcmp(name, "HPMCOUNTER17") == 0) return 3089;

    if (strcmp(name, "hpmcounter17") == 0) return 3089;

    if (strcmp(name, "CSR_HPMCOUNTER18") == 0) return 3090;

    if (strcmp(name, "HPMCOUNTER18") == 0) return 3090;

    if (strcmp(name, "hpmcounter18") == 0) return 3090;

    if (strcmp(name, "CSR_HPMCOUNTER19") == 0) return 3091;

    if (strcmp(name, "HPMCOUNTER19") == 0) return 3091;

    if (strcmp(name, "hpmcounter19") == 0) return 3091;

    if (strcmp(name, "CSR_HPMCOUNTER20") == 0) return 3092;

    if (strcmp(name, "HPMCOUNTER20") == 0) return 3092;

    if (strcmp(name, "hpmcounter20") == 0) return 3092;

    if (strcmp(name, "CSR_HPMCOUNTER21") == 0) return 3093;

    if (strcmp(name, "HPMCOUNTER21") == 0) return 3093;

    if (strcmp(name, "hpmcounter21") == 0) return 3093;

    if (strcmp(name, "CSR_HPMCOUNTER22") == 0) return 3094;

    if (strcmp(name, "HPMCOUNTER22") == 0) return 3094;

    if (strcmp(name, "hpmcounter22") == 0) return 3094;

    if (strcmp(name, "CSR_HPMCOUNTER23") == 0) return 3095;

    if (strcmp(name, "HPMCOUNTER23") == 0) return 3095;

    if (strcmp(name, "hpmcounter23") == 0) return 3095;

    if (strcmp(name, "CSR_HPMCOUNTER24") == 0) return 3096;

    if (strcmp(name, "HPMCOUNTER24") == 0) return 3096;

    if (strcmp(name, "hpmcounter24") == 0) return 3096;

    if (strcmp(name, "CSR_HPMCOUNTER25") == 0) return 3097;

    if (strcmp(name, "HPMCOUNTER25") == 0) return 3097;

    if (strcmp(name, "hpmcounter25") == 0) return 3097;

    if (strcmp(name, "CSR_HPMCOUNTER26") == 0) return 3098;

    if (strcmp(name, "HPMCOUNTER26") == 0) return 3098;

    if (strcmp(name, "hpmcounter26") == 0) return 3098;

    if (strcmp(name, "CSR_HPMCOUNTER27") == 0) return 3099;

    if (strcmp(name, "HPMCOUNTER27") == 0) return 3099;

    if (strcmp(name, "hpmcounter27") == 0) return 3099;

    if (strcmp(name, "CSR_HPMCOUNTER28") == 0) return 3100;

    if (strcmp(name, "HPMCOUNTER28") == 0) return 3100;

    if (strcmp(name, "hpmcounter28") == 0) return 3100;

    if (strcmp(name, "CSR_HPMCOUNTER29") == 0) return 3101;

    if (strcmp(name, "HPMCOUNTER29") == 0) return 3101;

    if (strcmp(name, "hpmcounter29") == 0) return 3101;

    if (strcmp(name, "CSR_HPMCOUNTER30") == 0) return 3102;

    if (strcmp(name, "HPMCOUNTER30") == 0) return 3102;

    if (strcmp(name, "hpmcounter30") == 0) return 3102;

    if (strcmp(name, "CSR_HPMCOUNTER31") == 0) return 3103;

    if (strcmp(name, "HPMCOUNTER31") == 0) return 3103;

    if (strcmp(name, "hpmcounter31") == 0) return 3103;

    if (strcmp(name, "CSR_CYCLEH") == 0) return 3200;

    if (strcmp(name, "CYCLEH") == 0) return 3200;

    if (strcmp(name, "cycleh") == 0) return 3200;

    if (strcmp(name, "CSR_TIMEH") == 0) return 3201;

    if (strcmp(name, "TIMEH") == 0) return 3201;

    if (strcmp(name, "timeh") == 0) return 3201;

    if (strcmp(name, "CSR_INSTRETH") == 0) return 3202;

    if (strcmp(name, "INSTRETH") == 0) return 3202;

    if (strcmp(name, "instreth") == 0) return 3202;

    if (strcmp(name, "CSR_HPMCOUNTER03H") == 0) return 3203;

    if (strcmp(name, "HPMCOUNTER03H") == 0) return 3203;

    if (strcmp(name, "hpmcounter03h") == 0) return 3203;

    if (strcmp(name, "CSR_HPMCOUNTER04H") == 0) return 3204;

    if (strcmp(name, "HPMCOUNTER04H") == 0) return 3204;

    if (strcmp(name, "hpmcounter04h") == 0) return 3204;

    if (strcmp(name, "CSR_HPMCOUNTER05H") == 0) return 3205;

    if (strcmp(name, "HPMCOUNTER05H") == 0) return 3205;

    if (strcmp(name, "hpmcounter05h") == 0) return 3205;

    if (strcmp(name, "CSR_HPMCOUNTER06H") == 0) return 3206;

    if (strcmp(name, "HPMCOUNTER06H") == 0) return 3206;

    if (strcmp(name, "hpmcounter06h") == 0) return 3206;

    if (strcmp(name, "CSR_HPMCOUNTER07H") == 0) return 3207;

    if (strcmp(name, "HPMCOUNTER07H") == 0) return 3207;

    if (strcmp(name, "hpmcounter07h") == 0) return 3207;

    if (strcmp(name, "CSR_HPMCOUNTER08H") == 0) return 3208;

    if (strcmp(name, "HPMCOUNTER08H") == 0) return 3208;

    if (strcmp(name, "hpmcounter08h") == 0) return 3208;

    if (strcmp(name, "CSR_HPMCOUNTER09H") == 0) return 3209;

    if (strcmp(name, "HPMCOUNTER09H") == 0) return 3209;

    if (strcmp(name, "hpmcounter09h") == 0) return 3209;

    if (strcmp(name, "CSR_HPMCOUNTER10H") == 0) return 3210;

    if (strcmp(name, "HPMCOUNTER10H") == 0) return 3210;

    if (strcmp(name, "hpmcounter10h") == 0) return 3210;

    if (strcmp(name, "CSR_HPMCOUNTER11H") == 0) return 3211;

    if (strcmp(name, "HPMCOUNTER11H") == 0) return 3211;

    if (strcmp(name, "hpmcounter11h") == 0) return 3211;

    if (strcmp(name, "CSR_HPMCOUNTER12H") == 0) return 3212;

    if (strcmp(name, "HPMCOUNTER12H") == 0) return 3212;

    if (strcmp(name, "hpmcounter12h") == 0) return 3212;

    if (strcmp(name, "CSR_HPMCOUNTER13H") == 0) return 3213;

    if (strcmp(name, "HPMCOUNTER13H") == 0) return 3213;

    if (strcmp(name, "hpmcounter13h") == 0) return 3213;

    if (strcmp(name, "CSR_HPMCOUNTER14H") == 0) return 3214;

    if (strcmp(name, "HPMCOUNTER14H") == 0) return 3214;

    if (strcmp(name, "hpmcounter14h") == 0) return 3214;

    if (strcmp(name, "CSR_HPMCOUNTER15H") == 0) return 3215;

    if (strcmp(name, "HPMCOUNTER15H") == 0) return 3215;

    if (strcmp(name, "hpmcounter15h") == 0) return 3215;

    if (strcmp(name, "CSR_HPMCOUNTER16H") == 0) return 3216;

    if (strcmp(name, "HPMCOUNTER16H") == 0) return 3216;

    if (strcmp(name, "hpmcounter16h") == 0) return 3216;

    if (strcmp(name, "CSR_HPMCOUNTER17H") == 0) return 3217;

    if (strcmp(name, "HPMCOUNTER17H") == 0) return 3217;

    if (strcmp(name, "hpmcounter17h") == 0) return 3217;

    if (strcmp(name, "CSR_HPMCOUNTER18H") == 0) return 3218;

    if (strcmp(name, "HPMCOUNTER18H") == 0) return 3218;

    if (strcmp(name, "hpmcounter18h") == 0) return 3218;

    if (strcmp(name, "CSR_HPMCOUNTER19H") == 0) return 3219;

    if (strcmp(name, "HPMCOUNTER19H") == 0) return 3219;

    if (strcmp(name, "hpmcounter19h") == 0) return 3219;

    if (strcmp(name, "CSR_HPMCOUNTER20H") == 0) return 3220;

    if (strcmp(name, "HPMCOUNTER20H") == 0) return 3220;

    if (strcmp(name, "hpmcounter20h") == 0) return 3220;

    if (strcmp(name, "CSR_HPMCOUNTER21H") == 0) return 3221;

    if (strcmp(name, "HPMCOUNTER21H") == 0) return 3221;

    if (strcmp(name, "hpmcounter21h") == 0) return 3221;

    if (strcmp(name, "CSR_HPMCOUNTER22H") == 0) return 3222;

    if (strcmp(name, "HPMCOUNTER22H") == 0) return 3222;

    if (strcmp(name, "hpmcounter22h") == 0) return 3222;

    if (strcmp(name, "CSR_HPMCOUNTER23H") == 0) return 3223;

    if (strcmp(name, "HPMCOUNTER23H") == 0) return 3223;

    if (strcmp(name, "hpmcounter23h") == 0) return 3223;

    if (strcmp(name, "CSR_HPMCOUNTER24H") == 0) return 3224;

    if (strcmp(name, "HPMCOUNTER24H") == 0) return 3224;

    if (strcmp(name, "hpmcounter24h") == 0) return 3224;

    if (strcmp(name, "CSR_HPMCOUNTER25H") == 0) return 3225;

    if (strcmp(name, "HPMCOUNTER25H") == 0) return 3225;

    if (strcmp(name, "hpmcounter25h") == 0) return 3225;

    if (strcmp(name, "CSR_HPMCOUNTER26H") == 0) return 3226;

    if (strcmp(name, "HPMCOUNTER26H") == 0) return 3226;

    if (strcmp(name, "hpmcounter26h") == 0) return 3226;

    if (strcmp(name, "CSR_HPMCOUNTER27H") == 0) return 3227;

    if (strcmp(name, "HPMCOUNTER27H") == 0) return 3227;

    if (strcmp(name, "hpmcounter27h") == 0) return 3227;

    if (strcmp(name, "CSR_HPMCOUNTER28H") == 0) return 3228;

    if (strcmp(name, "HPMCOUNTER28H") == 0) return 3228;

    if (strcmp(name, "hpmcounter28h") == 0) return 3228;

    if (strcmp(name, "CSR_HPMCOUNTER29H") == 0) return 3229;

    if (strcmp(name, "HPMCOUNTER29H") == 0) return 3229;

    if (strcmp(name, "hpmcounter29h") == 0) return 3229;

    if (strcmp(name, "CSR_HPMCOUNTER30H") == 0) return 3230;

    if (strcmp(name, "HPMCOUNTER30H") == 0) return 3230;

    if (strcmp(name, "hpmcounter30h") == 0) return 3230;

    if (strcmp(name, "CSR_HPMCOUNTER31H") == 0) return 3231;

    if (strcmp(name, "HPMCOUNTER31H") == 0) return 3231;

    if (strcmp(name, "hpmcounter31h") == 0) return 3231;

    if (strcmp(name, "CSR_SSTATUS") == 0) return 256;

    if (strcmp(name, "SSTATUS") == 0) return 256;

    if (strcmp(name, "sstatus") == 0) return 256;

    if (strcmp(name, "CSR_SEDELEG") == 0) return 258;

    if (strcmp(name, "SEDELEG") == 0) return 258;

    if (strcmp(name, "sedeleg") == 0) return 258;

    if (strcmp(name, "CSR_SIDELEG") == 0) return 259;

    if (strcmp(name, "SIDELEG") == 0) return 259;

    if (strcmp(name, "sideleg") == 0) return 259;

    if (strcmp(name, "CSR_SIE") == 0) return 260;

    if (strcmp(name, "SIE") == 0) return 260;

    if (strcmp(name, "sie") == 0) return 260;

    if (strcmp(name, "CSR_STVEC") == 0) return 261;

    if (strcmp(name, "STVEC") == 0) return 261;

    if (strcmp(name, "stvec") == 0) return 261;

    if (strcmp(name, "CSR_SCOUNTEREN") == 0) return 262;

    if (strcmp(name, "SCOUNTEREN") == 0) return 262;

    if (strcmp(name, "scounteren") == 0) return 262;

    if (strcmp(name, "CSR_SSCRATCH") == 0) return 320;

    if (strcmp(name, "SSCRATCH") == 0) return 320;

    if (strcmp(name, "sscratch") == 0) return 320;

    if (strcmp(name, "CSR_SEPC") == 0) return 321;

    if (strcmp(name, "SEPC") == 0) return 321;

    if (strcmp(name, "sepc") == 0) return 321;

    if (strcmp(name, "CSR_SCAUSE") == 0) return 322;

    if (strcmp(name, "SCAUSE") == 0) return 322;

    if (strcmp(name, "scause") == 0) return 322;

    if (strcmp(name, "CSR_STVAL") == 0) return 323;

    if (strcmp(name, "STVAL") == 0) return 323;

    if (strcmp(name, "stval") == 0) return 323;

    if (strcmp(name, "CSR_SIP") == 0) return 324;

    if (strcmp(name, "SIP") == 0) return 324;

    if (strcmp(name, "sip") == 0) return 324;

    if (strcmp(name, "CSR_SATP") == 0) return 384;

    if (strcmp(name, "SATP") == 0) return 384;

    if (strcmp(name, "satp") == 0) return 384;

    if (strcmp(name, "CSR_IRDI") == 0) return 3008;

    if (strcmp(name, "IRDI") == 0) return 3008;

    if (strcmp(name, "irdi") == 0) return 3008;

    if (strcmp(name, "CSR_PIRDI") == 0) return 3009;

    if (strcmp(name, "PIRDI") == 0) return 3009;

    if (strcmp(name, "pirdi") == 0) return 3009;

    if (strcmp(name, "CSR_MVENDORID") == 0) return 3857;

    if (strcmp(name, "MVENDORID") == 0) return 3857;

    if (strcmp(name, "mvendorid") == 0) return 3857;

    if (strcmp(name, "CSR_MARCHID") == 0) return 3858;

    if (strcmp(name, "MARCHID") == 0) return 3858;

    if (strcmp(name, "marchid") == 0) return 3858;

    if (strcmp(name, "CSR_MIMPID") == 0) return 3859;

    if (strcmp(name, "MIMPID") == 0) return 3859;

    if (strcmp(name, "mimpid") == 0) return 3859;

    if (strcmp(name, "CSR_MHARTID") == 0) return 3860;

    if (strcmp(name, "MHARTID") == 0) return 3860;

    if (strcmp(name, "mhartid") == 0) return 3860;

    if (strcmp(name, "CSR_MSTATUS") == 0) return 768;

    if (strcmp(name, "MSTATUS") == 0) return 768;

    if (strcmp(name, "mstatus") == 0) return 768;

    if (strcmp(name, "CSR_MISA") == 0) return 769;

    if (strcmp(name, "MISA") == 0) return 769;

    if (strcmp(name, "misa") == 0) return 769;

    if (strcmp(name, "CSR_MEDELEG") == 0) return 770;

    if (strcmp(name, "MEDELEG") == 0) return 770;

    if (strcmp(name, "medeleg") == 0) return 770;

    if (strcmp(name, "CSR_MIDELEG") == 0) return 771;

    if (strcmp(name, "MIDELEG") == 0) return 771;

    if (strcmp(name, "mideleg") == 0) return 771;

    if (strcmp(name, "CSR_MIE") == 0) return 772;

    if (strcmp(name, "MIE") == 0) return 772;

    if (strcmp(name, "mie") == 0) return 772;

    if (strcmp(name, "CSR_MTVEC") == 0) return 773;

    if (strcmp(name, "MTVEC") == 0) return 773;

    if (strcmp(name, "mtvec") == 0) return 773;

    if (strcmp(name, "CSR_MCOUNTEREN") == 0) return 774;

    if (strcmp(name, "MCOUNTEREN") == 0) return 774;

    if (strcmp(name, "mcounteren") == 0) return 774;

    if (strcmp(name, "CSR_MSTATUSH") == 0) return 784;

    if (strcmp(name, "MSTATUSH") == 0) return 784;

    if (strcmp(name, "mstatush") == 0) return 784;

    if (strcmp(name, "CSR_MSCRATCH") == 0) return 832;

    if (strcmp(name, "MSCRATCH") == 0) return 832;

    if (strcmp(name, "mscratch") == 0) return 832;

    if (strcmp(name, "CSR_MEPC") == 0) return 833;

    if (strcmp(name, "MEPC") == 0) return 833;

    if (strcmp(name, "mepc") == 0) return 833;

    if (strcmp(name, "CSR_MCAUSE") == 0) return 834;

    if (strcmp(name, "MCAUSE") == 0) return 834;

    if (strcmp(name, "mcause") == 0) return 834;

    if (strcmp(name, "CSR_MTVAL") == 0) return 835;

    if (strcmp(name, "MTVAL") == 0) return 835;

    if (strcmp(name, "mtval") == 0) return 835;

    if (strcmp(name, "CSR_MIP") == 0) return 836;

    if (strcmp(name, "MIP") == 0) return 836;

    if (strcmp(name, "mip") == 0) return 836;

    if (strcmp(name, "CSR_PMPCFG0") == 0) return 928;

    if (strcmp(name, "PMPCFG0") == 0) return 928;

    if (strcmp(name, "pmpcfg0") == 0) return 928;

    if (strcmp(name, "CSR_PMPCFG1") == 0) return 929;

    if (strcmp(name, "PMPCFG1") == 0) return 929;

    if (strcmp(name, "pmpcfg1") == 0) return 929;

    if (strcmp(name, "CSR_PMPCFG2") == 0) return 930;

    if (strcmp(name, "PMPCFG2") == 0) return 930;

    if (strcmp(name, "pmpcfg2") == 0) return 930;

    if (strcmp(name, "CSR_PMPCFG3") == 0) return 931;

    if (strcmp(name, "PMPCFG3") == 0) return 931;

    if (strcmp(name, "pmpcfg3") == 0) return 931;

    if (strcmp(name, "CSR_PMPADDR00") == 0) return 944;

    if (strcmp(name, "PMPADDR00") == 0) return 944;

    if (strcmp(name, "pmpaddr00") == 0) return 944;

    if (strcmp(name, "CSR_PMPADDR01") == 0) return 945;

    if (strcmp(name, "PMPADDR01") == 0) return 945;

    if (strcmp(name, "pmpaddr01") == 0) return 945;

    if (strcmp(name, "CSR_PMPADDR02") == 0) return 946;

    if (strcmp(name, "PMPADDR02") == 0) return 946;

    if (strcmp(name, "pmpaddr02") == 0) return 946;

    if (strcmp(name, "CSR_PMPADDR03") == 0) return 947;

    if (strcmp(name, "PMPADDR03") == 0) return 947;

    if (strcmp(name, "pmpaddr03") == 0) return 947;

    if (strcmp(name, "CSR_PMPADDR04") == 0) return 948;

    if (strcmp(name, "PMPADDR04") == 0) return 948;

    if (strcmp(name, "pmpaddr04") == 0) return 948;

    if (strcmp(name, "CSR_PMPADDR05") == 0) return 949;

    if (strcmp(name, "PMPADDR05") == 0) return 949;

    if (strcmp(name, "pmpaddr05") == 0) return 949;

    if (strcmp(name, "CSR_PMPADDR06") == 0) return 950;

    if (strcmp(name, "PMPADDR06") == 0) return 950;

    if (strcmp(name, "pmpaddr06") == 0) return 950;

    if (strcmp(name, "CSR_PMPADDR07") == 0) return 951;

    if (strcmp(name, "PMPADDR07") == 0) return 951;

    if (strcmp(name, "pmpaddr07") == 0) return 951;

    if (strcmp(name, "CSR_PMPADDR08") == 0) return 952;

    if (strcmp(name, "PMPADDR08") == 0) return 952;

    if (strcmp(name, "pmpaddr08") == 0) return 952;

    if (strcmp(name, "CSR_PMPADDR09") == 0) return 953;

    if (strcmp(name, "PMPADDR09") == 0) return 953;

    if (strcmp(name, "pmpaddr09") == 0) return 953;

    if (strcmp(name, "CSR_PMPADDR10") == 0) return 954;

    if (strcmp(name, "PMPADDR10") == 0) return 954;

    if (strcmp(name, "pmpaddr10") == 0) return 954;

    if (strcmp(name, "CSR_PMPADDR11") == 0) return 955;

    if (strcmp(name, "PMPADDR11") == 0) return 955;

    if (strcmp(name, "pmpaddr11") == 0) return 955;

    if (strcmp(name, "CSR_PMPADDR12") == 0) return 956;

    if (strcmp(name, "PMPADDR12") == 0) return 956;

    if (strcmp(name, "pmpaddr12") == 0) return 956;

    if (strcmp(name, "CSR_PMPADDR13") == 0) return 957;

    if (strcmp(name, "PMPADDR13") == 0) return 957;

    if (strcmp(name, "pmpaddr13") == 0) return 957;

    if (strcmp(name, "CSR_PMPADDR14") == 0) return 958;

    if (strcmp(name, "PMPADDR14") == 0) return 958;

    if (strcmp(name, "pmpaddr14") == 0) return 958;

    if (strcmp(name, "CSR_PMPADDR15") == 0) return 959;

    if (strcmp(name, "PMPADDR15") == 0) return 959;

    if (strcmp(name, "pmpaddr15") == 0) return 959;

    if (strcmp(name, "CSR_MCYCLE") == 0) return 2816;

    if (strcmp(name, "MCYCLE") == 0) return 2816;

    if (strcmp(name, "mcycle") == 0) return 2816;

    if (strcmp(name, "CSR_MINSTRET") == 0) return 2818;

    if (strcmp(name, "MINSTRET") == 0) return 2818;

    if (strcmp(name, "minstret") == 0) return 2818;

    if (strcmp(name, "CSR_MHPMCOUNTER03") == 0) return 2819;

    if (strcmp(name, "MHPMCOUNTER03") == 0) return 2819;

    if (strcmp(name, "mhpmcounter03") == 0) return 2819;

    if (strcmp(name, "CSR_MHPMCOUNTER04") == 0) return 2820;

    if (strcmp(name, "MHPMCOUNTER04") == 0) return 2820;

    if (strcmp(name, "mhpmcounter04") == 0) return 2820;

    if (strcmp(name, "CSR_MHPMCOUNTER05") == 0) return 2821;

    if (strcmp(name, "MHPMCOUNTER05") == 0) return 2821;

    if (strcmp(name, "mhpmcounter05") == 0) return 2821;

    if (strcmp(name, "CSR_MHPMCOUNTER06") == 0) return 2822;

    if (strcmp(name, "MHPMCOUNTER06") == 0) return 2822;

    if (strcmp(name, "mhpmcounter06") == 0) return 2822;

    if (strcmp(name, "CSR_MHPMCOUNTER07") == 0) return 2823;

    if (strcmp(name, "MHPMCOUNTER07") == 0) return 2823;

    if (strcmp(name, "mhpmcounter07") == 0) return 2823;

    if (strcmp(name, "CSR_MHPMCOUNTER08") == 0) return 2824;

    if (strcmp(name, "MHPMCOUNTER08") == 0) return 2824;

    if (strcmp(name, "mhpmcounter08") == 0) return 2824;

    if (strcmp(name, "CSR_MHPMCOUNTER09") == 0) return 2825;

    if (strcmp(name, "MHPMCOUNTER09") == 0) return 2825;

    if (strcmp(name, "mhpmcounter09") == 0) return 2825;

    if (strcmp(name, "CSR_MHPMCOUNTER10") == 0) return 2826;

    if (strcmp(name, "MHPMCOUNTER10") == 0) return 2826;

    if (strcmp(name, "mhpmcounter10") == 0) return 2826;

    if (strcmp(name, "CSR_MHPMCOUNTER11") == 0) return 2827;

    if (strcmp(name, "MHPMCOUNTER11") == 0) return 2827;

    if (strcmp(name, "mhpmcounter11") == 0) return 2827;

    if (strcmp(name, "CSR_MHPMCOUNTER12") == 0) return 2828;

    if (strcmp(name, "MHPMCOUNTER12") == 0) return 2828;

    if (strcmp(name, "mhpmcounter12") == 0) return 2828;

    if (strcmp(name, "CSR_MHPMCOUNTER13") == 0) return 2829;

    if (strcmp(name, "MHPMCOUNTER13") == 0) return 2829;

    if (strcmp(name, "mhpmcounter13") == 0) return 2829;

    if (strcmp(name, "CSR_MHPMCOUNTER14") == 0) return 2830;

    if (strcmp(name, "MHPMCOUNTER14") == 0) return 2830;

    if (strcmp(name, "mhpmcounter14") == 0) return 2830;

    if (strcmp(name, "CSR_MHPMCOUNTER15") == 0) return 2831;

    if (strcmp(name, "MHPMCOUNTER15") == 0) return 2831;

    if (strcmp(name, "mhpmcounter15") == 0) return 2831;

    if (strcmp(name, "CSR_MHPMCOUNTER16") == 0) return 2832;

    if (strcmp(name, "MHPMCOUNTER16") == 0) return 2832;

    if (strcmp(name, "mhpmcounter16") == 0) return 2832;

    if (strcmp(name, "CSR_MHPMCOUNTER17") == 0) return 2833;

    if (strcmp(name, "MHPMCOUNTER17") == 0) return 2833;

    if (strcmp(name, "mhpmcounter17") == 0) return 2833;

    if (strcmp(name, "CSR_MHPMCOUNTER18") == 0) return 2834;

    if (strcmp(name, "MHPMCOUNTER18") == 0) return 2834;

    if (strcmp(name, "mhpmcounter18") == 0) return 2834;

    if (strcmp(name, "CSR_MHPMCOUNTER19") == 0) return 2835;

    if (strcmp(name, "MHPMCOUNTER19") == 0) return 2835;

    if (strcmp(name, "mhpmcounter19") == 0) return 2835;

    if (strcmp(name, "CSR_MHPMCOUNTER20") == 0) return 2836;

    if (strcmp(name, "MHPMCOUNTER20") == 0) return 2836;

    if (strcmp(name, "mhpmcounter20") == 0) return 2836;

    if (strcmp(name, "CSR_MHPMCOUNTER21") == 0) return 2837;

    if (strcmp(name, "MHPMCOUNTER21") == 0) return 2837;

    if (strcmp(name, "mhpmcounter21") == 0) return 2837;

    if (strcmp(name, "CSR_MHPMCOUNTER22") == 0) return 2838;

    if (strcmp(name, "MHPMCOUNTER22") == 0) return 2838;

    if (strcmp(name, "mhpmcounter22") == 0) return 2838;

    if (strcmp(name, "CSR_MHPMCOUNTER23") == 0) return 2839;

    if (strcmp(name, "MHPMCOUNTER23") == 0) return 2839;

    if (strcmp(name, "mhpmcounter23") == 0) return 2839;

    if (strcmp(name, "CSR_MHPMCOUNTER24") == 0) return 2840;

    if (strcmp(name, "MHPMCOUNTER24") == 0) return 2840;

    if (strcmp(name, "mhpmcounter24") == 0) return 2840;

    if (strcmp(name, "CSR_MHPMCOUNTER25") == 0) return 2841;

    if (strcmp(name, "MHPMCOUNTER25") == 0) return 2841;

    if (strcmp(name, "mhpmcounter25") == 0) return 2841;

    if (strcmp(name, "CSR_MHPMCOUNTER26") == 0) return 2842;

    if (strcmp(name, "MHPMCOUNTER26") == 0) return 2842;

    if (strcmp(name, "mhpmcounter26") == 0) return 2842;

    if (strcmp(name, "CSR_MHPMCOUNTER27") == 0) return 2843;

    if (strcmp(name, "MHPMCOUNTER27") == 0) return 2843;

    if (strcmp(name, "mhpmcounter27") == 0) return 2843;

    if (strcmp(name, "CSR_MHPMCOUNTER28") == 0) return 2844;

    if (strcmp(name, "MHPMCOUNTER28") == 0) return 2844;

    if (strcmp(name, "mhpmcounter28") == 0) return 2844;

    if (strcmp(name, "CSR_MHPMCOUNTER29") == 0) return 2845;

    if (strcmp(name, "MHPMCOUNTER29") == 0) return 2845;

    if (strcmp(name, "mhpmcounter29") == 0) return 2845;

    if (strcmp(name, "CSR_MHPMCOUNTER30") == 0) return 2846;

    if (strcmp(name, "MHPMCOUNTER30") == 0) return 2846;

    if (strcmp(name, "mhpmcounter30") == 0) return 2846;

    if (strcmp(name, "CSR_MHPMCOUNTER31") == 0) return 2847;

    if (strcmp(name, "MHPMCOUNTER31") == 0) return 2847;

    if (strcmp(name, "mhpmcounter31") == 0) return 2847;

    if (strcmp(name, "CSR_MCYCLEH") == 0) return 2944;

    if (strcmp(name, "MCYCLEH") == 0) return 2944;

    if (strcmp(name, "mcycleh") == 0) return 2944;

    if (strcmp(name, "CSR_MINSTRETH") == 0) return 2946;

    if (strcmp(name, "MINSTRETH") == 0) return 2946;

    if (strcmp(name, "minstreth") == 0) return 2946;

    if (strcmp(name, "CSR_MHPMCOUNTER03H") == 0) return 2947;

    if (strcmp(name, "MHPMCOUNTER03H") == 0) return 2947;

    if (strcmp(name, "mhpmcounter03h") == 0) return 2947;

    if (strcmp(name, "CSR_MHPMCOUNTER04H") == 0) return 2948;

    if (strcmp(name, "MHPMCOUNTER04H") == 0) return 2948;

    if (strcmp(name, "mhpmcounter04h") == 0) return 2948;

    if (strcmp(name, "CSR_MHPMCOUNTER05H") == 0) return 2949;

    if (strcmp(name, "MHPMCOUNTER05H") == 0) return 2949;

    if (strcmp(name, "mhpmcounter05h") == 0) return 2949;

    if (strcmp(name, "CSR_MHPMCOUNTER06H") == 0) return 2950;

    if (strcmp(name, "MHPMCOUNTER06H") == 0) return 2950;

    if (strcmp(name, "mhpmcounter06h") == 0) return 2950;

    if (strcmp(name, "CSR_MHPMCOUNTER07H") == 0) return 2951;

    if (strcmp(name, "MHPMCOUNTER07H") == 0) return 2951;

    if (strcmp(name, "mhpmcounter07h") == 0) return 2951;

    if (strcmp(name, "CSR_MHPMCOUNTER08H") == 0) return 2952;

    if (strcmp(name, "MHPMCOUNTER08H") == 0) return 2952;

    if (strcmp(name, "mhpmcounter08h") == 0) return 2952;

    if (strcmp(name, "CSR_MHPMCOUNTER09H") == 0) return 2953;

    if (strcmp(name, "MHPMCOUNTER09H") == 0) return 2953;

    if (strcmp(name, "mhpmcounter09h") == 0) return 2953;

    if (strcmp(name, "CSR_MHPMCOUNTER10H") == 0) return 2954;

    if (strcmp(name, "MHPMCOUNTER10H") == 0) return 2954;

    if (strcmp(name, "mhpmcounter10h") == 0) return 2954;

    if (strcmp(name, "CSR_MHPMCOUNTER11H") == 0) return 2955;

    if (strcmp(name, "MHPMCOUNTER11H") == 0) return 2955;

    if (strcmp(name, "mhpmcounter11h") == 0) return 2955;

    if (strcmp(name, "CSR_MHPMCOUNTER12H") == 0) return 2956;

    if (strcmp(name, "MHPMCOUNTER12H") == 0) return 2956;

    if (strcmp(name, "mhpmcounter12h") == 0) return 2956;

    if (strcmp(name, "CSR_MHPMCOUNTER13H") == 0) return 2957;

    if (strcmp(name, "MHPMCOUNTER13H") == 0) return 2957;

    if (strcmp(name, "mhpmcounter13h") == 0) return 2957;

    if (strcmp(name, "CSR_MHPMCOUNTER14H") == 0) return 2958;

    if (strcmp(name, "MHPMCOUNTER14H") == 0) return 2958;

    if (strcmp(name, "mhpmcounter14h") == 0) return 2958;

    if (strcmp(name, "CSR_MHPMCOUNTER15H") == 0) return 2959;

    if (strcmp(name, "MHPMCOUNTER15H") == 0) return 2959;

    if (strcmp(name, "mhpmcounter15h") == 0) return 2959;

    if (strcmp(name, "CSR_MHPMCOUNTER16H") == 0) return 2960;

    if (strcmp(name, "MHPMCOUNTER16H") == 0) return 2960;

    if (strcmp(name, "mhpmcounter16h") == 0) return 2960;

    if (strcmp(name, "CSR_MHPMCOUNTER17H") == 0) return 2961;

    if (strcmp(name, "MHPMCOUNTER17H") == 0) return 2961;

    if (strcmp(name, "mhpmcounter17h") == 0) return 2961;

    if (strcmp(name, "CSR_MHPMCOUNTER18H") == 0) return 2962;

    if (strcmp(name, "MHPMCOUNTER18H") == 0) return 2962;

    if (strcmp(name, "mhpmcounter18h") == 0) return 2962;

    if (strcmp(name, "CSR_MHPMCOUNTER19H") == 0) return 2963;

    if (strcmp(name, "MHPMCOUNTER19H") == 0) return 2963;

    if (strcmp(name, "mhpmcounter19h") == 0) return 2963;

    if (strcmp(name, "CSR_MHPMCOUNTER20H") == 0) return 2964;

    if (strcmp(name, "MHPMCOUNTER20H") == 0) return 2964;

    if (strcmp(name, "mhpmcounter20h") == 0) return 2964;

    if (strcmp(name, "CSR_MHPMCOUNTER21H") == 0) return 2965;

    if (strcmp(name, "MHPMCOUNTER21H") == 0) return 2965;

    if (strcmp(name, "mhpmcounter21h") == 0) return 2965;

    if (strcmp(name, "CSR_MHPMCOUNTER22H") == 0) return 2966;

    if (strcmp(name, "MHPMCOUNTER22H") == 0) return 2966;

    if (strcmp(name, "mhpmcounter22h") == 0) return 2966;

    if (strcmp(name, "CSR_MHPMCOUNTER23H") == 0) return 2967;

    if (strcmp(name, "MHPMCOUNTER23H") == 0) return 2967;

    if (strcmp(name, "mhpmcounter23h") == 0) return 2967;

    if (strcmp(name, "CSR_MHPMCOUNTER24H") == 0) return 2968;

    if (strcmp(name, "MHPMCOUNTER24H") == 0) return 2968;

    if (strcmp(name, "mhpmcounter24h") == 0) return 2968;

    if (strcmp(name, "CSR_MHPMCOUNTER25H") == 0) return 2969;

    if (strcmp(name, "MHPMCOUNTER25H") == 0) return 2969;

    if (strcmp(name, "mhpmcounter25h") == 0) return 2969;

    if (strcmp(name, "CSR_MHPMCOUNTER26H") == 0) return 2970;

    if (strcmp(name, "MHPMCOUNTER26H") == 0) return 2970;

    if (strcmp(name, "mhpmcounter26h") == 0) return 2970;

    if (strcmp(name, "CSR_MHPMCOUNTER27H") == 0) return 2971;

    if (strcmp(name, "MHPMCOUNTER27H") == 0) return 2971;

    if (strcmp(name, "mhpmcounter27h") == 0) return 2971;

    if (strcmp(name, "CSR_MHPMCOUNTER28H") == 0) return 2972;

    if (strcmp(name, "MHPMCOUNTER28H") == 0) return 2972;

    if (strcmp(name, "mhpmcounter28h") == 0) return 2972;

    if (strcmp(name, "CSR_MHPMCOUNTER29H") == 0) return 2973;

    if (strcmp(name, "MHPMCOUNTER29H") == 0) return 2973;

    if (strcmp(name, "mhpmcounter29h") == 0) return 2973;

    if (strcmp(name, "CSR_MHPMCOUNTER30H") == 0) return 2974;

    if (strcmp(name, "MHPMCOUNTER30H") == 0) return 2974;

    if (strcmp(name, "mhpmcounter30h") == 0) return 2974;

    if (strcmp(name, "CSR_MHPMCOUNTER31H") == 0) return 2975;

    if (strcmp(name, "MHPMCOUNTER31H") == 0) return 2975;

    if (strcmp(name, "mhpmcounter31h") == 0) return 2975;

    if (strcmp(name, "CSR_MHPMEVENT03") == 0) return 803;

    if (strcmp(name, "MHPMEVENT03") == 0) return 803;

    if (strcmp(name, "mhpmevent03") == 0) return 803;

    if (strcmp(name, "CSR_MHPMEVENT04") == 0) return 804;

    if (strcmp(name, "MHPMEVENT04") == 0) return 804;

    if (strcmp(name, "mhpmevent04") == 0) return 804;

    if (strcmp(name, "CSR_MHPMEVENT05") == 0) return 805;

    if (strcmp(name, "MHPMEVENT05") == 0) return 805;

    if (strcmp(name, "mhpmevent05") == 0) return 805;

    if (strcmp(name, "CSR_MHPMEVENT06") == 0) return 806;

    if (strcmp(name, "MHPMEVENT06") == 0) return 806;

    if (strcmp(name, "mhpmevent06") == 0) return 806;

    if (strcmp(name, "CSR_MHPMEVENT07") == 0) return 807;

    if (strcmp(name, "MHPMEVENT07") == 0) return 807;

    if (strcmp(name, "mhpmevent07") == 0) return 807;

    if (strcmp(name, "CSR_MHPMEVENT08") == 0) return 808;

    if (strcmp(name, "MHPMEVENT08") == 0) return 808;

    if (strcmp(name, "mhpmevent08") == 0) return 808;

    if (strcmp(name, "CSR_MHPMEVENT09") == 0) return 809;

    if (strcmp(name, "MHPMEVENT09") == 0) return 809;

    if (strcmp(name, "mhpmevent09") == 0) return 809;

    if (strcmp(name, "CSR_MHPMEVENT10") == 0) return 810;

    if (strcmp(name, "MHPMEVENT10") == 0) return 810;

    if (strcmp(name, "mhpmevent10") == 0) return 810;

    if (strcmp(name, "CSR_MHPMEVENT11") == 0) return 811;

    if (strcmp(name, "MHPMEVENT11") == 0) return 811;

    if (strcmp(name, "mhpmevent11") == 0) return 811;

    if (strcmp(name, "CSR_MHPMEVENT12") == 0) return 812;

    if (strcmp(name, "MHPMEVENT12") == 0) return 812;

    if (strcmp(name, "mhpmevent12") == 0) return 812;

    if (strcmp(name, "CSR_MHPMEVENT13") == 0) return 813;

    if (strcmp(name, "MHPMEVENT13") == 0) return 813;

    if (strcmp(name, "mhpmevent13") == 0) return 813;

    if (strcmp(name, "CSR_MHPMEVENT14") == 0) return 814;

    if (strcmp(name, "MHPMEVENT14") == 0) return 814;

    if (strcmp(name, "mhpmevent14") == 0) return 814;

    if (strcmp(name, "CSR_MHPMEVENT15") == 0) return 815;

    if (strcmp(name, "MHPMEVENT15") == 0) return 815;

    if (strcmp(name, "mhpmevent15") == 0) return 815;

    if (strcmp(name, "CSR_MHPMEVENT16") == 0) return 816;

    if (strcmp(name, "MHPMEVENT16") == 0) return 816;

    if (strcmp(name, "mhpmevent16") == 0) return 816;

    if (strcmp(name, "CSR_MHPMEVENT17") == 0) return 817;

    if (strcmp(name, "MHPMEVENT17") == 0) return 817;

    if (strcmp(name, "mhpmevent17") == 0) return 817;

    if (strcmp(name, "CSR_MHPMEVENT18") == 0) return 818;

    if (strcmp(name, "MHPMEVENT18") == 0) return 818;

    if (strcmp(name, "mhpmevent18") == 0) return 818;

    if (strcmp(name, "CSR_MHPMEVENT19") == 0) return 819;

    if (strcmp(name, "MHPMEVENT19") == 0) return 819;

    if (strcmp(name, "mhpmevent19") == 0) return 819;

    if (strcmp(name, "CSR_MHPMEVENT20") == 0) return 820;

    if (strcmp(name, "MHPMEVENT20") == 0) return 820;

    if (strcmp(name, "mhpmevent20") == 0) return 820;

    if (strcmp(name, "CSR_MHPMEVENT21") == 0) return 821;

    if (strcmp(name, "MHPMEVENT21") == 0) return 821;

    if (strcmp(name, "mhpmevent21") == 0) return 821;

    if (strcmp(name, "CSR_MHPMEVENT22") == 0) return 822;

    if (strcmp(name, "MHPMEVENT22") == 0) return 822;

    if (strcmp(name, "mhpmevent22") == 0) return 822;

    if (strcmp(name, "CSR_MHPMEVENT23") == 0) return 823;

    if (strcmp(name, "MHPMEVENT23") == 0) return 823;

    if (strcmp(name, "mhpmevent23") == 0) return 823;

    if (strcmp(name, "CSR_MHPMEVENT24") == 0) return 824;

    if (strcmp(name, "MHPMEVENT24") == 0) return 824;

    if (strcmp(name, "mhpmevent24") == 0) return 824;

    if (strcmp(name, "CSR_MHPMEVENT25") == 0) return 825;

    if (strcmp(name, "MHPMEVENT25") == 0) return 825;

    if (strcmp(name, "mhpmevent25") == 0) return 825;

    if (strcmp(name, "CSR_MHPMEVENT26") == 0) return 826;

    if (strcmp(name, "MHPMEVENT26") == 0) return 826;

    if (strcmp(name, "mhpmevent26") == 0) return 826;

    if (strcmp(name, "CSR_MHPMEVENT27") == 0) return 827;

    if (strcmp(name, "MHPMEVENT27") == 0) return 827;

    if (strcmp(name, "mhpmevent27") == 0) return 827;

    if (strcmp(name, "CSR_MHPMEVENT28") == 0) return 828;

    if (strcmp(name, "MHPMEVENT28") == 0) return 828;

    if (strcmp(name, "mhpmevent28") == 0) return 828;

    if (strcmp(name, "CSR_MHPMEVENT29") == 0) return 829;

    if (strcmp(name, "MHPMEVENT29") == 0) return 829;

    if (strcmp(name, "mhpmevent29") == 0) return 829;

    if (strcmp(name, "CSR_MHPMEVENT30") == 0) return 830;

    if (strcmp(name, "MHPMEVENT30") == 0) return 830;

    if (strcmp(name, "mhpmevent30") == 0) return 830;

    if (strcmp(name, "CSR_MHPMEVENT31") == 0) return 831;

    if (strcmp(name, "MHPMEVENT31") == 0) return 831;

    if (strcmp(name, "mhpmevent31") == 0) return 831;

    if (strcmp(name, "CSR_TSELECT") == 0) return 1952;

    if (strcmp(name, "TSELECT") == 0) return 1952;

    if (strcmp(name, "tselect") == 0) return 1952;

    if (strcmp(name, "CSR_TDATA1") == 0) return 1953;

    if (strcmp(name, "TDATA1") == 0) return 1953;

    if (strcmp(name, "tdata1") == 0) return 1953;

    if (strcmp(name, "CSR_TDATA2") == 0) return 1954;

    if (strcmp(name, "TDATA2") == 0) return 1954;

    if (strcmp(name, "tdata2") == 0) return 1954;

    if (strcmp(name, "CSR_TDATA3") == 0) return 1955;

    if (strcmp(name, "TDATA3") == 0) return 1955;

    if (strcmp(name, "tdata3") == 0) return 1955;

    if (strcmp(name, "CSR_DCSR") == 0) return 1968;

    if (strcmp(name, "DCSR") == 0) return 1968;

    if (strcmp(name, "dcsr") == 0) return 1968;

    if (strcmp(name, "CSR_DPC") == 0) return 1969;

    if (strcmp(name, "DPC") == 0) return 1969;

    if (strcmp(name, "dpc") == 0) return 1969;

    if (strcmp(name, "CSR_DSCRATCH") == 0) return 1970;

    if (strcmp(name, "DSCRATCH") == 0) return 1970;

    if (strcmp(name, "dscratch") == 0) return 1970;

    return -1; // 未找到对应的寄存器
}


int getInstructionIndexByName(const char* name) {

    if (strcmp(name, "C_addi4spn") == 0) return 1;

    if (strcmp(name, "addi4spn") == 0) return 1;

    if (strcmp(name, "C_fld") == 0) return 2;

    if (strcmp(name, "fld") == 0) return 2;

    if (strcmp(name, "C_lw") == 0) return 3;

    if (strcmp(name, "lw") == 0) return 3;

    if (strcmp(name, "C_flw") == 0) return 4;

    if (strcmp(name, "flw") == 0) return 4;

    if (strcmp(name, "C_ld") == 0) return 5;

    if (strcmp(name, "ld") == 0) return 5;

    if (strcmp(name, "Unknown") == 0) return 6;

    if (strcmp(name, "C_fsd") == 0) return 7;

    if (strcmp(name, "fsd") == 0) return 7;

    if (strcmp(name, "C_sw") == 0) return 8;

    if (strcmp(name, "sw") == 0) return 8;

    if (strcmp(name, "C_fsw") == 0) return 9;

    if (strcmp(name, "fsw") == 0) return 9;

    if (strcmp(name, "C_sd") == 0) return 10;

    if (strcmp(name, "sd") == 0) return 10;

    if (strcmp(name, "C_addi") == 0) return 11;

    if (strcmp(name, "addi") == 0) return 11;

    if (strcmp(name, "C_jal") == 0) return 12;

    if (strcmp(name, "jal") == 0) return 12;

    if (strcmp(name, "C_addiw") == 0) return 13;

    if (strcmp(name, "addiw") == 0) return 13;

    if (strcmp(name, "C_li") == 0) return 14;

    if (strcmp(name, "li") == 0) return 14;

    if (strcmp(name, "C_addi16sp") == 0) return 15;

    if (strcmp(name, "addi16sp") == 0) return 15;

    if (strcmp(name, "C_lui") == 0) return 16;

    if (strcmp(name, "lui") == 0) return 16;

    if (strcmp(name, "C_srli") == 0) return 17;

    if (strcmp(name, "srli") == 0) return 17;

    if (strcmp(name, "C_srai") == 0) return 18;

    if (strcmp(name, "srai") == 0) return 18;

    if (strcmp(name, "C_andi") == 0) return 19;

    if (strcmp(name, "andi") == 0) return 19;

    if (strcmp(name, "C_sub") == 0) return 20;

    if (strcmp(name, "sub") == 0) return 20;

    if (strcmp(name, "C_xor") == 0) return 21;

    if (strcmp(name, "xor") == 0) return 21;

    if (strcmp(name, "C_or") == 0) return 22;

    if (strcmp(name, "or") == 0) return 22;

    if (strcmp(name, "C_and") == 0) return 23;

    if (strcmp(name, "and") == 0) return 23;

    if (strcmp(name, "C_subw") == 0) return 24;

    if (strcmp(name, "subw") == 0) return 24;

    if (strcmp(name, "C_addw") == 0) return 25;

    if (strcmp(name, "addw") == 0) return 25;

    if (strcmp(name, "C_j") == 0) return 26;

    if (strcmp(name, "j") == 0) return 26;

    if (strcmp(name, "C_beqz") == 0) return 27;

    if (strcmp(name, "beqz") == 0) return 27;

    if (strcmp(name, "C_bnez") == 0) return 28;

    if (strcmp(name, "bnez") == 0) return 28;

    if (strcmp(name, "C_slli") == 0) return 29;

    if (strcmp(name, "slli") == 0) return 29;

    if (strcmp(name, "C_fldsp") == 0) return 30;

    if (strcmp(name, "fldsp") == 0) return 30;

    if (strcmp(name, "C_lwsp") == 0) return 31;

    if (strcmp(name, "lwsp") == 0) return 31;

    if (strcmp(name, "C_flwsp") == 0) return 32;

    if (strcmp(name, "flwsp") == 0) return 32;

    if (strcmp(name, "C_ldsp") == 0) return 33;

    if (strcmp(name, "ldsp") == 0) return 33;

    if (strcmp(name, "C_jr") == 0) return 34;

    if (strcmp(name, "jr") == 0) return 34;

    if (strcmp(name, "C_mv") == 0) return 35;

    if (strcmp(name, "mv") == 0) return 35;

    if (strcmp(name, "C_ebreak") == 0) return 36;

    if (strcmp(name, "ebreak") == 0) return 36;

    if (strcmp(name, "C_jalr") == 0) return 37;

    if (strcmp(name, "jalr") == 0) return 37;

    if (strcmp(name, "C_add") == 0) return 38;

    if (strcmp(name, "add") == 0) return 38;

    if (strcmp(name, "C_fsdsp") == 0) return 39;

    if (strcmp(name, "fsdsp") == 0) return 39;

    if (strcmp(name, "C_swsp") == 0) return 40;

    if (strcmp(name, "swsp") == 0) return 40;

    if (strcmp(name, "C_fswsp") == 0) return 41;

    if (strcmp(name, "fswsp") == 0) return 41;

    if (strcmp(name, "C_sdsp") == 0) return 42;

    if (strcmp(name, "sdsp") == 0) return 42;

    if (strcmp(name, "Lb") == 0) return 43;

    if (strcmp(name, "Lh") == 0) return 44;

    if (strcmp(name, "Lw") == 0) return 45;

    if (strcmp(name, "Ld") == 0) return 46;

    if (strcmp(name, "Lbu") == 0) return 47;

    if (strcmp(name, "Lhu") == 0) return 48;

    if (strcmp(name, "Lwu") == 0) return 49;

    if (strcmp(name, "Flh") == 0) return 50;

    if (strcmp(name, "Flw") == 0) return 51;

    if (strcmp(name, "Fld") == 0) return 52;

    if (strcmp(name, "Fence") == 0) return 53;

    if (strcmp(name, "Fence_i") == 0) return 54;

    if (strcmp(name, "i") == 0) return 54;

    if (strcmp(name, "Slli") == 0) return 55;

    if (strcmp(name, "Zip") == 0) return 56;

    if (strcmp(name, "Sha256sum0") == 0) return 57;

    if (strcmp(name, "Sha256sum1") == 0) return 58;

    if (strcmp(name, "Sha256sig0") == 0) return 59;

    if (strcmp(name, "Sha256sig1") == 0) return 60;

    if (strcmp(name, "Sha512sum0") == 0) return 61;

    if (strcmp(name, "Sha512sum1") == 0) return 62;

    if (strcmp(name, "Sha512sig0") == 0) return 63;

    if (strcmp(name, "Sha512sig1") == 0) return 64;

    if (strcmp(name, "Sm3p0") == 0) return 65;

    if (strcmp(name, "Sm3p1") == 0) return 66;

    if (strcmp(name, "Bseti") == 0) return 67;

    if (strcmp(name, "Aes64im") == 0) return 68;

    if (strcmp(name, "Aes64ks1i") == 0) return 69;

    if (strcmp(name, "Bclri") == 0) return 70;

    if (strcmp(name, "Binvi") == 0) return 71;

    if (strcmp(name, "Clz") == 0) return 72;

    if (strcmp(name, "Ctz") == 0) return 73;

    if (strcmp(name, "Cpop") == 0) return 74;

    if (strcmp(name, "Sext_b") == 0) return 75;

    if (strcmp(name, "b") == 0) return 83;

    if (strcmp(name, "Sext_h") == 0) return 76;

    if (strcmp(name, "h") == 0) return 292;

    if (strcmp(name, "Addi") == 0) return 77;

    if (strcmp(name, "Slti") == 0) return 78;

    if (strcmp(name, "Sltiu") == 0) return 79;

    if (strcmp(name, "Xori") == 0) return 80;

    if (strcmp(name, "Srli") == 0) return 81;

    if (strcmp(name, "Unzip") == 0) return 82;

    if (strcmp(name, "Orc_b") == 0) return 83;

    if (strcmp(name, "Srai") == 0) return 84;

    if (strcmp(name, "Bexti") == 0) return 85;

    if (strcmp(name, "Rori") == 0) return 86;

    if (strcmp(name, "Rev8") == 0) return 87;

    if (strcmp(name, "Brev8") == 0) return 88;

    if (strcmp(name, "Ori") == 0) return 89;

    if (strcmp(name, "Andi") == 0) return 90;

    if (strcmp(name, "Auipc") == 0) return 91;

    if (strcmp(name, "Addiw") == 0) return 92;

    if (strcmp(name, "Slliw") == 0) return 93;

    if (strcmp(name, "Slli_uw") == 0) return 94;

    if (strcmp(name, "uw") == 0) return 204;

    if (strcmp(name, "Clzw") == 0) return 95;

    if (strcmp(name, "Ctzw") == 0) return 96;

    if (strcmp(name, "Cpopw") == 0) return 97;

    if (strcmp(name, "Srliw") == 0) return 98;

    if (strcmp(name, "Sraiw") == 0) return 99;

    if (strcmp(name, "Roriw") == 0) return 100;

    if (strcmp(name, "Sb") == 0) return 101;

    if (strcmp(name, "Sh") == 0) return 102;

    if (strcmp(name, "Sw") == 0) return 103;

    if (strcmp(name, "Sd") == 0) return 104;

    if (strcmp(name, "Fsh") == 0) return 105;

    if (strcmp(name, "Fsw") == 0) return 106;

    if (strcmp(name, "Fsd") == 0) return 107;

    if (strcmp(name, "Lr_w") == 0) return 108;

    if (strcmp(name, "w") == 0) return 287;

    if (strcmp(name, "Sc_w") == 0) return 109;

    if (strcmp(name, "Amoadd_w") == 0) return 110;

    if (strcmp(name, "Amoswap_w") == 0) return 111;

    if (strcmp(name, "Amoxor_w") == 0) return 112;

    if (strcmp(name, "Amoor_w") == 0) return 113;

    if (strcmp(name, "Amoand_w") == 0) return 114;

    if (strcmp(name, "Amomin_w") == 0) return 115;

    if (strcmp(name, "Amomax_w") == 0) return 116;

    if (strcmp(name, "Amominu_w") == 0) return 117;

    if (strcmp(name, "Amomaxu_w") == 0) return 118;

    if (strcmp(name, "Lr_d") == 0) return 119;

    if (strcmp(name, "d") == 0) return 290;

    if (strcmp(name, "Sc_d") == 0) return 120;

    if (strcmp(name, "Amoadd_d") == 0) return 121;

    if (strcmp(name, "Amoswap_d") == 0) return 122;

    if (strcmp(name, "Amoxor_d") == 0) return 123;

    if (strcmp(name, "Amoor_d") == 0) return 124;

    if (strcmp(name, "Amoand_d") == 0) return 125;

    if (strcmp(name, "Amomin_d") == 0) return 126;

    if (strcmp(name, "Amomax_d") == 0) return 127;

    if (strcmp(name, "Amominu_d") == 0) return 128;

    if (strcmp(name, "Amomaxu_d") == 0) return 129;

    if (strcmp(name, "Add") == 0) return 130;

    if (strcmp(name, "Sub") == 0) return 131;

    if (strcmp(name, "Mul") == 0) return 132;

    if (strcmp(name, "Sha512sum0r") == 0) return 133;

    if (strcmp(name, "Sha512sum1r") == 0) return 134;

    if (strcmp(name, "Sha512sig0l") == 0) return 135;

    if (strcmp(name, "Sha512sig1l") == 0) return 136;

    if (strcmp(name, "Sha512sig0h") == 0) return 137;

    if (strcmp(name, "Sha512sig1h") == 0) return 138;

    if (strcmp(name, "Aes32esi") == 0) return 139;

    if (strcmp(name, "Aes32esmi") == 0) return 140;

    if (strcmp(name, "Aes32dsi") == 0) return 141;

    if (strcmp(name, "Aes32dsmi") == 0) return 142;

    if (strcmp(name, "Sm4ed") == 0) return 143;

    if (strcmp(name, "Aes64es") == 0) return 144;

    if (strcmp(name, "Sm4ks") == 0) return 145;

    if (strcmp(name, "Aes64esm") == 0) return 146;

    if (strcmp(name, "Aes64ds") == 0) return 147;

    if (strcmp(name, "Aes64dsm") == 0) return 148;

    if (strcmp(name, "Aes64ks2") == 0) return 149;

    if (strcmp(name, "Sll") == 0) return 150;

    if (strcmp(name, "Mulh") == 0) return 151;

    if (strcmp(name, "Clmul") == 0) return 152;

    if (strcmp(name, "Bset") == 0) return 153;

    if (strcmp(name, "Bclr") == 0) return 154;

    if (strcmp(name, "Rol") == 0) return 155;

    if (strcmp(name, "Binv") == 0) return 156;

    if (strcmp(name, "Slt") == 0) return 157;

    if (strcmp(name, "Mulhsu") == 0) return 158;

    if (strcmp(name, "Clmulr") == 0) return 159;

    if (strcmp(name, "Sh1add") == 0) return 160;

    if (strcmp(name, "Xperm4") == 0) return 161;

    if (strcmp(name, "Sltu") == 0) return 162;

    if (strcmp(name, "Mulhu") == 0) return 163;

    if (strcmp(name, "Clmulh") == 0) return 164;

    if (strcmp(name, "Xor") == 0) return 165;

    if (strcmp(name, "Div") == 0) return 166;

    if (strcmp(name, "Pack") == 0) return 167;

    if (strcmp(name, "Min") == 0) return 168;

    if (strcmp(name, "Sh2add") == 0) return 169;

    if (strcmp(name, "Xperm8") == 0) return 170;

    if (strcmp(name, "Xnor") == 0) return 171;

    if (strcmp(name, "Srl") == 0) return 172;

    if (strcmp(name, "Divu") == 0) return 173;

    if (strcmp(name, "Sra") == 0) return 174;

    if (strcmp(name, "Minu") == 0) return 175;

    if (strcmp(name, "Bext") == 0) return 176;

    if (strcmp(name, "Ror") == 0) return 177;

    if (strcmp(name, "Or") == 0) return 178;

    if (strcmp(name, "Rem") == 0) return 179;

    if (strcmp(name, "Max") == 0) return 180;

    if (strcmp(name, "Sh3add") == 0) return 181;

    if (strcmp(name, "Orn") == 0) return 182;

    if (strcmp(name, "And") == 0) return 183;

    if (strcmp(name, "Remu") == 0) return 184;

    if (strcmp(name, "Packh") == 0) return 185;

    if (strcmp(name, "Maxu") == 0) return 186;

    if (strcmp(name, "Andn") == 0) return 187;

    if (strcmp(name, "Lui") == 0) return 188;

    if (strcmp(name, "Addw") == 0) return 189;

    if (strcmp(name, "Mulw") == 0) return 190;

    if (strcmp(name, "Add_uw") == 0) return 191;

    if (strcmp(name, "Subw") == 0) return 192;

    if (strcmp(name, "Sllw") == 0) return 193;

    if (strcmp(name, "Rolw") == 0) return 194;

    if (strcmp(name, "Sh1add_uw") == 0) return 195;

    if (strcmp(name, "Divw") == 0) return 196;

    if (strcmp(name, "Packw") == 0) return 197;

    if (strcmp(name, "Sh2add_uw") == 0) return 198;

    if (strcmp(name, "Srlw") == 0) return 199;

    if (strcmp(name, "Divuw") == 0) return 200;

    if (strcmp(name, "Sraw") == 0) return 201;

    if (strcmp(name, "Rorw") == 0) return 202;

    if (strcmp(name, "Remw") == 0) return 203;

    if (strcmp(name, "Sh3add_uw") == 0) return 204;

    if (strcmp(name, "Remuw") == 0) return 205;

    if (strcmp(name, "Fmadd_s") == 0) return 206;

    if (strcmp(name, "s") == 0) return 288;

    if (strcmp(name, "Fmadd_d") == 0) return 207;

    if (strcmp(name, "Fmadd_h") == 0) return 208;

    if (strcmp(name, "Fmsub_s") == 0) return 209;

    if (strcmp(name, "Fmsub_d") == 0) return 210;

    if (strcmp(name, "Fmsub_h") == 0) return 211;

    if (strcmp(name, "Fnmsub_s") == 0) return 212;

    if (strcmp(name, "Fnmsub_d") == 0) return 213;

    if (strcmp(name, "Fnmsub_h") == 0) return 214;

    if (strcmp(name, "Fnmadd_s") == 0) return 215;

    if (strcmp(name, "Fnmadd_d") == 0) return 216;

    if (strcmp(name, "Fnmadd_h") == 0) return 217;

    if (strcmp(name, "Fadd_s") == 0) return 218;

    if (strcmp(name, "Fadd_d") == 0) return 219;

    if (strcmp(name, "Fadd_h") == 0) return 220;

    if (strcmp(name, "Fsub_s") == 0) return 221;

    if (strcmp(name, "Fsub_d") == 0) return 222;

    if (strcmp(name, "Fsub_h") == 0) return 223;

    if (strcmp(name, "Fmul_s") == 0) return 224;

    if (strcmp(name, "Fmul_d") == 0) return 225;

    if (strcmp(name, "Fmul_h") == 0) return 226;

    if (strcmp(name, "Fdiv_s") == 0) return 227;

    if (strcmp(name, "Fdiv_d") == 0) return 228;

    if (strcmp(name, "Fdiv_h") == 0) return 229;

    if (strcmp(name, "Fsgnj_s") == 0) return 230;

    if (strcmp(name, "Fsgnjn_s") == 0) return 231;

    if (strcmp(name, "Fsgnjx_s") == 0) return 232;

    if (strcmp(name, "Fsgnj_d") == 0) return 233;

    if (strcmp(name, "Fsgnjn_d") == 0) return 234;

    if (strcmp(name, "Fsgnjx_d") == 0) return 235;

    if (strcmp(name, "Fsgnj_h") == 0) return 236;

    if (strcmp(name, "Fsgnjn_h") == 0) return 237;

    if (strcmp(name, "Fsgnjx_h") == 0) return 238;

    if (strcmp(name, "Fmin_s") == 0) return 239;

    if (strcmp(name, "Fmax_s") == 0) return 240;

    if (strcmp(name, "Fmin_d") == 0) return 241;

    if (strcmp(name, "Fmax_d") == 0) return 242;

    if (strcmp(name, "Fmin_h") == 0) return 243;

    if (strcmp(name, "Fmax_h") == 0) return 244;

    if (strcmp(name, "Fcvt_s_d") == 0) return 245;

    if (strcmp(name, "Fcvt_s_h") == 0) return 246;

    if (strcmp(name, "Fcvt_d_s") == 0) return 247;

    if (strcmp(name, "Fcvt_d_h") == 0) return 248;

    if (strcmp(name, "Fcvt_h_s") == 0) return 249;

    if (strcmp(name, "Fcvt_h_d") == 0) return 250;

    if (strcmp(name, "Fsqrt_s") == 0) return 251;

    if (strcmp(name, "Fsqrt_d") == 0) return 252;

    if (strcmp(name, "Fsqrt_h") == 0) return 253;

    if (strcmp(name, "Fle_s") == 0) return 254;

    if (strcmp(name, "Flt_s") == 0) return 255;

    if (strcmp(name, "Feq_s") == 0) return 256;

    if (strcmp(name, "Fle_d") == 0) return 257;

    if (strcmp(name, "Flt_d") == 0) return 258;

    if (strcmp(name, "Feq_d") == 0) return 259;

    if (strcmp(name, "Fle_h") == 0) return 260;

    if (strcmp(name, "Flt_h") == 0) return 261;

    if (strcmp(name, "Feq_h") == 0) return 262;

    if (strcmp(name, "Fcvt_w_s") == 0) return 263;

    if (strcmp(name, "Fcvt_wu_s") == 0) return 264;

    if (strcmp(name, "Fcvt_l_s") == 0) return 265;

    if (strcmp(name, "Fcvt_lu_s") == 0) return 266;

    if (strcmp(name, "Fcvt_w_d") == 0) return 267;

    if (strcmp(name, "Fcvt_wu_d") == 0) return 268;

    if (strcmp(name, "Fcvt_l_d") == 0) return 269;

    if (strcmp(name, "Fcvt_lu_d") == 0) return 270;

    if (strcmp(name, "Fcvt_w_h") == 0) return 271;

    if (strcmp(name, "Fcvt_wu_h") == 0) return 272;

    if (strcmp(name, "Fcvt_l_h") == 0) return 273;

    if (strcmp(name, "Fcvt_lu_h") == 0) return 274;

    if (strcmp(name, "Fcvt_s_w") == 0) return 275;

    if (strcmp(name, "Fcvt_s_wu") == 0) return 276;

    if (strcmp(name, "wu") == 0) return 284;

    if (strcmp(name, "Fcvt_s_l") == 0) return 277;

    if (strcmp(name, "l") == 0) return 285;

    if (strcmp(name, "Fcvt_s_lu") == 0) return 278;

    if (strcmp(name, "lu") == 0) return 286;

    if (strcmp(name, "Fcvt_d_w") == 0) return 279;

    if (strcmp(name, "Fcvt_d_wu") == 0) return 280;

    if (strcmp(name, "Fcvt_d_l") == 0) return 281;

    if (strcmp(name, "Fcvt_d_lu") == 0) return 282;

    if (strcmp(name, "Fcvt_h_w") == 0) return 283;

    if (strcmp(name, "Fcvt_h_wu") == 0) return 284;

    if (strcmp(name, "Fcvt_h_l") == 0) return 285;

    if (strcmp(name, "Fcvt_h_lu") == 0) return 286;

    if (strcmp(name, "Fmv_x_w") == 0) return 287;

    if (strcmp(name, "Fclass_s") == 0) return 288;

    if (strcmp(name, "Fmv_x_d") == 0) return 289;

    if (strcmp(name, "Fclass_d") == 0) return 290;

    if (strcmp(name, "Fmv_x_h") == 0) return 291;

    if (strcmp(name, "Fclass_h") == 0) return 292;

    if (strcmp(name, "Fmv_w_x") == 0) return 293;

    if (strcmp(name, "x") == 0) return 295;

    if (strcmp(name, "Fmv_d_x") == 0) return 294;

    if (strcmp(name, "Fmv_h_x") == 0) return 295;

    if (strcmp(name, "Beq") == 0) return 296;

    if (strcmp(name, "Bne") == 0) return 297;

    if (strcmp(name, "Blt") == 0) return 298;

    if (strcmp(name, "Bge") == 0) return 299;

    if (strcmp(name, "Bltu") == 0) return 300;

    if (strcmp(name, "Bgeu") == 0) return 301;

    if (strcmp(name, "Jalr") == 0) return 302;

    if (strcmp(name, "Jal") == 0) return 303;

    if (strcmp(name, "Ecall") == 0) return 304;

    if (strcmp(name, "Ebreak") == 0) return 305;

    if (strcmp(name, "Uret") == 0) return 306;

    if (strcmp(name, "Sret") == 0) return 307;

    if (strcmp(name, "Wfi") == 0) return 308;

    if (strcmp(name, "Sfence_vma") == 0) return 309;

    if (strcmp(name, "vma") == 0) return 309;

    if (strcmp(name, "Mret") == 0) return 310;

    if (strcmp(name, "Csrrw") == 0) return 311;

    if (strcmp(name, "Csrrs") == 0) return 312;

    if (strcmp(name, "Csrrc") == 0) return 313;

    if (strcmp(name, "Mirdbu") == 0) return 314;

    if (strcmp(name, "Csrrwi") == 0) return 315;

    if (strcmp(name, "Csrrsi") == 0) return 316;

    if (strcmp(name, "Csrrci") == 0) return 317;

    if (strcmp(name, "M5Op") == 0) return 318;

    if (strcmp(name, "MAXINSTRUCTION") == 0) return 318;

    return -1; // 未找到对应的指令
}
