#include <stdio.h>
#include <unistd.h>

typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned char uchar;

//char ans[32] = {78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78,
//                78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78};
//char ans[32] = {118, 50, 161, 43, 121, 184, 159, 131, 36, 231, 64, 240, 241, 63, 173, 85, 73, 205, 89, 108, 41, 27, 2, 155, 45, 225, 155, 123, 230, 234, 107, 187};
//char ans[32] = {148, 204, 32, 80, 73, 151, 206, 62, 112, 63, 173, 231, 196, 23, 108, 77, 51, 111, 151, 253, 214, 83, 90, 156, 230, 76, 252, 119, 26, 50, 27, 135};
//char ans[32] = {9, 44, 231, 185, 93, 13, 187, 68, 254, 77, 3, 152, 115, 101, 120, 212, 168, 13, 202, 1, 117, 207, 8, 130, 8, 105, 0, 86, 181, 58, 5, 1};


int get_dword(char *buf, int offset) { return *(int *)(buf + offset); }

short get_short(char *buf, int offset) { return *(short *)(buf + offset); }

int check1(char* ans) {
  int v1 = (((int)ans[10] - (int)ans[4]) * 0x1000000 >> 0x18) + 0x5a;
  return ((v1 >> 0x1f) - v1 ^ v1 >> 0x1f);
}

int check2(char* ans) {
  int v2 = (char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb;
  return ((v2 >> 0x1f) - v2 ^ v2 >> 0x1f);
}

int check3(char* ans) {
  int v3 = ((get_dword(ans, 8) + get_dword(ans, 0) ^
             (get_dword(ans, 7) | get_dword(ans, 3))) +
            0x56cb0106);
  return ((v3 >> 0x1f) - (v3 ^ v3 >> 0x1f));
}

int check4(char* ans) {

  int v4 =
      (get_dword(ans, 10) ^ get_dword(ans, 4) ^
       get_dword(ans, 0x11) & (get_dword(ans, 0x17) ^ get_dword(ans, 0x1c)));
  return (int)((v4 + v4 + 0xd0d747cc & (int)(v4 + 0x686ba3e6) >> 0x1f) -
               (v4 + 0x686ba3e6));
}
int check5(char* ans) {

  int v5 = (int)(short)(get_short(ans, 0xe) + get_short(ans, 0x1d) &
                        get_short(ans, 0x12) -
                            (get_short(ans, 0x13) | get_short(ans, 0x1a)));
  return (int)(v5 - 0x2258U | 0x2258U - v5);
}
int check6(char* ans) {

  int v6 = ((get_dword(ans, 0x13) ^ get_dword(ans, 0x12)) -
            (get_dword(ans, 0x18) + get_dword(ans, 0x11) &
             (get_dword(ans, 7) ^ get_dword(ans, 0x14))));
  return (int)(((int)(v6 + -0x66d6ff0b) >> 0x1f) -
               (v6 + 0x992900f5 ^ (int)(v6 + -0x66d6ff0b) >> 0x1f));
}
int check7(char* ans) {

  int v7 = (get_dword(ans, 0xd) & get_dword(ans, 0x12) & get_dword(ans, 0x16) &
            get_dword(ans, 0));
  return (int)(v7 + 0xdfffff80 | 0x20000080 - v7);
}
int check8(char* ans) {

  int v8 = ((get_dword(ans, 5) & get_dword(ans, 6)) + 0xccedf7f7);
  return (int)(((int)v8 >> 0x1f) - v8 ^ (int)v8 >> 0x1f);
}
int check9(char* ans) {

  int v9 = (int)(short)(get_short(ans, 0xc) | get_short(ans, 0x11) |
                        get_short(ans, 0x11) | get_short(ans, 0x15));
  return (int)(v9 + 0x3005U | -v9 - 0x3005U);
}
int check10(char* ans) {

  int v10 = (((int)(short)(get_short(ans, 0x1e) & get_short(ans, 6)) +
              (int)(short)(get_short(ans, 5) & get_short(ans, 0x1d))) *
                 0x10000 >>
             0x10);
  return (int)(v10 - 0x1018U | 0x1018U - v10);
}
int check11(char* ans) {

  int v11 = (((int)(char)(ans[9] | ans[6]) +
              ((int)(char)(ans[0x1e] ^ ans[1]) &
               (int)(char)ans[4] - (int)(char)ans[0x1f])) *
                 0x1000000 >>
             0x18);
  return ((v11 + -7 >> 0x1f) - (v11 + -7) ^ v11 + -7 >> 0x1f);
}
int check12(char* ans) {

  int v12 = ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
              ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
              (int)(char)(ans[2] & ans[0xb])) *
                 0x1000000 >>
             0x18);
  return ((v12 + 0xb >> 0x1f) - (v12 + 0xb) ^ v12 + 0xb >> 0x1f);
}
int check13(char* ans) {

  int v13 = (int)(short)(get_short(ans, 0) | get_short(ans, 0xc) |
                         get_short(ans, 0xb));
  return (int)(v13 + 0x2005U | -v13 - 0x2005U);
}
int check14(char* ans) {

  int v14 = (get_dword(ans, 0x10) ^ get_dword(ans, 0x1c));
  return (int)(v14 + 0xe817e6e3 | 0x17e8191d - v14);
}
int check15(char* ans) {

  //
  int v15 = (((int)(char)(ans[0x17] ^ *ans) -
              (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
               ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
                 0x1000000 >>
             0x18);
  return (int)(v15 - 0x18U | 0x18U - v15);
}
int check16(char* ans) {
  int v16 = ((((int)get_short(ans, 0x18) - (int)get_short(ans, 0x16)) +
              ((int)get_short(ans, 0) |
               (int)get_short(ans, 6) + (int)get_short(ans, 0xf))) *
                 0x10000 >>
             0x10);
  return (int)(v16 + 0x6840U | -v16 - 0x6840U);
}
int check17(char* ans) {

  int v17 =
      (((int)(char)ans[3] - ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
           0x1000000 >>
       0x18);
  return (int)(v17 - 0x76U | 0x76U - v17);
}
int check18(char* ans) {

  int v18 =
      ((get_dword(ans, 0x1b) ^ get_dword(ans, 0x14)) -
       (get_dword(ans, 0x11) | get_dword(ans, 0xc) | get_dword(ans, 0x1b)));
  return (int)(v18 + 0xe3a3e85c | 0x1c5c17a4 - v18);
}
int check19(char* ans) {

  int v19 = (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18);
  int v19_1 =
      (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18);
  return (v19 + v19 + -0x18 & v19 + -0xc >> 0x1f) -
         ((((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
          -0xc);
}
int check20(char* ans) {
  int v20 = (((int)(short)(get_short(ans, 7) ^ get_short(ans, 0x14)) -
              ((int)get_short(ans, 7) + (int)get_short(ans, 0xc) &
               (int)(short)(get_short(ans, 0xf) | get_short(ans, 0x1b)))) *
                 0x10000 >>
             0x10);
  return ((v20 + -0x21c7 >> 0x1f) - (v20 + -0x21c7) ^ v20 + -0x21c7 >> 0x1f);
}
int check21(char* ans) {

  int v21 = (get_dword(ans, 3) ^ get_dword(ans, 3));
  return (int)(((int)v21 >> 0x1f) - (v21 ^ (int)v21 >> 0x1f));
}
int check22(char* ans) {

  int v22 = (get_dword(ans, 9) | get_dword(ans, 3) ^ get_dword(ans, 0x17));
  return (int)(v22 + 0x20040281 | 0xdffbfd7f - v22);
}
int check23(char* ans) {

  int v23 = (((int)(char)(ans[0x13] ^ ans[4]) -
              (int)(char)(ans[0x1d] | ans[2] ^ ans[0x11])) *
                 0x1000000 >>
             0x18);
  return (int)(v23 + 0x7dU | -v23 - 0x7dU);
}
int check24(char* ans) {

  int v24 = (short)(get_short(ans, 1) ^ get_short(ans, 10) & get_short(ans, 2));
  return ((int)v24 + v24 + 0xa966 & v24 + 0x54b3 >> 0x1f) - (v24 + 0x54b3);
}
int check25(char* ans) {

  int v25 = ((((int)get_short(ans, 0xd) - (int)get_short(ans, 0xc)) +
              (int)(short)(get_short(ans, 0x10) &
                           (get_short(ans, 0xe) | get_short(ans, 0x1e)))) *
                 0x10000 >>
             0x10) +
            0x45e6;

  return ((v25 >> 0x1f) - v25 ^ v25 >> 0x1f);
}
int check26(char* ans) {

  int v26 = (((int)(char)ans[0x17] + (int)(char)(ans[0x1e] | ans[0x18])) *
                 0x1000000 >>
             0x18);
  return (int)(v26 + 0x71U | -v26 - 0x71U);
}
int check27(char* ans) {

  int v27 = (((int)(short)(get_short(ans, 0x15) ^ get_short(ans, 0x10)) -
              ((int)get_short(ans, 4) - (int)get_short(ans, 0x17))) *
                 0x10000 >>
             0x10);

  return (int)(v27 - 0x72a6U | 0x72a6U - v27);
}
int check28(char* ans) {

  int v28 = (short)(get_short(ans, 0x12) | get_short(ans, 0x11)) + 0x3031;
  return ((v28 >> 0x1f) - (v28) ^ v28 >> 0x1f);
}
int check29(char* ans) {

  int v29 = (short)(get_short(ans, 0x14) | get_short(ans, 0xc));
  return ((int)v29 + v29 + 0x2442 & v29 + 0x1221 >> 0x1f) - (v29 + 0x1221);
}
int check30(char* ans) {

  int v30 = (int)(short)(get_short(ans, 7) | get_short(ans, 8) |
                         get_short(ans, 8) -
                             (get_short(ans, 2) ^ get_short(ans, 10)));
  return (int)(v30 + 0x4041U | -v30 - 0x4041U);
}
int check31(char* ans) {

  int v31 = ((
              (get_dword(ans, 7) ^ get_dword(ans, 0xd)) &
              get_dword(ans, 0x10) + get_dword(ans, 0x16) + get_dword(ans, 0)
             ) +
             0x5f0d37f8);

  return (int)((v31 * 2 & (int)v31 >> 0x1f) - v31);
}
int check32(char* ans) {

  int v32 = ((get_dword(ans, 0x17) & get_dword(ans, 0)) + 0xbb7dfb00);
  return (int)(((int)v32 >> 0x1f) - (v32 ^ (int)v32 >> 0x1f));
}
int check33(char* ans) {

  //
  int v33 = (short)(get_short(ans, 7) - get_short(ans, 0xf) ^
                    (get_short(ans, 0x1e) | get_short(ans, 4)) -
                        (get_short(ans, 0x1c) - get_short(ans, 3))) +
            -0x7811;
  return ((v33 >> 0x1f) - v33 ^ v33 >> 0x1f);
}
int check34(char* ans) {

  int v34 = (((int)(char)(ans[0x1f] | ans[0x1e]) -
              ((int)(char)(ans[0x14] ^ ans[7]) &
               (int)(char)ans[1] - (int)(char)*ans)) *
                 0x1000000 >>
             0x18);
  return ((v34 + 0x1c >> 0x1f) - (v34 + 0x1c) ^ v34 + 0x1c >> 0x1f);
}
int check35(char* ans) {
  //
  int v35 =
      (((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
       0x18);
  return ((v35 + -0x57 >> 0x1f) - (v35 + -0x57) ^ v35 + -0x57 >> 0x1f);
}
int check36(char* ans) {

  int v36 = (int)(char)(ans[0xb] + ans[0x12] |
                        ans[8] + ans[7] ^ ans[0x1a] ^ ans[0x1c]);

  return (int)(v36 + 0xbU | -v36 - 0xbU);
}
int check37(char* ans) {

  int v37 = (((int)(char)ans[0xf] - (int)(char)ans[2]) * 0x1000000 >> 0x18);
  return (int)(v37 + 6U | -v37 - 6U);
}
int check38(char* ans) {

  //
  int v38 = ((get_dword(ans, 0x1c) - get_dword(ans, 0xf)) -
             (get_dword(ans, 0xf) & get_dword(ans, 0x11)));

  return (int)(v38 + 0x8962d79a | 0x769d2866 - v38);
}
int check39(char* ans) {

  //
  int v39 = ((get_dword(ans, 2) ^ get_dword(ans, 3) & get_dword(ans, 1)) +
             0x4e550331);

  return (int)(((int)v39 >> 0x1f) - (v39 ^ (int)v39 >> 0x1f));
}
int check40(char* ans) {

  int v40 = (((int)(char)(ans[0x14] & ans[0x12]) +
              (int)(char)(ans[0xb] ^ ans[6] ^ ans[9] ^ ans[0x11])) *
                 0x1000000 >>
             0x18);
  return (int)(v40 - 0x60U | 0x60U - v40);
}
int check41(char* ans) {

  //
  int v41 = (int)(char)(ans[3] & ans[0x14] & ans[0xb]);
  return (int)(((uint)v41 >> 1) - v41);
}
int check42(char* ans) {

  //
  int v42 = (get_dword(ans, 2) - (get_dword(ans, 9) - get_dword(ans, 0xe))) +
            -0x21a2fc12;

  return ((v42 >> 0x1f) - v42 ^ v42 >> 0x1f);
}
int check43(char* ans) {

  //
  int v43 = ((short)(get_short(ans, 0x1b) | get_short(ans, 0x1b) |
                     get_short(ans, 0x17) |
                     get_short(ans, 0x17) & get_short(ans, 0x12)) +
             0x10d3);
  return (v43 * 2 & v43 >> 0x1f) - v43;
}
int check44(char* ans) {

  //
  int v44 = ((get_dword(ans, 0xb) ^ get_dword(ans, 4) - get_dword(ans, 7)) +
             0x5feba26b);

  return (int)((v44 * 2 & (int)v44 >> 0x1f) - v44);
}
int check45(char* ans) {

  //
  int v45 = (get_dword(ans, 2) - get_dword(ans, 0xb) &
             (get_dword(ans, 6) ^ get_dword(ans, 9)));
  return (int)(v45 + 0x57efe51e | 0xa8101ae2 - v45);
}
int check46(char* ans) {

  //
  int v46 = (get_dword(ans, 0x1a) & get_dword(ans, 4) |
             get_dword(ans, 5) ^ get_dword(ans, 0x12) ^ get_dword(ans, 0x1b) ^
                 get_dword(ans, 0xe));

  return (int)((v46 + v46 + 0x8009a0e4 & (int)(v46 + 0x4004d072) >> 0x1f) -
               (v46 + 0x4004d072));
}
int check47(char* ans) {

  int v47 = (get_dword(ans, 1) + get_dword(ans, 6) & get_dword(ans, 0xd) &
             get_dword(ans, 0x1c) + get_dword(ans, 0x1c));
  return (int)(v47 + 0x7ffedf80 | 0x80012080 - v47);
}
int check48(char* ans) {

  //
  int v48 = (((int)(short)(get_short(ans, 0x1e) ^ get_short(ans, 0x10)) +
              ((int)get_short(ans, 1) &
               (int)get_short(ans, 0xb) + (int)get_short(ans, 2))) *
                 0x10000 >>
             0x10);
  return (int)((v48 + -0x55d9 >> 0x1f) -
               (v48 - 0x55d9U ^ v48 + -0x55d9 >> 0x1f));
}
int check49(char* ans) {

  //
  int v49 = ((short)(get_short(ans, 0x13) |
                     get_short(ans, 0x18) + get_short(ans, 6)) +
             0x3009);

  return (v49 * 2 & v49 >> 0x1f) - v49;
}
int check50(char* ans) {

  //
  int v50 = (short)(get_short(ans, 0x15) & get_short(ans, 2) |
                    (get_short(ans, 0x1c) | get_short(ans, 0x13)) -
                        (get_short(ans, 4) & get_short(ans, 0x12))) +
            0x2011;
  return ((v50 >> 0x1f) - (v50) ^ v50 >> 0x1f);
}
int check51(char* ans) {

  //
  int v51 = (((int)(short)(get_short(ans, 0x13) ^ get_short(ans, 0x14)) -
              ((int)get_short(ans, 0x14) - (int)get_short(ans, 0x16))) *
                 0x10000 >>
             0x10);
  return (v51 + v51 + 0xb37e & v51 + 0x59bf >> 0x1f) - (v51 + 0x59bf);
}
int check52(char* ans) {
  int v52 = (int)(short)(get_short(ans, 1) & get_short(ans, 0x12) ^
                         get_short(ans, 0x1e) ^ get_short(ans, 0x1c));
  return (int)(v52 + 0x363cU | -v52 - 0x363cU);
}
int check53(char* ans) {
  int v53 = (int)(ans[0x1f] & (*ans | ans[0x14]));
  return (int)(v53 + 0x30U | -v53 - 0x30U);
}

//int de_main() {
//  int a;
//  printf("1 %u\n", check1());
//  printf("2 %u\n", check2());
//  printf("3 %u\n", check3());
//  printf("4 %u\n", check4());
//  printf("5 %u\n", check5());
//  printf("6 %u\n", check6());
//  printf("7 %u\n", check7());
//  printf("8 %u\n", check8());
//  printf("9 %u\n", check9());
//  printf("10 %u\n", check10());
//  printf("11 %u\n", check11());
//  printf("12 %u\n", check12());
//  printf("13 %u\n", check13());
//  printf("14 %u\n", check14());
//  printf("15 %u\n", check15());
//  printf("16 %u\n", check16());
//  printf("17 %u\n", check17());
//  printf("18 %u\n", check18());
//  printf("19 %u\n", check19());
//  printf("20 %u\n", check20());
//  printf("21 %u\n", check21());
//  printf("22 %u\n", check22());
//  printf("23 %u\n", check23());
//  printf("24 %u\n", check24());
//  printf("25 %u\n", check25());
//  printf("26 %u\n", check26());
//  printf("27 %u\n", check27());
//  printf("28 %u\n", check28());
//  printf("29 %u\n", check29());
//  printf("30 %u\n", check30());
//  printf("31 %u\n", check31());
//  printf("32 %u\n", check32());
//  printf("33 %u\n", check33());
//  printf("34 %u\n", check34());
//  printf("35 %u\n", check35());
//  printf("36 %u\n", check36());
//  printf("37 %u\n", check37());
//  printf("38 %u\n", check38());
//  printf("39 %u\n", check39());
//  printf("40 %u\n", check40());
//  printf("41 %u\n", check41());
//  printf("42 %u\n", check42());
//  printf("43 %u\n", check43());
//  printf("44 %u\n", check44());
//  printf("45 %u\n", check45());
//  printf("46 %u\n", check46());
//  printf("47 %u\n", check47());
//  printf("48 %u\n", check48());
//  printf("49 %u\n", check49());
//  printf("50 %u\n", check50());
//  printf("51 %u\n", check51());
//  printf("52 %u\n", check52());
//  printf("53 %u\n", check53());
//}

//int main() {
//  char buf[0x20] = {0};
//  for(size_t i = 0; i < 32; i++){
//      scanf("%d", buf + i);
//  }
//  //if (check(buf)) {
//  //  puts("ok");
//  //} else {
//  //  puts("no");
//  //}
//}
//
