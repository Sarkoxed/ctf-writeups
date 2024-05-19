#include <stdio.h>
#include <unistd.h>
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned char uchar;

//char ans[32] = {78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78};
//
char ans[32] = {118, 50, 161, 43, 121, 184, 159, 131, 36, 231, 64, 240, 241, 63, 173, 85, 73, 205, 89, 108, 41, 27, 2, 155, 45, 225, 155, 123, 230, 234, 107, 187};



int check1(){
  int v1 =
      (((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a;
  int v1_1 =
      ((((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a);
  int v1_2 =
      (((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a;
  return ((v1 >> 0x1f) - v1 ^ v1 >> 0x1f);
}

int check2(){
  int v2 = (char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb;
  int v2_1 = (char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb;
  int v2_2 = (char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb;
  return ((v2 >> 0x1f) - v2 ^ v2 >> 0x1f);
}
int check3(){

  int v3 = ((*(int *)(ans + 8) + *(int *)ans ^
             (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
            0x56cb0106);
  int v3_1 = (*(int *)(ans + 8) + *(int *)ans ^
              (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
             0x56cb0106;
  int v3_2 = ((*(int *)(ans + 8) + *(int *)ans ^
               (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
              0x56cb0106);
  return (int)(((int)v3 >> 0x1f) - (v3 ^ (int)v3 >> 0x1f));
}
int check4(){

  int v4 =
      (*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
       *(uint *)(ans + 0x11) & (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c)));
  int v4_1 =
      (*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
       *(uint *)(ans + 0x11) & (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c)));
  int v4_2 =
      (*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
       *(uint *)(ans + 0x11) & (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c)));
  int v4_3 =
      (*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
       *(uint *)(ans + 0x11) & (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c)));
  return (int)((v4 + v4 + 0xd0d747cc & (int)(v4 + 0x686ba3e6) >> 0x1f) -
            (v4 + 0x686ba3e6));
 }
int check5(){

  int v5 = (int)(short)(*(short *)(ans + 0xe) + *(short *)(ans + 0x1d) &
                        *(short *)(ans + 0x12) - (*(ushort *)(ans + 0x13) |
                                                  *(ushort *)(ans + 0x1a)));
  int v5_1 = (int)(short)(*(short *)(ans + 0xe) + *(short *)(ans + 0x1d) &
                          *(short *)(ans + 0x12) - (*(ushort *)(ans + 0x13) |
                                                    *(ushort *)(ans + 0x1a)));
  return (int)(v5 - 0x2258U | 0x2258U - v5);
}
int check6(){

  int v6 = ((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
            (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
             (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14))));
  int v6_1 = ((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
              (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
               (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14))));
  int v6_2 = ((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
              (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
               (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14))));
  return (int)(((int)(v6 + -0x66d6ff0b) >> 0x1f) -
            (v6 + 0x992900f5 ^ (int)(v6 + -0x66d6ff0b) >> 0x1f));

}
int check7(){

  int v7 = (*(uint *)(ans + 0xd) & *(uint *)(ans + 0x12) &
            *(uint *)(ans + 0x16) & *(uint *)ans);
  int v7_1 = (*(uint *)(ans + 0xd) & *(uint *)(ans + 0x12) &
              *(uint *)(ans + 0x16) & *(uint *)ans);
  return (int)(v7 + 0xdfffff80 | 0x20000080 - v7);
}
int check8(){

  int v8 = ((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7);
  int v8_1 = ((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7);
  int v8_2 = ((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7);
  return (int)(((int)v8 >> 0x1f) - v8 ^ (int)v8 >> 0x1f);
}
int check9(){

  int v9 = (int)(short)(*(ushort *)(ans + 0xc) | *(ushort *)(ans + 0x11) |
                        *(ushort *)(ans + 0x11) | *(ushort *)(ans + 0x15));
  int v9_1 = (int)(short)(*(ushort *)(ans + 0xc) | *(ushort *)(ans + 0x11) |
                          *(ushort *)(ans + 0x11) | *(ushort *)(ans + 0x15));

  return (int)(v9 + 0x3005U | -v9 - 0x3005U);
}
int check10(){

  int v10 = (((int)(short)(*(ushort *)(ans + 0x1e) & *(ushort *)(ans + 6)) +
              (int)(short)(*(ushort *)(ans + 5) & *(ushort *)(ans + 0x1d))) *
                 0x10000 >>
             0x10);
  int v10_1 = (((int)(short)(*(ushort *)(ans + 0x1e) & *(ushort *)(ans + 6)) +
                (int)(short)(*(ushort *)(ans + 5) & *(ushort *)(ans + 0x1d))) *
                   0x10000 >>
               0x10);
  return (int)(v10 - 0x1018U | 0x1018U - v10);
}
int check11(){

  int v11 = (((int)(char)(ans[9] | ans[6]) +
              ((int)(char)(ans[0x1e] ^ ans[1]) &
               (int)(char)ans[4] - (int)(char)ans[0x1f])) *
                 0x1000000 >>
             0x18);
  int v11_1 = (((int)(char)(ans[9] | ans[6]) +
                ((int)(char)(ans[0x1e] ^ ans[1]) &
                 (int)(char)ans[4] - (int)(char)ans[0x1f])) *
                   0x1000000 >>
               0x18);
  int v11_2 = (((int)(char)(ans[9] | ans[6]) +
                ((int)(char)(ans[0x1e] ^ ans[1]) &
                 (int)(char)ans[4] - (int)(char)ans[0x1f])) *
                   0x1000000 >>
               0x18);
  return ((v11 + -7 >> 0x1f) - (v11 + -7) ^ v11 + -7 >> 0x1f);
}
int check12(){

  int v12 = ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
              ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
              (int)(char)(ans[2] & ans[0xb])) *
                 0x1000000 >>
             0x18);
  int v12_1 = ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
                ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
                (int)(char)(ans[2] & ans[0xb])) *
                   0x1000000 >>
               0x18);
  int v12_2 = ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
                ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
                (int)(char)(ans[2] & ans[0xb])) *
                   0x1000000 >>
               0x18);

  return ((v12 + 0xb >> 0x1f) - (v12 + 0xb) ^ v12 + 0xb >> 0x1f);
}
int check13(){

  int v13 = (int)(short)(*(ushort *)ans | *(ushort *)(ans + 0xc) |
                         *(ushort *)(ans + 0xb));
  int v13_1 = (int)(short)(*(ushort *)ans | *(ushort *)(ans + 0xc) |
                           *(ushort *)(ans + 0xb));
  return (int)(v13 + 0x2005U | -v13 - 0x2005U);
}
int check14(){

  int v14 = (*(uint *)(ans + 0x10) ^ *(uint *)(ans + 0x1c));
  int v14_1 = (*(uint *)(ans + 0x10) ^ *(uint *)(ans + 0x1c));
  return (int)(v14 + 0xe817e6e3 | 0x17e8191d - v14);
}
int check15(){

  //
  int v15 = (((int)(char)(ans[0x17] ^ *ans) -
              (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
               ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
                 0x1000000 >>
             0x18);
  int v15_1 = (((int)(char)(ans[0x17] ^ *ans) -
                (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
                 ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
                   0x1000000 >>
               0x18);
  return (int)(v15 - 0x18U | 0x18U - v15);
}
int check16(){

  //
  int v16 = ((((int)*(short *)(ans + 0x18) - (int)*(short *)(ans + 0x16)) +
              ((int)*(short *)ans |
               (int)*(short *)(ans + 6) + (int)*(short *)(ans + 0xf))) *
                 0x10000 >>
             0x10);
  int v16_1 = ((((int)*(short *)(ans + 0x18) - (int)*(short *)(ans + 0x16)) +
                ((int)*(short *)ans |
                 (int)*(short *)(ans + 6) + (int)*(short *)(ans + 0xf))) *
                   0x10000 >>
               0x10);

  return (int)(v16 + 0x6840U | -v16 - 0x6840U);
}
int check17(){

  int v17 =
      (((int)(char)ans[3] - ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
           0x1000000 >>
       0x18);
  int v17_1 =
      (((int)(char)ans[3] - ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
           0x1000000 >>
       0x18);
  return (int)(v17 - 0x76U | 0x76U - v17);
}
int check18(){

  int v18 =
      ((*(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0x14)) -
       (*(uint *)(ans + 0x11) | *(uint *)(ans + 0xc) | *(uint *)(ans + 0x1b)));
  int v18_1 =
      ((*(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0x14)) -
       (*(uint *)(ans + 0x11) | *(uint *)(ans + 0xc) | *(uint *)(ans + 0x1b)));
  return (int)(v18 + 0xe3a3e85c | 0x1c5c17a4 - v18);
}
int check19(){

  int v19 = (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18);
  int v19_1 =
      (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18);
  int v19_2 =
      (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18);
  return (v19 + v19 + -0x18 & v19 + -0xc >> 0x1f) -
          ((((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
           -0xc);
} 
int check20(){
  int v20 =
      (((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
         (int)(short)(*(ushort *)(ans + 0xf) | *(ushort *)(ans + 0x1b)))) *
           0x10000 >>
       0x10);
  int v20_1 =
      (((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
         (int)(short)(*(ushort *)(ans + 0xf) | *(ushort *)(ans + 0x1b)))) *
           0x10000 >>
       0x10);
  int v20_2 =
      (((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
         (int)(short)(*(ushort *)(ans + 0xf) | *(ushort *)(ans + 0x1b)))) *
           0x10000 >>
       0x10);

  return ((v20 + -0x21c7 >> 0x1f) - (v20 + -0x21c7) ^ v20 + -0x21c7 >> 0x1f);
}
int check21(){

  int v21 = (*(uint *)(ans + 3) ^ *(uint *)(ans + 3));
  int v21_1 = *(uint *)(ans + 3) ^ *(uint *)(ans + 3);
  int v21_2 = (*(uint *)(ans + 3) ^ *(uint *)(ans + 3));
  return (int)(((int)v21 >> 0x1f) - (v21 ^ (int)v21 >> 0x1f));
}
int check22(){

  int v22 = (*(uint *)(ans + 9) | *(uint *)(ans + 3) ^ *(uint *)(ans + 0x17));
  int v22_1 = (*(uint *)(ans + 9) | *(uint *)(ans + 3) ^ *(uint *)(ans + 0x17));
  return (int)(v22 + 0x20040281 | 0xdffbfd7f - v22);
}
int check23(){

  int v23 = (((int)(char)(ans[0x13] ^ ans[4]) -
              (int)(char)(ans[0x1d] | ans[2] ^ ans[0x11])) *
                 0x1000000 >>
             0x18);
  int v23_1 = (((int)(char)(ans[0x13] ^ ans[4]) -
                (int)(char)(ans[0x1d] | ans[2] ^ ans[0x11])) *
                   0x1000000 >>
               0x18);
  return (int)(v23 + 0x7dU | -v23 - 0x7dU);
}
int check24(){

  int v24 = (short)(*(ushort *)(ans + 1) ^
                    *(ushort *)(ans + 10) & *(ushort *)(ans + 2));
  int v24_1 = (short)(*(ushort *)(ans + 1) ^
                      *(ushort *)(ans + 10) & *(ushort *)(ans + 2));
  int v24_2 = (short)(*(ushort *)(ans + 1) ^
                      *(ushort *)(ans + 10) & *(ushort *)(ans + 2));
  int v24_3 = (short)(*(ushort *)(ans + 1) ^
                      *(ushort *)(ans + 10) & *(ushort *)(ans + 2));
  return ((int)v24 + v24 + 0xa966 & v24 + 0x54b3 >> 0x1f) - (v24 + 0x54b3);
}
int check25(){

  int v25 =
      ((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
        (int)(short)(*(ushort *)(ans + 0x10) &
                     (*(ushort *)(ans + 0xe) | *(ushort *)(ans + 0x1e)))) *
           0x10000 >>
       0x10) +
      0x45e6;
  int v25_1 =
      (((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
         (int)(short)(*(ushort *)(ans + 0x10) &
                      (*(ushort *)(ans + 0xe) | *(ushort *)(ans + 0x1e)))) *
            0x10000 >>
        0x10) +
       0x45e6);
  int v25_2 =
      ((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
        (int)(short)(*(ushort *)(ans + 0x10) &
                     (*(ushort *)(ans + 0xe) | *(ushort *)(ans + 0x1e)))) *
           0x10000 >>
       0x10) +
      0x45e6;
  return ((v25 >> 0x1f) - v25 ^ v25 >> 0x1f);
}
int check26(){

  int v26 = (((int)(char)ans[0x17] + (int)(char)(ans[0x1e] | ans[0x18])) *
                 0x1000000 >>
             0x18);
  int v26_1 = (((int)(char)ans[0x17] + (int)(char)(ans[0x1e] | ans[0x18])) *
                   0x1000000 >>
               0x18);
  return (int)(v26 + 0x71U | -v26 - 0x71U);
}
int check27(){

  int v27 = (((int)(short)(*(ushort *)(ans + 0x15) ^ *(ushort *)(ans + 0x10)) -
              ((int)*(short *)(ans + 4) - (int)*(short *)(ans + 0x17))) *
                 0x10000 >>
             0x10);
  int v27_1 =
      (((int)(short)(*(ushort *)(ans + 0x15) ^ *(ushort *)(ans + 0x10)) -
        ((int)*(short *)(ans + 4) - (int)*(short *)(ans + 0x17))) *
           0x10000 >>
       0x10);
  return (int)(v27 - 0x72a6U | 0x72a6U - v27);
}
int check28(){

  int v28 = (short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) + 0x3031;
  int v28_1 =
      (short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) + 0x3031;
  int v28_2 =
      (short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) + 0x3031;
  return ((v28 >> 0x1f) - (v28) ^ v28 >> 0x1f);
}
int check29(){

  int v29 = (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc));
  int v29_1 = (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc));
  int v29_2 = (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc));
  int v29_3 = (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc));
  return ((int)v29 + v29 + 0x2442 & v29 + 0x1221 >> 0x1f) - (v29 + 0x1221);
}
int check30(){

  int v30 = (int)(short)(*(ushort *)(ans + 7) | *(ushort *)(ans + 8) |
                         *(short *)(ans + 8) -
                             (*(ushort *)(ans + 2) ^ *(ushort *)(ans + 10)));
  int v30_1 = (int)(short)(*(ushort *)(ans + 7) | *(ushort *)(ans + 8) |
                           *(short *)(ans + 8) -
                               (*(ushort *)(ans + 2) ^ *(ushort *)(ans + 10)));
  return (int)(v30 + 0x4041U | -v30 - 0x4041U);
}
int check31(){

  int v31 = (((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
              *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
             0x5f0d37f8);
  int v31_1 = (((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
                *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
               0x5f0d37f8);
  int v31_2 = (((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
                *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
               0x5f0d37f8);
  return (int)((v31 * 2 & (int)v31 >> 0x1f) - v31);
}
int check32(){

  int v32 = ((*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00);
  int v32_1 = (*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00;
  int v32_2 = ((*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00);
  return (int)(((int)v32 >> 0x1f) - (v32 ^ (int)v32 >> 0x1f));
}
int check33(){

  //
  int v33 = (short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
                    (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                        (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
            -0x7811;
  int v33_1 = ((short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
                       (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                           (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
               -0x7811);
  int v33_2 = (short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
                      (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                          (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
              -0x7811;

  return ((v33 >> 0x1f) - v33 ^ v33 >> 0x1f);
}
int check34(){

  int v34 = (((int)(char)(ans[0x1f] | ans[0x1e]) -
              ((int)(char)(ans[0x14] ^ ans[7]) &
               (int)(char)ans[1] - (int)(char)*ans)) *
                 0x1000000 >>
             0x18);
  int v34_1 = (((int)(char)(ans[0x1f] | ans[0x1e]) -
                ((int)(char)(ans[0x14] ^ ans[7]) &
                 (int)(char)ans[1] - (int)(char)*ans)) *
                   0x1000000 >>
               0x18);
  int v34_2 = (((int)(char)(ans[0x1f] | ans[0x1e]) -
                ((int)(char)(ans[0x14] ^ ans[7]) &
                 (int)(char)ans[1] - (int)(char)*ans)) *
                   0x1000000 >>
               0x18);

  return ((v34 + 0x1c >> 0x1f) - (v34 + 0x1c) ^ v34 + 0x1c >> 0x1f);
}
int check35(){
  //
  int v35 =
      (((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
       0x18);
  int v35_1 =
      (((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
       0x18);
  int v35_2 =
      (((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
       0x18);
  return ((v35 + -0x57 >> 0x1f) - (v35 + -0x57) ^ v35 + -0x57 >> 0x1f);
}
int check36(){

  int v36 = (int)(char)(ans[0xb] + ans[0x12] |
                        ans[8] + ans[7] ^ ans[0x1a] ^ ans[0x1c]);
  int v36_1 = (int)(char)(ans[0xb] + ans[0x12] |
                          ans[8] + ans[7] ^ ans[0x1a] ^ ans[0x1c]);
  return (int)(v36 + 0xbU | -v36 -0xbU);
}
int check37(){

  int v37 = (((int)(char)ans[0xf] - (int)(char)ans[2]) * 0x1000000 >> 0x18);
  int v37_1 = (((int)(char)ans[0xf] - (int)(char)ans[2]) * 0x1000000 >> 0x18);
  return (int)(v37 + 6U | -v37 - 6U);
}
int check38(){

  //
  int v38 = ((*(int *)(ans + 0x1c) - *(int *)(ans + 0xf)) -
             (*(uint *)(ans + 0xf) & *(uint *)(ans + 0x11)));
  int v38_1 = ((*(int *)(ans + 0x1c) - *(int *)(ans + 0xf)) -
               (*(uint *)(ans + 0xf) & *(uint *)(ans + 0x11)));
  return (int)(v38 + 0x8962d79a | 0x769d2866 - v38);
}
int check39(){

  //
  int v39 = ((*(uint *)(ans + 2) ^ *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
             0x4e550331);
  int v39_1 = (*(uint *)(ans + 2) ^ *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
              0x4e550331;
  int v39_2 = ((*(uint *)(ans + 2) ^ *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
               0x4e550331);
  return (int)(((int)v39 >> 0x1f) - (v39 ^ (int)v39 >> 0x1f));
}
int check40(){

  int v40 = (((int)(char)(ans[0x14] & ans[0x12]) +
              (int)(char)(ans[0xb] ^ ans[6] ^ ans[9] ^ ans[0x11])) *
                 0x1000000 >>
             0x18);
  int v40_1 = (((int)(char)(ans[0x14] & ans[0x12]) +
                (int)(char)(ans[0xb] ^ ans[6] ^ ans[9] ^ ans[0x11])) *
                   0x1000000 >>
               0x18);
  return (int)(v40 - 0x60U | 0x60U - v40);
}
int check41(){

  //
  int v41 = (int)(char)(ans[3] & ans[0x14] & ans[0xb]);
  int v41_1 = (int)(char)(ans[3] & ans[0x14] & ans[0xb]);
  return (int)(((uint)v41 >> 1) - v41);
}
int check42(){

  //
  int v42 = (*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
            -0x21a2fc12;
  int v42_1 = ((*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
               -0x21a2fc12);
  int v42_2 = (*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
              -0x21a2fc12;
  return ((v42 >> 0x1f) - v42 ^ v42 >> 0x1f);
}
int check43(){

  //
  int v43 = ((short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
                     *(ushort *)(ans + 0x17) |
                     *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
             0x10d3);
  int v43_1 = (short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
                      *(ushort *)(ans + 0x17) |
                      *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
              0x10d3;
  int v43_2 = ((short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
                       *(ushort *)(ans + 0x17) |
                       *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
               0x10d3);

  return (v43 * 2 & v43 >> 0x1f) - v43;
}
int check44(){

  //
  int v44 = ((*(uint *)(ans + 0xb) ^ *(int *)(ans + 4) - *(int *)(ans + 7)) +
             0x5feba26b);
  int v44_1 = ((*(uint *)(ans + 0xb) ^ *(int *)(ans + 4) - *(int *)(ans + 7)) +
               0x5feba26b);
  int v44_2 = ((*(uint *)(ans + 0xb) ^ *(int *)(ans + 4) - *(int *)(ans + 7)) +
               0x5feba26b);
  return (int)((v44 * 2 & (int)v44 >> 0x1f) - v44);
}
int check45(){

  //
  int v45 = (*(int *)(ans + 2) - *(int *)(ans + 0xb) &
             (*(uint *)(ans + 6) ^ *(uint *)(ans + 9)));
  int v45_1 = (*(int *)(ans + 2) - *(int *)(ans + 0xb) &
               (*(uint *)(ans + 6) ^ *(uint *)(ans + 9)));
  return (int)(v45 + 0x57efe51e | 0xa8101ae2 - v45);
}
int check46(){

  //
  int v46 = (*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
             *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                 *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe));
  int v46_1 = (*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
               *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                   *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe));
  int v46_2 = (*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
               *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                   *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe));
  int v46_3 = (*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
               *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                   *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe));
  return (int)((v46 + v46 + 0x8009a0e4 & (int)(v46 + 0x4004d072) >> 0x1f) -
            (v46 + 0x4004d072));
}
int check47(){

  int v47 = (*(int *)(ans + 1) + *(int *)(ans + 6) & *(uint *)(ans + 0xd) &
             *(int *)(ans + 0x1c) + *(int *)(ans + 0x1c));
  int v47_1 = (*(int *)(ans + 1) + *(int *)(ans + 6) & *(uint *)(ans + 0xd) &
               *(int *)(ans + 0x1c) + *(int *)(ans + 0x1c));
  return (int)(v47 + 0x7ffedf80 | 0x80012080 - v47);
}
int check48(){

  //
  int v48 = (((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
              ((int)*(short *)(ans + 1) &
               (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
                 0x10000 >>
             0x10);
  int v48_1 =
      (((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
        ((int)*(short *)(ans + 1) &
         (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
           0x10000 >>
       0x10);
  int v48_2 =
      (((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
        ((int)*(short *)(ans + 1) &
         (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
           0x10000 >>
       0x10);
  return (int)((v48 + -0x55d9 >> 0x1f) - (v48 - 0x55d9U ^ v48 + -0x55d9 >> 0x1f));
}
int check49(){

  //
  int v49 = ((short)(*(ushort *)(ans + 0x13) |
                     *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
             0x3009);
  int v49_1 = (short)(*(ushort *)(ans + 0x13) |
                      *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
              0x3009;
  int v49_2 = ((short)(*(ushort *)(ans + 0x13) |
                       *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
               0x3009);
  return (v49 * 2 & v49 >> 0x1f) - v49;
}
int check50(){

  //
  int v50 = (short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
                    (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                        (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
            0x2011;
  int v50_1 = (short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
                      (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                          (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
              0x2011;

  int v50_2 = (short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
                      (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                          (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
              0x2011;

  return ((v50 >> 0x1f) - (v50) ^ v50 >> 0x1f);
}
int check51(){

  //
  int v51 = (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
              ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
                 0x10000 >>
             0x10);
  int v51_1 =
      (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
           0x10000 >>
       0x10);
  int v51_2 =
      (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
           0x10000 >>
       0x10);
  int v51_3 =
      (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
        ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
           0x10000 >>
       0x10);

  return (v51 + v51 + 0xb37e & v51 + 0x59bf >> 0x1f) - (v51 + 0x59bf);
}
int check52(){

  //
  int v52 = (int)(short)(*(ushort *)(ans + 1) & *(ushort *)(ans + 0x12) ^
                         *(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x1c));
  int v52_1 = (int)(short)(*(ushort *)(ans + 1) & *(ushort *)(ans + 0x12) ^
                           *(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x1c));
//  printf("52: %d\n", v52 == v52_1);

  return (int)(v52 + 0x363cU | -v52_1 - 0x363cU);
}
int check53(){

  //
  int v53 = (int)(char)(ans[0x1f] & (*ans | ans[0x14]));
  int v53_1 = (int)(char)(ans[0x1f] & (*ans | ans[0x14]));
  return (int)(v53 + 0x30U | -v53_1 - 0x30U);
}

int main(){
int a;
printf("1 %d\n", check1());
printf("2 %d\n", check2());
printf("3 %d\n", check3());
printf("4 %d\n", check4());
printf("5 %d\n", check5());
printf("6 %d\n", check6());
printf("7 %d\n", check7());
printf("8 %d\n", check8());
printf("9 %d\n", check9());
printf("10 %d\n", check10());
printf("11 %d\n", check11());
printf("12 %d\n", check12());
printf("13 %d\n", check13());
printf("14 %d\n", check14());
printf("15 %d\n", check15());
printf("16 %d\n", check16());
printf("17 %d\n", check17());
printf("18 %d\n", check18());
printf("19 %d\n", check19());
printf("20 %d\n", check20());
printf("21 %d\n", check21());
printf("22 %d\n", check22());
printf("23 %d\n", check23());
printf("24 %d\n", check24());
printf("25 %d\n", check25());
printf("26 %d\n", check26());
printf("27 %d\n", check27());
printf("28 %d\n", check28());
printf("29 %d\n", check29());
printf("30 %d\n", check30());
printf("31 %d\n", check31());
printf("32 %d\n", check32());
printf("33 %d\n", check33());
printf("34 %d\n", check34());
printf("35 %d\n", check35());
printf("36 %d\n", check36());
printf("37 %d\n", check37());
printf("38 %d\n", check38());
printf("39 %d\n", check39());
printf("40 %d\n", check40());
printf("41 %d\n", check41());
printf("42 %d\n", check42());
printf("43 %d\n", check43());
printf("44 %d\n", check44());
printf("45 %d\n", check45());
printf("46 %d\n", check46());
printf("47 %d\n", check47());
printf("48 %d\n", check48());
printf("49 %d\n", check49());
printf("50 %d\n", check50());
printf("51 %d\n", check51());
printf("52 %d\n", check52());
printf("53 %d\n", check53());
}
//int main() {
//  uchar buf[0x20] = {0};
//  read(0, buf, 0x20);
//  if (check(buf)) {
//    puts("ok");
//  } else {
//    puts("no");
//  }
//}
