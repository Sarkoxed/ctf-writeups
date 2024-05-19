#include <stdio.h>
#include <unistd.h>
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned char uchar;

//char ans[32] = {78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78};
//
char ans[32] = {118, 50, 161, 43, 121, 184, 159, 131, 36, 231, 64, 240, 241, 63, 173, 85, 73, 205, 89, 108, 41, 27, 2, 155, 45, 225, 155, 123, 230, 234, 107, 187};



int check1() {
  int govno1 =
      ((((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a >>
       0x1f);
  int govno2 =
      ((((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a >>
       0x1f);
  int govno3 =
      ((((int)(char)ans[10] - (int)(char)ans[4]) * 0x1000000 >> 0x18) + 0x5a);

  // ((x >> 0x1f) - x) ^ (x >> 0x1f))
  return (govno1 - govno3 ^ govno2);
}

int check2() {
  int govno1 =
      ((char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb >>
       0x1f);
  int govno2 =
      ((char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb);
  int govno3 =
      ((char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb >>
       0x1f);

   return (govno1 - govno2 ^ govno3);
}

int check3() {
  return (int)(((int)((*(int *)(ans + 8) + *(int *)ans ^
                    (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
                   0x56cb0106) >>
             0x1f) -
            ((*(int *)(ans + 8) + *(int *)ans ^
              (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
                 0x56cb0106 ^
             (int)((*(int *)(ans + 8) + *(int *)ans ^
                    (*(uint *)(ans + 7) | *(uint *)(ans + 3))) +
                   0x56cb0106) >>
                 0x1f)); 
}

int check4() {
  return (int)(((*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
              *(uint *)(ans + 0x11) &
                  (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c))) +
                 (*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
                  *(uint *)(ans + 0x11) &
                      (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c))) +
                 0xd0d747cc &
             (int)((*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
                    *(uint *)(ans + 0x11) &
                        (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c))) +
                   0x686ba3e6) >>
                 0x1f) -
            ((*(uint *)(ans + 10) ^ *(uint *)(ans + 4) ^
              *(uint *)(ans + 0x11) &
                  (*(uint *)(ans + 0x17) ^ *(uint *)(ans + 0x1c))) +
             0x686ba3e6)

                ); 
}

int check5() {
  return (int)((int)(short)(*(short *)(ans + 0xe) + *(short *)(ans + 0x1d) &
                         *(short *)(ans + 0x12) - (*(ushort *)(ans + 0x13) |
                                                   *(ushort *)(ans + 0x1a))) -
                0x2258U |
            0x2258U -
                (int)(short)(*(short *)(ans + 0xe) + *(short *)(ans + 0x1d) &
                             *(short *)(ans + 0x12) -
                                 (*(ushort *)(ans + 0x13) |
                                  *(ushort *)(ans + 0x1a)))); 
}

int check6() {
  return (int)(((int)(((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
                    (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
                     (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14)))) +
                   -0x66d6ff0b) >>
             0x1f) -
            (((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
              (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
               (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14)))) +
                 0x992900f5 ^
             (int)(((*(uint *)(ans + 0x13) ^ *(uint *)(ans + 0x12)) -
                    (*(int *)(ans + 0x18) + *(int *)(ans + 0x11) &
                     (*(uint *)(ans + 7) ^ *(uint *)(ans + 0x14)))) +
                   -0x66d6ff0b) >>
                 0x1f)); 
}

int check7() {
  return (int)((*(uint *)(ans + 0xd) & *(uint *)(ans + 0x12) &
             *(uint *)(ans + 0x16) & *(uint *)ans) +
                0xdfffff80 |
            0x20000080 - (*(uint *)(ans + 0xd) & *(uint *)(ans + 0x12) &
                          *(uint *)(ans + 0x16) & *(uint *)ans)); 
}

int check8() {
  return (int)(((int)((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7) >>
             0x1f) -
                ((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7) ^
            (int)((*(uint *)(ans + 5) & *(uint *)(ans + 6)) + 0xccedf7f7) >>
                0x1f); 
}
int check9() {
  return (int)((int)(short)(*(ushort *)(ans + 0xc) | *(ushort *)(ans + 0x11) |
                         *(ushort *)(ans + 0x11) | *(ushort *)(ans + 0x15)) +
                0x3005U |
            -(int)(short)(*(ushort *)(ans + 0xc) | *(ushort *)(ans + 0x11) |
                          *(ushort *)(ans + 0x11) | *(ushort *)(ans + 0x15)) -
                0x3005U); 
}

int check10() {
  return (int)((((int)(short)(*(ushort *)(ans + 0x1e) & *(ushort *)(ans + 6)) +
              (int)(short)(*(ushort *)(ans + 5) & *(ushort *)(ans + 0x1d))) *
                 0x10000 >>
             0x10) -
                0x1018U |
            0x1018U -
                (((int)(short)(*(ushort *)(ans + 0x1e) & *(ushort *)(ans + 6)) +
                  (int)(short)(*(ushort *)(ans + 5) &
                               *(ushort *)(ans + 0x1d))) *
                     0x10000 >>
                 0x10)); 
}
int check11() {
  return (((((int)(char)(ans[9] | ans[6]) +
          ((int)(char)(ans[0x1e] ^ ans[1]) &
           (int)(char)ans[4] - (int)(char)ans[0x1f])) *
             0x1000000 >>
         0x18) +
            -7 >>
        0x1f) -
           ((((int)(char)(ans[9] | ans[6]) +
              ((int)(char)(ans[0x1e] ^ ans[1]) &
               (int)(char)ans[4] - (int)(char)ans[0x1f])) *
                 0x1000000 >>
             0x18) +
            -7) ^
       (((int)(char)(ans[9] | ans[6]) +
         ((int)(char)(ans[0x1e] ^ ans[1]) &
          (int)(char)ans[4] - (int)(char)ans[0x1f])) *
            0x1000000 >>
        0x18) + -7 >>
           0x1f); 
}
int check12() {
  return ((((((int)(char)ans[10] - (int)(char)ans[0x17]) +
          ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
          (int)(char)(ans[2] & ans[0xb])) *
             0x1000000 >>
         0x18) +
            0xb >>
        0x1f) -
           (((((int)(char)ans[10] - (int)(char)ans[0x17]) +
              ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
              (int)(char)(ans[2] & ans[0xb])) *
                 0x1000000 >>
             0x18) +
            0xb) ^
       ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
         ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
         (int)(char)(ans[2] & ans[0xb])) *
            0x1000000 >>
        0x18) + 0xb >>
           0x1f); 
}
int check13() {
  return (int)((int)(short)(*(ushort *)ans | *(ushort *)(ans + 0xc) |
                         *(ushort *)(ans + 0xb)) +
                0x2005U |
            -(int)(short)(*(ushort *)ans | *(ushort *)(ans + 0xc) |
                          *(ushort *)(ans + 0xb)) -
                0x2005U); 
}
int check14() {
  return (int)((*(uint *)(ans + 0x10) ^ *(uint *)(ans + 0x1c)) + 0xe817e6e3 |
            0x17e8191d - (*(uint *)(ans + 0x10) ^ *(uint *)(ans + 0x1c))); 
}
int check15() {
  return (int)((((int)(char)(ans[0x17] ^ *ans) -
              (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
               ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
                 0x1000000 >>
             0x18) -
                0x18U |
            0x18U - (((int)(char)(ans[0x17] ^ *ans) -
                      (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
                       ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
                         0x1000000 >>
                     0x18)); 
}
int check16() {
  return (int)(((((int)*(short *)(ans + 0x18) - (int)*(short *)(ans + 0x16)) +
              ((int)*(short *)ans |
               (int)*(short *)(ans + 6) + (int)*(short *)(ans + 0xf))) *
                 0x10000 >>
             0x10) +
                0x6840U |
            -((((int)*(short *)(ans + 0x18) - (int)*(short *)(ans + 0x16)) +
               ((int)*(short *)ans |
                (int)*(short *)(ans + 6) + (int)*(short *)(ans + 0xf))) *
                  0x10000 >>
              0x10) -
                0x6840U); 
}
int check17() {
  return (int)((((int)(char)ans[3] -
              ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
                 0x1000000 >>
             0x18) -
                0x76U |
            0x76U - (((int)(char)ans[3] -
                      ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
                         0x1000000 >>
                     0x18)); 
}
int check18() {
  return (int)(((*(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0x14)) -
             (*(uint *)(ans + 0x11) | *(uint *)(ans + 0xc) |
              *(uint *)(ans + 0x1b))) +
                0xe3a3e85c |
            0x1c5c17a4 - ((*(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0x14)) -
                          (*(uint *)(ans + 0x11) | *(uint *)(ans + 0xc) |
                           *(uint *)(ans + 0x1b)))); 
}
int check19() {
  return ((((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
           (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
           -0x18 &
       (((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
               -0xc >>
           0x1f) -
          ((((int)(char)ans[0x16] + (int)(char)ans[0x16]) * 0x1000000 >> 0x18) +
           -0xc);
}
int check20() {
  return (((((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
          ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
           (int)(short)(*(ushort *)(ans + 0xf) | *(ushort *)(ans + 0x1b)))) *
             0x10000 >>
         0x10) +
            -0x21c7 >>
        0x1f) -
           ((((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
              ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
               (int)(short)(*(ushort *)(ans + 0xf) |
                            *(ushort *)(ans + 0x1b)))) *
                 0x10000 >>
             0x10) +
            -0x21c7) ^
       (((int)(short)(*(ushort *)(ans + 7) ^ *(ushort *)(ans + 0x14)) -
         ((int)*(short *)(ans + 7) + (int)*(short *)(ans + 0xc) &
          (int)(short)(*(ushort *)(ans + 0xf) | *(ushort *)(ans + 0x1b)))) *
            0x10000 >>
        0x10) + -0x21c7 >>
           0x1f); 
}
int check21() {
  return (int)(((int)(*(uint *)(ans + 3) ^ *(uint *)(ans + 3)) >> 0x1f) -
            (*(uint *)(ans + 3) ^ *(uint *)(ans + 3) ^
             (int)(*(uint *)(ans + 3) ^ *(uint *)(ans + 3)) >> 0x1f)); 
}
int check22() {
  return (int)((*(uint *)(ans + 9) | *(uint *)(ans + 3) ^ *(uint *)(ans + 0x17)) +
                0x20040281 |
            0xdffbfd7f - (*(uint *)(ans + 9) |
                          *(uint *)(ans + 3) ^ *(uint *)(ans + 0x17))); 
}
int check23() {
  return (int)((((int)(char)(ans[0x13] ^ ans[4]) -
              (int)(char)(ans[0x1d] | ans[2] ^ ans[0x11])) *
                 0x1000000 >>
             0x18) +
                0x7dU |
            -(((int)(char)(ans[0x13] ^ ans[4]) -
               (int)(char)(ans[0x1d] | ans[2] ^ ans[0x11])) *
                  0x1000000 >>
              0x18) -
                0x7dU); 
}
int check24() {
  return ((int)(short)(*(ushort *)(ans + 1) ^
                    *(ushort *)(ans + 10) & *(ushort *)(ans + 2)) +
           (short)(*(ushort *)(ans + 1) ^
                   *(ushort *)(ans + 10) & *(ushort *)(ans + 2)) +
           0xa966 &
       (short)(*(ushort *)(ans + 1) ^
               *(ushort *)(ans + 10) & *(ushort *)(ans + 2)) +
               0x54b3 >>
           0x1f) -
          ((short)(*(ushort *)(ans + 1) ^
                   *(ushort *)(ans + 10) & *(ushort *)(ans + 2)) +
           0x54b3);
}
int check25() {
  return ((((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
          (int)(short)(*(ushort *)(ans + 0x10) &
                       (*(ushort *)(ans + 0xe) | *(ushort *)(ans + 0x1e)))) *
             0x10000 >>
         0x10) +
            0x45e6 >>
        0x1f) -
           (((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
              (int)(short)(*(ushort *)(ans + 0x10) &
                           (*(ushort *)(ans + 0xe) |
                            *(ushort *)(ans + 0x1e)))) *
                 0x10000 >>
             0x10) +
            0x45e6) ^
       ((((int)*(short *)(ans + 0xd) - (int)*(short *)(ans + 0xc)) +
         (int)(short)(*(ushort *)(ans + 0x10) &
                      (*(ushort *)(ans + 0xe) | *(ushort *)(ans + 0x1e)))) *
            0x10000 >>
        0x10) + 0x45e6 >>
           0x1f); 
}
int check26() {
  return (int)((((int)(char)ans[0x17] + (int)(char)(ans[0x1e] | ans[0x18])) *
                 0x1000000 >>
             0x18) +
                0x71U |
            -(((int)(char)ans[0x17] + (int)(char)(ans[0x1e] | ans[0x18])) *
                  0x1000000 >>
              0x18) -
                0x71U); 
}
int check27() {
  return (int)((((int)(short)(*(ushort *)(ans + 0x15) ^ *(ushort *)(ans + 0x10)) -
              ((int)*(short *)(ans + 4) - (int)*(short *)(ans + 0x17))) *
                 0x10000 >>
             0x10) -
                0x72a6U |
            0x72a6U -
                (((int)(short)(*(ushort *)(ans + 0x15) ^
                               *(ushort *)(ans + 0x10)) -
                  ((int)*(short *)(ans + 4) - (int)*(short *)(ans + 0x17))) *
                     0x10000 >>
                 0x10)); 
}
int check28() {
  return (((short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) + 0x3031 >>
        0x1f) -
           ((short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) +
            0x3031) ^
       (short)(*(ushort *)(ans + 0x12) | *(ushort *)(ans + 0x11)) + 0x3031 >>
           0x1f); 
}
int check29() {
  return ((int)(short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc)) +
           (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc)) + 0x2442 &
       (short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc)) + 0x1221 >>
           0x1f) -
          ((short)(*(ushort *)(ans + 0x14) | *(ushort *)(ans + 0xc)) + 0x1221);
}
int check30() {
  return (int)((int)(short)(*(ushort *)(ans + 7) | *(ushort *)(ans + 8) |
                         *(short *)(ans + 8) -
                             (*(ushort *)(ans + 2) ^ *(ushort *)(ans + 10))) +
                0x4041U |
            -(int)(short)(*(ushort *)(ans + 7) | *(ushort *)(ans + 8) |
                          *(short *)(ans + 8) -
                              (*(ushort *)(ans + 2) ^ *(ushort *)(ans + 10))) -
                0x4041U); 
}
int check31() {
  return (int)(((((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
               *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
              0x5f0d37f8) *
                 2 &
             (int)(((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
                    *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
                   0x5f0d37f8) >>
                 0x1f) -
            (((*(uint *)(ans + 7) ^ *(uint *)(ans + 0xd)) &
              *(int *)(ans + 0x10) + *(int *)(ans + 0x16) + *(int *)ans) +
             0x5f0d37f8)); 
}
int check32() {
  return (int)(((int)((*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00) >>
             0x1f) -
            ((*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00 ^
             (int)((*(uint *)(ans + 0x17) & *(uint *)ans) + 0xbb7dfb00) >>
                 0x1f)); 
}
int check33() {
  return (((short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
                (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                    (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
            -0x7811 >>
        0x1f) -
           ((short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
                    (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                        (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
            -0x7811) ^
       (short)(*(short *)(ans + 7) - *(short *)(ans + 0xf) ^
               (*(ushort *)(ans + 0x1e) | *(ushort *)(ans + 4)) -
                   (*(short *)(ans + 0x1c) - *(short *)(ans + 3))) +
               -0x7811 >>
           0x1f); 
}
int check34() {
  return (((((int)(char)(ans[0x1f] | ans[0x1e]) -
          ((int)(char)(ans[0x14] ^ ans[7]) &
           (int)(char)ans[1] - (int)(char)*ans)) *
             0x1000000 >>
         0x18) +
            0x1c >>
        0x1f) -
           ((((int)(char)(ans[0x1f] | ans[0x1e]) -
              ((int)(char)(ans[0x14] ^ ans[7]) &
               (int)(char)ans[1] - (int)(char)*ans)) *
                 0x1000000 >>
             0x18) +
            0x1c) ^
       (((int)(char)(ans[0x1f] | ans[0x1e]) -
         ((int)(char)(ans[0x14] ^ ans[7]) &
          (int)(char)ans[1] - (int)(char)*ans)) *
            0x1000000 >>
        0x18) + 0x1c >>
           0x1f); 
}
int check35() {
  return (((((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
         0x18) +
            -0x57 >>
        0x1f) -
           ((((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) *
                 0x1000000 >>
             0x18) +
            -0x57) ^
       (((int)(char)ans[0x10] - (int)(char)(ans[0xc] & ans[4])) * 0x1000000 >>
        0x18) + -0x57 >>
           0x1f); 
}
int check36() {
  return (int)((int)(char)(ans[0xb] + ans[0x12] |
                        ans[8] + ans[7] ^ ans[0x1a] ^ ans[0x1c]) +
                0xbU |
            -(int)(char)(ans[0xb] + ans[0x12] |
                         ans[8] + ans[7] ^ ans[0x1a] ^ ans[0x1c]) -
                0xbU); 
}
int check37() {
  return (int)((((int)(char)ans[0xf] - (int)(char)ans[2]) * 0x1000000 >> 0x18) +
                6U |
            -(((int)(char)ans[0xf] - (int)(char)ans[2]) * 0x1000000 >> 0x18) -
                6U); 
}
int check38() {
  return (int)(((*(int *)(ans + 0x1c) - *(int *)(ans + 0xf)) -
             (*(uint *)(ans + 0xf) & *(uint *)(ans + 0x11))) +
                0x8962d79a |
            0x769d2866 - ((*(int *)(ans + 0x1c) - *(int *)(ans + 0xf)) -
                          (*(uint *)(ans + 0xf) & *(uint *)(ans + 0x11)))); 
}
int check39() {
  return (int)(((int)((*(uint *)(ans + 2) ^
                    *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
                   0x4e550331) >>
             0x1f) -
            ((*(uint *)(ans + 2) ^ *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
                 0x4e550331 ^
             (int)((*(uint *)(ans + 2) ^
                    *(uint *)(ans + 3) & *(uint *)(ans + 1)) +
                   0x4e550331) >>
                 0x1f)); 
}
int check40() {
  return (int)((((int)(char)(ans[0x14] & ans[0x12]) +
              (int)(char)(ans[0xb] ^ ans[6] ^ ans[9] ^ ans[0x11])) *
                 0x1000000 >>
             0x18) -
                0x60U |
            0x60U - (((int)(char)(ans[0x14] & ans[0x12]) +
                      (int)(char)(ans[0xb] ^ ans[6] ^ ans[9] ^ ans[0x11])) *
                         0x1000000 >>
                     0x18)); 
}
int check41() {
  return (int)(((uint)(int)(char)(ans[3] & ans[0x14] & ans[0xb]) >> 1) -
            (int)(char)(ans[3] & ans[0x14] & ans[0xb])); 
}
int check42() {
  return (((*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
            -0x21a2fc12 >>
        0x1f) -
           ((*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
            -0x21a2fc12) ^
       (*(int *)(ans + 2) - (*(int *)(ans + 9) - *(int *)(ans + 0xe))) +
               -0x21a2fc12 >>
           0x1f); 
}
int check43() {
  return (((short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
                *(ushort *)(ans + 0x17) |
                *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
        0x10d3) *
           2 &
       (short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
               *(ushort *)(ans + 0x17) |
               *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
               0x10d3 >>
           0x1f) -
          ((short)(*(ushort *)(ans + 0x1b) | *(ushort *)(ans + 0x1b) |
                   *(ushort *)(ans + 0x17) |
                   *(ushort *)(ans + 0x17) & *(ushort *)(ans + 0x12)) +
           0x10d3);
}
int check44() {
  return (int)((((*(uint *)(ans + 0xb) ^ *(int *)(ans + 4) - *(int *)(ans + 7)) +
              0x5feba26b) *
                 2 &
             (int)((*(uint *)(ans + 0xb) ^
                    *(int *)(ans + 4) - *(int *)(ans + 7)) +
                   0x5feba26b) >>
                 0x1f) -
            ((*(uint *)(ans + 0xb) ^ *(int *)(ans + 4) - *(int *)(ans + 7)) +
             0x5feba26b)); 
}
int check45() {
  return (int)((*(int *)(ans + 2) - *(int *)(ans + 0xb) &
             (*(uint *)(ans + 6) ^ *(uint *)(ans + 9))) +
                0x57efe51e |
            0xa8101ae2 - (*(int *)(ans + 2) - *(int *)(ans + 0xb) &
                          (*(uint *)(ans + 6) ^ *(uint *)(ans + 9)))); 
}
int check46() {
  return (int)(((*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
              *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                  *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe)) +
                 (*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
                  *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                      *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe)) +
                 0x8009a0e4 &
             (int)((*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
                    *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                        *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe)) +
                   0x4004d072) >>
                 0x1f) -
            ((*(uint *)(ans + 0x1a) & *(uint *)(ans + 4) |
              *(uint *)(ans + 5) ^ *(uint *)(ans + 0x12) ^
                  *(uint *)(ans + 0x1b) ^ *(uint *)(ans + 0xe)) +
             0x4004d072)); 
}
int check47() {
  return (int)((*(int *)(ans + 1) + *(int *)(ans + 6) & *(uint *)(ans + 0xd) &
             *(int *)(ans + 0x1c) + *(int *)(ans + 0x1c)) +
                0x7ffedf80 |
            0x80012080 -
                (*(int *)(ans + 1) + *(int *)(ans + 6) & *(uint *)(ans + 0xd) &
                 *(int *)(ans + 0x1c) + *(int *)(ans + 0x1c))); 
}
int check48() {
  return (int)(((((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
               ((int)*(short *)(ans + 1) &
                (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
                  0x10000 >>
              0x10) +
                 -0x55d9 >>
             0x1f) -
            ((((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
               ((int)*(short *)(ans + 1) &
                (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
                  0x10000 >>
              0x10) -
                 0x55d9U ^
             (((int)(short)(*(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x10)) +
               ((int)*(short *)(ans + 1) &
                (int)*(short *)(ans + 0xb) + (int)*(short *)(ans + 2))) *
                  0x10000 >>
              0x10) + -0x55d9 >>
                 0x1f)); 
}
int check49() {
  return (((short)(*(ushort *)(ans + 0x13) |
                *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
        0x3009) *
           2 &
       (short)(*(ushort *)(ans + 0x13) |
               *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
               0x3009 >>
           0x1f) -
          ((short)(*(ushort *)(ans + 0x13) |
                   *(short *)(ans + 0x18) + *(short *)(ans + 6)) +
           0x3009);
  return 1;
}
int check50() {
  return (((short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
                (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                    (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
            0x2011 >>
        0x1f) -
           ((short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
                    (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                        (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
            0x2011) ^
       (short)(*(ushort *)(ans + 0x15) & *(ushort *)(ans + 2) |
               (*(ushort *)(ans + 0x1c) | *(ushort *)(ans + 0x13)) -
                   (*(ushort *)(ans + 4) & *(ushort *)(ans + 0x12))) +
               0x2011 >>
           0x1f); 
}
int check51() {
  return ((((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
         ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
            0x10000 >>
        0x10) +
           (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
             ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
                0x10000 >>
            0x10) +
           0xb37e &
       (((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
         ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
            0x10000 >>
        0x10) + 0x59bf >>
           0x1f) -
          ((((int)(short)(*(ushort *)(ans + 0x13) ^ *(ushort *)(ans + 0x14)) -
             ((int)*(short *)(ans + 0x14) - (int)*(short *)(ans + 0x16))) *
                0x10000 >>
            0x10) +
           0x59bf);
}

int check52() {
  return (int)((int)(short)(*(ushort *)(ans + 1) & *(ushort *)(ans + 0x12) ^
                         *(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x1c)) +
                0x363cU |
            -(int)(short)(*(ushort *)(ans + 1) & *(ushort *)(ans + 0x12) ^
                          *(ushort *)(ans + 0x1e) ^ *(ushort *)(ans + 0x1c)) -
                0x363cU); 
}

int check53() {
  return (int)((int)(char)(ans[0x1f] & (*ans | ans[0x14])) + 0x30U |
            -(int)(char)(ans[0x1f] & (*ans | ans[0x14])) - 0x30U); 
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
