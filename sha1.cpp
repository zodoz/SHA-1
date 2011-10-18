/**
 * Copyright (c) 2011 Mike Kent
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 ***************************************************************************
 *
 * SHA-1 by Mike Kent 10/14/2011
 *
 * compiled with g++ (Debian 4.3.2-1.1) 4.3.2
 *
 * Before compiling, it is recommend to review the debug, FOUR_SCORE, and
 * TIME_TEST #defines and modify them as desired. These are used to prevent
 * the need for multiple file/functions, awkward flag parsing, and reduce
 * function argument count.
 *
 * To compile:
 * > g++ sha1.cpp
 *
 * To run:
 * > ./a.out
 * or:
 * > ./a.out "<message to hash>"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// 0 = don't show L, R, sum
// 1 = do show L, R, sum
//
// This only applies to the encrypt and decrypt Block functions
#define debug 0

//{{{ helper function
unsigned char* padPlaintext(unsigned char*,int);
void printHex(unsigned char*,int);
void printBinary(unsigned char*,int);
unsigned int getInt(unsigned char* text);
void copyIntToBytes(unsigned int, unsigned char*);
void copyLongToBytes(unsigned long, unsigned char*);
unsigned int il_rotate(unsigned int number, int shift);
//}}}

//{{{ main functions
unsigned char* performSHA1(unsigned char* text, unsigned char* H,
    int length);
void sha1(unsigned char* block, unsigned char* H);
//}}}

int main(int argv, char **argc) {
  /*
   * h0 = 67 45 23 01
   * h1 = EF CD AB 89
   * h3 = 98 BA DC FE
   * h3 = 10 32 54 76
   * h4 = C3 D2 E1 F0
   */
  const char initialH[] = {
    0x67, 0x45, 0x23, 0x01,
    0xEF, 0xCD, 0xAB, 0x89,
    0x98, 0xBA, 0xDC, 0xFE,
    0x10, 0x32, 0x54, 0x76,
    0xC3, 0xD2, 0xE1, 0xF0
  };

  // make H mutable
  unsigned char* H = (unsigned char*)calloc(20,sizeof(unsigned char*));
  memcpy(H,initialH,20);

  unsigned char* text;
  int len;
  if(argv == 1) { // use Four score text if none is given
    const char* ptr = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.";
    len = strlen(ptr);
    // make text mutable
    text = padPlaintext((unsigned char*)ptr,len);
  } else { // assume a string was sent to program
    char* ptr = argc[1];
    len = strlen(ptr);
    text = padPlaintext((unsigned char*)ptr,len);
  }
  performSHA1(text,H,len);

  // print result
  for(int i=0;i<5;i++) {
    printHex(H+(i*4),4);
    printf(" ");
  }
  printf("\n");
  return 0;
}

//{{{ unsigned char* performSHA1(unsigned char*, unsigned char*, int)
/*
 * This function is designed specifically for known texts.
 *
 * Others can be created to call sha1() that handle other formats.
 */
unsigned char* performSHA1(unsigned char* text, unsigned char* H,
    int length) {
  /* The following is suggested as a pre-processing step, however I have
   * chosen to implement it at the end as everything is an appendment
   * operation, it should not effect the processing of the raw text until I
   * get to the last packet.
   *
   * append the bit '1' to the message
   * append 0 ≤ k < 512 bits '0', so that the resulting message length (in
   *   bits)
   * is congruent to 448 (mod 512)
   */

  // get number of packets, assuming no additions and padding is added at
  // end
  unsigned long bitLength = length*8;
  int packets = length/64;
  int bytesLeft = length%64;
  if(bytesLeft > 0) {
    packets++;
  }

  // hash all but the last packet
  for(int i=0;i<packets-1;i++) {
    sha1(text+(64*i),H);
  }

  // Now to take care of the appendments and the last packet(s).
  unsigned char* left = (unsigned char*)calloc(64,sizeof(unsigned char));
  memcpy(left,text+(64*(packets-1)),bytesLeft);
  if(bytesLeft < 64) {
    left[bytesLeft] = 0x80;
  }
  if(bytesLeft+1 < 56) {
    copyLongToBytes(bitLength, left+56);
  }
  sha1(left,H);

  // send another packet if there was not enough space to append msg length
  if(bytesLeft+1 >= 56) {
    left = (unsigned char*)calloc(64,sizeof(unsigned char));
    if(bytesLeft == 0) {
      left[0] = 0x80;
    }
    copyLongToBytes(bitLength, left+56);
    sha1(left,H);
  }
}
//}}}
//{{{ void sha1(unsigned char* block, unsigned char* H)
/*
 * This function is designed to only implement sha1 for a single 512-bit
 * block of data. This can be called by functions that know how to split
 * up different types of data.
 */
void sha1(unsigned char* block, unsigned char* H) {
  unsigned char* words = (unsigned char*)calloc(80*4,sizeof(unsigned char));
  memcpy(words,block,64);

  unsigned int iWord, temp;
  unsigned char *ucWord = (unsigned char*)calloc(4,sizeof(unsigned char));
  for(int i=16; i<80; i++) {
    /* for i from 16 to 79
     *   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
     */
    iWord = getInt(words+((i-3)*4));
    iWord ^= getInt(words+((i-8)*4));
    iWord ^= getInt(words+((i-14)*4));
    iWord ^= getInt(words+((i-16)*4));
    //w[i] = ... -> copy int = 4 bytes
    copyIntToBytes(il_rotate(iWord,1), words+(i*4));
  }

  /* a = h0
   * b = h1
   * c = h2
   * d = h3
   * e = h4
   */
  unsigned int
      a = getInt(H),
      b = getInt(H+4),
      c = getInt(H+8),
      d = getInt(H+12),
      e = getInt(H+16);
  /* Main loop:
   * for i from 0 to 79
   *     if 0 ≤ i ≤ 19 then
   *         f = (b and c) or ((not b) and d)
   *         k = 0x5A827999
   *     else if 20 ≤ i ≤ 39
   *         f = b xor c xor d
   *         k = 0x6ED9EBA1
   *     else if 40 ≤ i ≤ 59
   *         f = (b and c) or (b and d) or (c and d) 
   *         k = 0x8F1BBCDC
   *     else if 60 ≤ i ≤ 79
   *         f = b xor c xor d
   *         k = 0xCA62C1D6
   */
  unsigned int f, k;

  for(int i=0; i<80; i++) {
    if(i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if(i < 40) {
      f = (b ^ c ^ d);
      k = 0x6ED9EBA1;
    } else if(i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = (b ^ c ^ d);
      k = 0xCA62C1D6;
    }
    /* temp = (a leftrotate 5) + f + e + k + w[i]
     * e = d
     * d = c
     * c = b leftrotate 30
     * b = a
     * a = temp
     */
    unsigned int temp = il_rotate(a,5) + f + e + k + getInt(words+(i*4));
    e = d;
    d = c;
    c = il_rotate(b,30);
    b = a;
    a = temp;
  }
  /* Add this chunk's hash to result so far:
   * h0 = h0 + a
   * h1 = h1 + b 
   * h2 = h2 + c
   * h3 = h3 + d
   * h4 = h4 + e
   */
  unsigned int
      aa = getInt(H) + a,
      bb = getInt(H+4) + b,
      cc = getInt(H+8) + c,
      dd = getInt(H+12) + d,
      ee = getInt(H+16) + e;
  copyIntToBytes(aa,H);    //H[0]
  copyIntToBytes(bb,H+4);  //H[1]
  copyIntToBytes(cc,H+8);  //H[2]
  copyIntToBytes(dd,H+12); //H[3]
  copyIntToBytes(ee,H+16); //H[4]
}
//}}}

//{{{ unsigned char* padPlaintext(unsigned char* plaintext, int len)
/*
 * creates a new unsigned char array which is padded at the end with 0s.
 */
unsigned char* padPlaintext(unsigned char* plaintext, int len) {
  int blocks = len/8;
  if(len - (len/8) > 0) {
    blocks ++;
  }
  unsigned char* newPlaintext = (unsigned char*)calloc(8*blocks,
      sizeof(unsigned char));
  memcpy(newPlaintext,plaintext,len);
  return newPlaintext;
}
//}}}
//{{{ void printHex(unsigned char *str, int len)
/*
 * prints a string of characters as hex
 */
void printHex(unsigned char *str, int len) {
  for(int i=0;i<len;i++) {
    printf("%02X",str[i]);
  }
}
//}}}
//{{{ void printBinary(unsigned char *bytes, int len)
/*
 * prints a specified number of bytes in binary with spaces between each
 * byte
 */
void printBinary(unsigned char *bytes, int len) {
  char* binary = (char*)calloc(8,sizeof(char));
  for(int i=0;i<len;i++) {
      unsigned char byte = bytes[i];
    for(int j=0;j<8;j++) {
      if(byte & (1<<(7-j)))
        printf("1");
      else
        printf("0");
    }
    printf(" ");
  }
  printf("\n");
}
//}}}
//{{{ unsigned int getInt(unsigned char *data)
/*
 * convert an character array to an int
 */
unsigned int getInt(unsigned char *data) {
  int T = 0;
  for(int i=0;i<4;i++) {
    // read as big-endian = byte[0] is most significant in integer
    T |= ((unsigned int)data[i]) << ((3-i)*8);
  }
  return T;
}
//}}}
//{{{ void copyIntToBytes(unsigned int i, unsigned char* ptr)
/*
 * copies an int to the unsigned char* used throughout the program
 *
 * This is created because memcpy seems to work backwards. I'm guessing
 * it is because of the endian of this system, but I decided it was better
 * to make my own function than research what endian my cloud server is
 * (of which, then information may not even be available).
 */
void copyIntToBytes(unsigned int i, unsigned char* ptr) {
  for(int j=0;j<4;j++) {
    *(ptr+(3-j)) = (unsigned char)(i>>(8*j));
  }
}
//}}}
//{{{ void copyLongToBytes(unsigned long, unsigned char*)
void copyLongToBytes(unsigned long l, unsigned char* ptr) {
  for(int j=0;j<8;j++) {
    *(ptr+(7-j)) = (unsigned char)(l>>(8*j));
  }
}
//}}}
//{{{ unsigned int il_rotate(unsigned int number, int shift)
/* This function circularly rotates the bits of an integer left by shift
 *
 * precondition: shift is <= 32
 */
unsigned int il_rotate(unsigned int number, int shift) {
  return (number << shift) | (number >> (32-shift));
}
//}}}
