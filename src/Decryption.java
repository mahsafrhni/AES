import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Decryption {
    static char[][] inverseSbox = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
    static char[][] sbox = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, //0
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, //1
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, //2
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, //3
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, //4
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, //5
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, //6
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, //7
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, //8
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, //9
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, //A
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, //B
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, //C
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, //D
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, //E
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}; //F

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        String key = input.next();
        String ciphertext = input.next();
        String[] w = new String[44];
        String[] Rconst = {"01000000", "02000000", "04000000", "08000000", "10000000", "20000000",
                "40000000", "80000000", "1b000000", "36000000"};
        for (int i = 0; i < 44; i++) {
            if (i < 4) {
                w[i] = key.substring(8 * i, (8 * i) + 8);
            } else {
                if (i % 4 != 0) {
                    w[i] = xorforHexadecimals(w[i - 1], w[i - 4]);
                    if (w[i].length() < 8) {
                        int count = 8 - w[i].length();
                        for (int j = 0; j < count; j++) {
                            w[i] = ("0").concat(w[i]);
                        }
                    }
                } else {
                    if (w[i - 1].length() < 8) {
                        int count = 8 - w[i - 1].length();
                        for (int j = 0; j < count; j++) {
                            w[i - 1] = ("0").concat(w[i - 1]);
                        }
                    }
                    if (w[i - 4].length() < 8) {
                        int count = 8 - w[i - 4].length();
                        for (int j = 0; j < count; j++) {
                            w[i - 4] = ("0").concat(w[i - 4]);
                        }
                    }
                    String[] test = subByteForKey((w[i - 1]).substring(2) + (w[i - 1]).substring(0, 2));
                    String subByted = test[0].concat(test[1]).concat(test[2]).concat(test[3]);
                    w[i] = xorforHexadecimals(xorforHexadecimals(subByted, Rconst[(i / 4) - 1]), w[i - 4]);
                    if (w[i].length() < 8) {
                        int count = 8 - w[i].length();
                        for (int j = 0; j < count; j++) {
                            w[i] = ("0").concat(w[i]);
                        }
                    }
                }
            }
        }
        List<String> parts = getParts(ciphertext);
        String newCipherText1 = "";
        String newCipherText2 = "";
        String newCipherText3 = "";
        String newCipherText4 = "";
        String newCipherText;
        for (int i = 0; i < 25; i += 8) {
            newCipherText1 = newCipherText1.concat(parts.get(i).concat(parts.get(i + 1)));
        }
        for (int i = 2; i < 27; i += 8) {
            newCipherText2 = newCipherText2.concat(parts.get(i).concat(parts.get(i + 1)));
        }
        for (int i = 4; i < 29; i += 8) {
            newCipherText3 = newCipherText3.concat(parts.get(i).concat(parts.get(i + 1)));
        }
        for (int i = 6; i < 31; i += 8) {
            newCipherText4 = newCipherText4.concat(parts.get(i).concat(parts.get(i + 1)));
        }
        newCipherText = newCipherText1.concat(newCipherText2.concat(newCipherText3.concat(newCipherText4)));
        String[] result = AddRoundKey(newCipherText, w[40], w[41], w[42], w[43]);
        String[] newresult = new String[16];
        newresult[0] = result[0];
        newresult[1] = result[4];
        newresult[2] = result[8];
        newresult[3] = result[12];
        newresult[4] = result[1];
        newresult[5] = result[5];
        newresult[6] = result[9];
        newresult[7] = result[13];
        newresult[8] = result[2];
        newresult[9] = result[6];
        newresult[10] = result[10];
        newresult[11] = result[14];
        newresult[12] = result[3];
        newresult[13] = result[7];
        newresult[14] = result[11];
        newresult[15] = result[15];
        shiftRow(newresult);
        String r2 = "";
        for (String s : newresult) {
            r2 = r2.concat(s);   //result ro shift row mikonim mishe r2
        }
        String[] result2 = subByte(r2);     //r2 ro subbyte mikonim mishe result2 ya r3
        String r3 = "";
        for (String s : result2) {
            r3 = r3.concat(s);   //r3 ro bayad round key konim
        }
        List<String> partsr3 = getParts(r3);
        String r31 = "";
        String r32 = "";
        String r33 = "";
        String r34 = "";
        String newr3;
        for (int i = 0; i < 25; i += 8) {
            r31 = r31.concat(partsr3.get(i).concat(partsr3.get(i + 1)));
        }
        for (int i = 2; i < 27; i += 8) {
            r32 = r32.concat(partsr3.get(i).concat(partsr3.get(i + 1)));
        }
        for (int i = 4; i < 29; i += 8) {
            r33 = r33.concat(partsr3.get(i).concat(partsr3.get(i + 1)));
        }
        for (int i = 6; i < 31; i += 8) {
            r34 = r34.concat(partsr3.get(i).concat(partsr3.get(i + 1)));
        }
        newr3 = r31.concat(r32.concat(r33.concat(r34)));
        ////////////////////
        for (int i = 0, k = 36; i < 9; i++, k -= 4) {
            String[] result3 = AddRoundKey(newr3, w[k], w[k + 1], w[k + 2], w[k + 3]);
            String[] newresult3 = new String[16];
            newresult3[0] = result3[0];
            newresult3[1] = result3[4];
            newresult3[2] = result3[8];
            newresult3[3] = result3[12];
            newresult3[4] = result3[1];
            newresult3[5] = result3[5];
            newresult3[6] = result3[9];
            newresult3[7] = result3[13];
            newresult3[8] = result3[2];
            newresult3[9] = result3[6];
            newresult3[10] = result3[10];
            newresult3[11] = result3[14];
            newresult3[12] = result3[3];
            newresult3[13] = result3[7];
            newresult3[14] = result3[11];
            newresult3[15] = result3[15];
            //mix, shift, sub
            String[][] newsubBytes = new String[4][4];
            for (int j = 0; j < 4; j++) {  //convert 1d arr to 2d
                System.arraycopy(newresult3, (j * 4), newsubBytes[j], 0, 4);
            }
            String[][] newsubBytes2 = new String[4][4];
            for (int j = 0; j < 4; j++) {
                for (int l = 0; l < 4; l++) {
                    newsubBytes2[j][l] = newsubBytes[l][j];
                }
            }
            String[][] result4 = mixColumn(newsubBytes2);     //araye 2 bodie integer khoroojie mix column ast
            String[] result5 = new String[16];
            for (int j = 0; j < 4; j++) {
                System.arraycopy(result4[j], 0, result5, (4 * j), 4);
            }
            String[] result6 = new String[16];
            result6[0] = result5[0];
            result6[1] = result5[4];
            result6[2] = result5[8];
            result6[3] = result5[12];
            result6[4] = result5[1];
            result6[5] = result5[5];
            result6[6] = result5[9];
            result6[7] = result5[13];
            result6[8] = result5[2];
            result6[9] = result5[6];
            result6[10] = result5[10];
            result6[11] = result5[14];
            result6[12] = result5[3];
            result6[13] = result5[7];
            result6[14] = result5[11];
            result6[15] = result5[15];
            shiftRow(result6);
            String r4 = "";
            for (String s : result6) {
                r4 = r4.concat(s);   //result ro shift row mikonim mishe r2
            }
            String[] r6 = subByte(r4);
            String r5 = "";
            for (String s : r6) {
                r5 = r5.concat(s);   //result ro shift row mikonim mishe r2
            }
            List<String> partsr5 = getParts(r5);
            String r51 = "";
            String r52 = "";
            String r53 = "";
            String r54 = "";
            String newr5;
            for (int j = 0; j < 25; j += 8) {
                r51 = r51.concat(partsr5.get(j).concat(partsr5.get(j + 1)));
            }
            for (int j = 2; j < 27; j += 8) {
                r52 = r52.concat(partsr5.get(j).concat(partsr5.get(j + 1)));
            }
            for (int j = 4; j < 29; j += 8) {
                r53 = r53.concat(partsr5.get(j).concat(partsr5.get(j + 1)));
            }
            for (int j = 6; j < 31; j += 8) {
                r54 = r54.concat(partsr5.get(j).concat(partsr5.get(j + 1)));
            }
            newr5 = r51.concat(r52.concat(r53.concat(r54)));
            newr3 = newr5;
        }
        String[] t2 = AddRoundKey(newr3, w[0], w[1], w[2], w[3]);
        System.out.print(t2[0]);
        System.out.print(t2[4]);
        System.out.print(t2[8]);
        System.out.print(t2[12]);
        System.out.print(t2[1]);
        System.out.print(t2[5]);
        System.out.print(t2[9]);
        System.out.print(t2[13]);
        System.out.print(t2[2]);
        System.out.print(t2[6]);
        System.out.print(t2[10]);
        System.out.print(t2[14]);
        System.out.print(t2[3]);
        System.out.print(t2[7]);
        System.out.print(t2[11]);
        System.out.print(t2[15]);
    }

    public static String[][] mixColumn(String[][] subBytes) {
        String[][] matrix = {{"0x0e", "0x0b", "0x0d", "0x09"}, {"0x09", "0x0e", "0x0b", "0x0d"},
                {"0x0d", "0x09", "0x0e", "0x0b"}, {"0x0b", "0x0d", "0x09", "0x0e"}};
        String[][] product = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int a = (Integer.parseInt(meydanMult(matrix[i][0], subBytes[0][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][1], subBytes[1][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][2], subBytes[2][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][3], subBytes[3][j]), 16));
                product[i][j] = Integer.toHexString(a);
                if (product[i][j].length() < 2) {
                    int c = 2 - product[i][j].length();
                    for (int k = 0; k < c; k++) {
                        product[i][j] = ("0").concat(product[i][j]);
                    }
                } else {
                    product[i][j] = Integer.toHexString(a);
                }
            }
        }
        for (int i = 0; i < 4; i++) {
            System.arraycopy(product[i], 0, subBytes[i], 0, 4);
        }
        return product;
    }


    public static String meydanMult(String i, String j) {
        int result;
        if ("0x09".equals(i)) {
            int a = Integer.parseInt(j, 16) * 2;
            int b;
            if (a > 255) {
                b = (a % 256) ^ 27;
            } else {
                b = a;
            }
            int a1 = b * 2;
            int b1;
            if (a1 > 255) {
                b1 = (a1 % 256) ^ 27;
            } else {
                b1 = a1;
            }
            int a2 = b1 * 2;
            int b2;
            if (a2 > 255) {
                b2 = (a2 % 256) ^ 27;
            } else {
                b2 = a2;
            }
            int c = b2 ^ Integer.parseInt(j, 16);
            if (c > 255) {
                result = (c % 256) ^ 27;
            } else {
                result = c;
            }
        } else if ("0x0b".equals(i)) {
            int a = Integer.parseInt(j, 16) * 2;
            int b, d, f, b1;
            if (a > 255) {
                b = (a % 256) ^ 27;
            } else {
                b = a;
            }
            int a1 = b * 2;
            if (a1 > 255) {
                b1 = (a1 % 256) ^ 27;
            } else {
                b1 = a1;
            }
            int c = b1 ^ Integer.parseInt(j, 16);
            if (c > 255) {
                d = (c % 256) ^ 27;
            } else {
                d = c;
            }
            int e = d * 2;
            if (e > 255) {
                f = (e % 256) ^ 27;
            } else {
                f = e;
            }
            int g = f ^ Integer.parseInt(j, 16);
            if (g > 255) {
                result = (g % 256) ^ 27;
            } else {
                result = g;
            }
        } else if ("0x0d".equals(i)) {// result = Integer.parseInt(j, 16);
            int a = Integer.parseInt(j, 16) * 2;
            int b;
            if (a > 255) {
                b = (a % 256) ^ 27;
            } else {
                b = a;
            }
            int d, f, h;
            int c = b ^ Integer.parseInt(j, 16);
            if (c > 255) {
                d = (c % 256) ^ 27;
            } else {
                d = c;
            }
            int e = d * 2;
            if (e > 255) {
                f = (e % 256) ^ 27;
            } else {
                f = e;
            }
            int e2 = f * 2;
            if (e2 > 255) {
                h = (e2 % 256) ^ 27;
            } else {
                h = e2;
            }
            int g = h ^ Integer.parseInt(j, 16);
            if (g > 255) {
                result = (g % 256) ^ 27;
            } else {
                result = g;
            }
        } else {//14
            int a = Integer.parseInt(j, 16) * 2;
            int b, d, f, h;
            if (a > 255) {
                b = (a % 256) ^ 27;
            } else {
                b = a;
            }
            int c = b ^ Integer.parseInt(j, 16);
            if (c > 255) {
                d = (c % 256) ^ 27;
            } else {
                d = c;
            }
            int e = d * 2;
            if (e > 255) {
                f = (e % 256) ^ 27;
            } else {
                f = e;
            }
            int g = f ^ Integer.parseInt(j, 16);
            if (g > 255) {
                h = (g % 256) ^ 27;
            } else {
                h = g;
            }
            int k = h * 2;
            if (k > 255) {
                result = (k % 256) ^ 27;
            } else {
                result = k;
            }
        }
        return Integer.toHexString(result);
    }

    public static String[] subByte(String plaintext) {
        List<String> parts = getParts(plaintext);
        String[] subBytes = new String[16];
        for (int i = 0, j = 0; i < 32; i += 2, j++) {
            subBytes[j] = Integer.toHexString(inverseSbox[Integer.parseInt(parts.get(i), 16)][Integer.parseInt(parts.get(i + 1), 16)]);
            if (subBytes[j].length() < 2) {
                int c = 2 - subBytes[j].length();
                for (int k = 0; k < c; k++) {
                    subBytes[j] = ("0").concat(subBytes[j]);
                }
            }
        }
        return subBytes;
    }

    public static void shiftRow(String[] subBytes) {
        String[] shiftRow = new String[16];
        shiftRow[0] = subBytes[0];
        shiftRow[1] = subBytes[13];
        shiftRow[2] = subBytes[10];
        shiftRow[3] = subBytes[7];
        shiftRow[4] = subBytes[4];
        shiftRow[5] = subBytes[1];
        shiftRow[6] = subBytes[14];
        shiftRow[7] = subBytes[11];
        shiftRow[8] = subBytes[8];
        shiftRow[9] = subBytes[5];
        shiftRow[10] = subBytes[2];
        shiftRow[11] = subBytes[15];
        shiftRow[12] = subBytes[12];
        shiftRow[13] = subBytes[9];
        shiftRow[14] = subBytes[6];
        shiftRow[15] = subBytes[3];
        System.arraycopy(shiftRow, 0, subBytes, 0, 16);
    }

    public static String[] AddRoundKey(String plaintext, String key0, String key1, String key2, String key3) {
        List<String> listOfP = getParts(plaintext);
        String[] result = new String[16];
        List<String> resultforKey0 = getParts(key0);
        List<String> resultforKey1 = getParts(key1);
        List<String> resultforKey2 = getParts(key2);
        List<String> resultforKey3 = getParts(key3);
        for (int i = 0, j = 0; i < 25; i += 8, j += 2) {
            int a = Integer.parseInt(listOfP.get(i).concat(listOfP.get(i + 1)), 16) ^
                    Integer.parseInt(resultforKey0.get(j).concat(resultforKey0.get(j + 1)), 16);
            result[i / 2] = Integer.toHexString(a);
            if (Integer.toHexString(a).length() < 2) {
                int count = 2 - Integer.toHexString(a).length();
                for (int l = 0; l < count; l++) {
                    result[i / 2] = ("0").concat(Integer.toHexString(a));
                }
            } else {
                result[i / 2] = Integer.toHexString(a);
            }
        }
        for (int i = 2, j = 0; i < 27; i += 8, j += 2) {
            int a = Integer.parseInt(listOfP.get(i).concat(listOfP.get(i + 1)), 16) ^
                    Integer.parseInt(resultforKey1.get(j).concat(resultforKey1.get(j + 1)), 16);
            if (Integer.toHexString(a).length() < 2) {
                int count = 2 - Integer.toHexString(a).length();
                for (int l = 0; l < count; l++) {
                    result[i / 2] = ("0").concat(Integer.toHexString(a));
                }
            } else {
                result[i / 2] = Integer.toHexString(a);
            }
        }
        for (int i = 4, j = 0; i < 29; i += 8, j += 2) {
            int a = Integer.parseInt(listOfP.get(i).concat(listOfP.get(i + 1)), 16) ^
                    Integer.parseInt(resultforKey2.get(j).concat(resultforKey2.get(j + 1)), 16);
            if (Integer.toHexString(a).length() < 2) {
                int count = 2 - Integer.toHexString(a).length();
                for (int l = 0; l < count; l++) {
                    result[i / 2] = ("0").concat(Integer.toHexString(a));
                }
            } else {
                result[i / 2] = Integer.toHexString(a);
            }
        }
        for (int i = 6, j = 0; i < 31; i += 8, j += 2) {
            int a = Integer.parseInt(listOfP.get(i).concat(listOfP.get(i + 1)), 16) ^
                    Integer.parseInt(resultforKey3.get(j).concat(resultforKey3.get(j + 1)), 16);

            if (Integer.toHexString(a).length() < 2) {
                int count = 2 - Integer.toHexString(a).length();
                for (int l = 0; l < count; l++) {
                    result[i / 2] = ("0").concat(Integer.toHexString(a));
                }
            } else {
                result[i / 2] = Integer.toHexString(a);
            }
        }
        return result;
    }

    private static List<String> getParts(String string) {  //split every n char in string
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < string.length(); i += 1) {
            parts.add(string.substring(i, Math.min(string.length(), i + 1)));
        }
        return parts;
    }

    public static String[] subByteForKey(String plaintext) {
        List<String> parts = getParts(plaintext);
        String[] subBytes = new String[4];
        for (int i = 0, j = 0; i < 8; i += 2, j++) {
            subBytes[j] = Integer.toHexString(sbox[Integer.parseInt(parts.get(i), 16)][Integer.parseInt(parts.get(i + 1), 16)]);
            if (subBytes[j].length() < 2) {
                int c = 2 - subBytes[j].length();
                for (int k = 0; k < c; k++) {
                    subBytes[j] = ("0").concat(subBytes[j]);
                }
            }
        }
        return subBytes;
    }

    public static String xorforHexadecimals(String s1, String s2) {
        char[] characters = new char[s1.length()];
        for (int i = 0; i < characters.length; i++) {
            int test = fh(s1.charAt(i)) ^ fh(s2.charAt(i));
            characters[i] = th(test);
        }
        return new String(characters);
    }

    private static int fh(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        throw new IllegalArgumentException();
    }

    private static char th(int no) {
        if (no >= 0 && no < 16) {
            return "0123456789abcdef".charAt(no);
        } else {
            throw new IllegalArgumentException();
        }
    }
}