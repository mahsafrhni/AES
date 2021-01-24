import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Encryption {
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
        String plaintext = input.next();
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
        String[] result = AddRoundKey(plaintext, w[0], w[1], w[2], w[3]);
        String r = "";
        for (String s : result) {
            r = r.concat(s);
        }
        for (int i = 0, k = 4; i < 9; i++, k += 4) {
            String[] t1 = subByte(r);
            String r2 = "";
            for (String s : t1) {
                r2 = r2.concat(s);
            }
            shiftRow(t1);
            String[][] newsubBytes = new String[4][4];
            for (int j = 0; j < 4; j++) {  //convert 1d arr to 2d
                System.arraycopy(t1, (j * 4), newsubBytes[j], 0, 4);
            }
            String[][] newsubBytes4 = new String[4][4];
            for (int j = 0; j < 4; j++) {
                for (int l = 0; l < 4; l++) {
                    newsubBytes4[l][j] = newsubBytes[j][l];
                }
            }
            newsubBytes = mixColumn(newsubBytes4);
            String newsubBytes2 = "";
            for (int l = 0; l < 4; l++) {
                for (int m = 0; m < 4; m++) {
                    newsubBytes2 = newsubBytes2.concat(newsubBytes[l][m]);
                }
            }
            List<String> parts = getParts(newsubBytes2);
            String newsubBytes21 = "";
            String newsubBytes22 = "";
            String newsubBytes23 = "";
            String newsubBytes24 = "";
            String newsubBytes222;
            for (int j = 0; j < 25; j += 8) {
                newsubBytes21 = newsubBytes21.concat(parts.get(j).concat(parts.get(j + 1)));
            }
            for (int j = 2; j < 27; j += 8) {
                newsubBytes22 = newsubBytes22.concat(parts.get(j).concat(parts.get(j + 1)));
            }
            for (int j = 4; j < 29; j += 8) {
                newsubBytes23 = newsubBytes23.concat(parts.get(j).concat(parts.get(j + 1)));
            }
            for (int j = 6; j < 31; j += 8) {
                newsubBytes24 = newsubBytes24.concat(parts.get(j).concat(parts.get(j + 1)));
            }
            newsubBytes222 = newsubBytes21.concat(newsubBytes22.concat(newsubBytes23.concat(newsubBytes24)));
            String[] rt = AddRoundKey(newsubBytes222, w[k], w[k + 1], w[k + 2], w[k + 3]);
            String newsubBytes3 = "";
            for (String s : rt) {
                newsubBytes3 = newsubBytes3.concat(s);
            }
            r = newsubBytes3;
        }
        String[] t1 = subByte(r);
        shiftRow(t1);
        String s = "";
        for (String value : t1) {
            s = s.concat(value);
        }
        String[] t2 = AddRoundKey(s, w[40], w[41], w[42], w[43]);
        for (int i = 0; i < 16; i++) {
            System.out.print(t2[i]);
        }
    }

    public static String RotWord(String s) {
        return s.substring(2) + s.substring(0, 2);
    }

    public static String[] AddRoundKey(String plaintext, String key0, String key1, String key2, String key3) {
        List<String> listOfP = getParts(plaintext);
        String[] result = new String[16];
        List<String> resultforrKey0 = getParts(key0);
        List<String> resultforrKey1 = getParts(key1);
        List<String> resultforrKey2 = getParts(key2);
        List<String> resultforrKey3 = getParts(key3);
        String keyn0 = resultforrKey0.get(0).concat(resultforrKey0.get(1).concat
                (resultforrKey1.get(0).concat(resultforrKey1.get(1).concat(resultforrKey2.get(0).
                        concat(resultforrKey2.get(1).concat(resultforrKey3.get(0).concat(resultforrKey3.get(1))))))));
        String keyn1 = resultforrKey0.get(2).concat(resultforrKey0.get(3).concat
                (resultforrKey1.get(2).concat(resultforrKey1.get(3).concat(resultforrKey2.get(2).
                        concat(resultforrKey2.get(3).concat(resultforrKey3.get(2).concat(resultforrKey3.get(3))))))));
        String keyn2 = resultforrKey0.get(4).concat(resultforrKey0.get(5).concat
                (resultforrKey1.get(4).concat(resultforrKey1.get(5).concat(resultforrKey2.get(4).
                        concat(resultforrKey2.get(5).concat(resultforrKey3.get(4).concat(resultforrKey3.get(5))))))));
        String keyn3 = resultforrKey0.get(6).concat(resultforrKey0.get(7).concat
                (resultforrKey1.get(6).concat(resultforrKey1.get(7).concat(resultforrKey2.get(6).
                        concat(resultforrKey2.get(7).concat(resultforrKey3.get(6).concat(resultforrKey3.get(7))))))));
        List<String> resultforKey0 = getParts(keyn0);
        List<String> resultforKey1 = getParts(keyn1);
        List<String> resultforKey2 = getParts(keyn2);
        List<String> resultforKey3 = getParts(keyn3);
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

    public static String xorforHexadecimals(String s1, String s2) {
        char[] characters = new char[s1.length()];
        for (int i = 0; i < characters.length; i++) {
            characters[i] = "0123456789ABCDEF".charAt(fh(s1.charAt(i)) ^ fh(s2.charAt(i)));
        }
        return new String(characters);
    }

    public static int fh(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        } else {
            return 0;
        }
    }

    public static String[] subByte(String plaintext) {
        List<String> parts = getParts(plaintext);
        String[] subBytes = new String[16];
        for (int i = 0, j = 0; i < 32; i += 2, j++) {
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

    public static String[][] mixColumn(String[][] subBytes) {
        String[][] matrix = {{"0x02", "0x03", "0x01", "0x01"}, {"0x01", "0x02", "0x03", "0x01"},
                {"0x01", "0x01", "0x02", "0x03"}, {"0x03", "0x01", "0x01", "0x02"}};
        String[][] product = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int a = (Integer.parseInt(meydanMult(matrix[i][0], subBytes[0][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][1], subBytes[1][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][2], subBytes[2][j]), 16) ^
                        Integer.parseInt(meydanMult(matrix[i][3], subBytes[3][j]), 16));
                int b;
                if (a > 255) {
                    b = (a % 256) ^ 27;
                } else {
                    b = a;
                }
                product[i][j] = Integer.toHexString(b);
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
        if (i.equals("0x02")) {
            if ((Integer.parseInt(j, 16) * 2) >= 256) {
                result = ((Integer.parseInt(j, 16) * 2) % 256) ^ 27;
            } else {
                result = Integer.parseInt(j, 16) * 2;
            }
        } else if (i.equals("0x03")) {
            int b;
            if (Integer.parseInt(j, 16) * 2 >= 256) {
                b = ((Integer.parseInt(j, 16) * 2) % 256) ^ 27;
            } else {
                b = Integer.parseInt(j, 16) * 2;
            }
            if ((b ^ Integer.parseInt(j, 16)) >= 256) {
                result = ((b ^ Integer.parseInt(j, 16)) % 256) ^ 27;
            } else {
                result = b ^ Integer.parseInt(j, 16);
            }
        } else {
            if (Integer.parseInt(j, 16) >= 256) {
                result = ((Integer.parseInt(j, 16) % 256)) ^ 27;
            } else {
                result = Integer.parseInt(j, 16);
            }
        }
        return Integer.toHexString(result);
    }

    public static void shiftRow(String[] subBytes) {
        String[] shiftRow = new String[16];
        shiftRow[0] = subBytes[0];
        shiftRow[1] = subBytes[5];
        shiftRow[2] = subBytes[10];
        shiftRow[3] = subBytes[15];
        shiftRow[4] = subBytes[4];
        shiftRow[5] = subBytes[9];
        shiftRow[6] = subBytes[14];
        shiftRow[7] = subBytes[3];
        shiftRow[8] = subBytes[8];
        shiftRow[9] = subBytes[13];
        shiftRow[10] = subBytes[2];
        shiftRow[11] = subBytes[7];
        shiftRow[12] = subBytes[12];
        shiftRow[13] = subBytes[1];
        shiftRow[14] = subBytes[6];
        shiftRow[15] = subBytes[11];
        System.arraycopy(shiftRow, 0, subBytes, 0, 16);
    }

    private static List<String> getParts(String string) {  //split every n char in string
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < string.length(); i += 1) {
            parts.add(string.substring(i, Math.min(string.length(), i + 1)));
        }
        return parts;
    }
}