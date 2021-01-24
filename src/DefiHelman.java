import java.math.*;
import java.util.*;

public class DefiHelman {
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        BigInteger p = input.nextBigInteger();
        BigInteger g = input.nextBigInteger();
        BigInteger a = input.nextBigInteger();
        BigInteger b = input.nextBigInteger();
        System.out.print(power(g, a).mod(p) + " ");
        System.out.print(power(g, b).mod(p) + " ");
        BigInteger A = power(g, b).mod(p);
        System.out.print(power(A, a).mod(p) + " ");
    }

    public static BigInteger zarb(BigInteger a, BigInteger b) {
        a = a.multiply(b);
        return a;
    }

    public static BigInteger power(BigInteger a, BigInteger b) {
        String count = "1";
        BigInteger number = new BigInteger(count);
        while (b.compareTo(BigInteger.ZERO) >= Integer.parseInt(count)) {
            boolean bool = b.testBit(0);
            if (bool) {
                number = zarb(number, a);
            }
            a = zarb(a, a);
            b = b.shiftRight(1);
        }
        return number;
    }
}