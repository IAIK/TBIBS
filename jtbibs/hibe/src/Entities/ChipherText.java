package Entities;

import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.field.ExtensionFieldElement;

public class ChipherText {

    public final ExtensionFieldElement c1;
    public final ECPoint c2;
    public final ECPoint c3;

    public ChipherText(ExtensionFieldElement part1, ECPoint part2, ECPoint part3) {
        this.c1 = part1;
        this.c2 = part2;
        this.c3 = part3;
    }
}
