package Entities;

import java.math.BigInteger;

public interface IPublicParams {
  BigInteger hash (byte[] msg);
}
