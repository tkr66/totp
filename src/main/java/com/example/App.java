package com.example;

import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class App {

  private static final int[] DIGITS_POWER = {
      1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
  };

  /**
   * Pads the output integer with leading zeros to ensure it has a fixed length.
   *
   * @param value The integer value to be padded.
   * @return A string representation of the integer, padded with leading zeros to
   *         the specified CODE_LENGTH.
   */
  public static String padOutput(int value, int digits) {
    var result = Integer.toString(value);
    for (int i = result.length(); i < digits; i++) {
      result = "0" + result;
    }
    return result;
  }

  /**
   * Computes an HMAC-SHA1 hash using the provided key and counter.
   *
   * @param key     The secret key used for HMAC generation.
   * @param counter The counter value to be hashed.
   * @return The byte array output of the HMAC-SHA1 hash.
   * @throws UndeclaredThrowableException if a GeneralSecurityException occurs
   *                                      during HMAC generation.
   */
  public static byte[] computeHash(byte[] key, byte[] counter) {
    try {
      var hmac = Mac.getInstance("HmacSHA1");
      var macKey = new SecretKeySpec(key, "RAW");
      hmac.init(macKey);
      return hmac.doFinal(counter);
    } catch (GeneralSecurityException gse) {
      throw new UndeclaredThrowableException(gse);
    }
  }

  /**
   * Truncates the HMAC-SHA1 hash to generate a HOTP.
   *
   * @param hash The byte array output of HMAC-SHA1.
   * @return A string representation of the truncated OTP, padded to the specified
   *         CODE_LENGTH.
   */
  public static String truncate(byte[] hash, int digits) {
    var binCode = extractDynamicBinaryCode(hash);
    var code = binCode % DIGITS_POWER[digits];
    var out = padOutput(code, digits);
    return out;
  }

  /**
   * Extracts the dynamic binary code from the HMAC-SHA1 output.
   *
   * @param hash The byte array output of HMAC-SHA1
   * @return The extracted 31-bit dynamic binary code
   */
  public static int extractDynamicBinaryCode(byte[] hash) {
    var offset = hash[19] & 0xf;
    int value = (hash[offset] & 0x7f) << 24
        | (hash[offset + 1] & 0xff) << 16
        | (hash[offset + 2] & 0xff) << 8
        | (hash[offset + 3] & 0xff);
    return value;
  }

  /**
   * Generates a HMAC-based One-Time Password (HOTP).
   *
   * @param key     The secret key used for HMAC generation.
   * @param counter The counter value to be hashed.
   * @return A string representation of the generated HOTP.
   */
  public static String generateHOTP(byte[] key, byte[] counter, int digits) {
    // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
    var hash = computeHash(key, counter);
    var hotp = truncate(hash, digits);
    return hotp;
  }

  public static String generateTOTP(String key, int period) {
    // X = time step in seconds (default 30)
    // T0 = unix time to start counting time steps (default 0)
    // T = (Current Unix time - T0) / X
    // TOTP = HOTP(K, T)
    var time = System.currentTimeMillis() / 1000;
    var step = time / period;
    var t = ByteBuffer.allocate(Long.BYTES).putLong(step).array();
    var totp = generateHOTP(key.getBytes(), t, 6);
    return totp;
  }

  /**
   * Generates a Time-based One-Time Password (TOTP) using the specified key and
   * time step.
   *
   * <p>
   * The TOTP is calculated based on the current Unix time divided by the
   * specified time step in seconds.
   * The resulting value is then used as the counter for the HMAC-based One-Time
   * Password (HOTP) algorithm.
   * </p>
   *
   * @param key    The secret key used for generating the TOTP,
   *               represented as a string.
   * @param period The time step in seconds for TOTP generation (e.g., 30
   *               seconds).
   * @param time   The time represented in Unix Time format.
   * @return A string representation of the generated TOTP.
   */
  public static String generateTOTP(byte[] secret, int period, long time, int digits) {
    // X = time step in seconds (default 30)
    // T0 = unix time to start counting time steps (default 0)
    // T = (Current Unix time - T0) / X
    // TOTP = HOTP(K, T)
    var step = time / period;
    var t = ByteBuffer.allocate(Long.BYTES).putLong(step).array();
    var totp = generateHOTP(secret, t, digits);
    return totp;
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      var usage = """
          Usage: java App <key> [period]
            <key>                The secret key for TOTP generation.
            [period]    The time step in seconds (default: 30).
          """;
      System.out.println(usage);
      System.exit(0);
    }
    var key = args[0];
    var period = args.length >= 2
        ? Integer.valueOf(args[1])
        : 30;
    var time = System.currentTimeMillis() / 1000;
    var decoded = new Base32().decode(key);
    var totp = generateTOTP(decoded, period, time, 6);
    System.out.println(totp);
  }
}
