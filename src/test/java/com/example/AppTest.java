package com.example;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

public class AppTest {

  @Test
  public void testGenerateTOTP_ValidKeyAndTimeStep() {
    var key = "secret";
    var period = 30;

    var totp = App.generateTOTP(key, period);

    assertNotNull(totp);
    assertEquals(6, totp.length());
    assertTrue(totp.matches("\\d{6}"));
  }

  @Test
  public void testGenerateTOTP_DifferentKeys() {
    var key1 = "secret";
    var key2 = "key";
    var period = 30;

    var totp1 = App.generateTOTP(key1, period);
    var totp2 = App.generateTOTP(key2, period);

    assertNotEquals(totp1, totp2);
  }

  @Test
  public void testGenerateTOTP_DifferentTimeSteps() {
    var key = "secret";
    var period1 = 30;
    var period2 = 60;

    var totp1 = App.generateTOTP(key, period1);
    var totp2 = App.generateTOTP(key, period2);

    assertNotEquals(totp1, totp2);
  }

  @Test
  public void testGenerateTOTP_EmptyKey() {
    var key = "";
    var period = 30;

    var ex = assertThrows(IllegalArgumentException.class, () -> {
      App.generateTOTP(key, period);
    });
    assertEquals("Empty key", ex.getMessage());
  }

  @Test
  public void testGenerateTOTP_ChangesAfterTimeStep() throws InterruptedException {
    var key = "secret";
    var period = 3;

    var initialTotp = App.generateTOTP(key, period);

    TimeUnit.SECONDS.sleep(period);

    var subsequentTotp = App.generateTOTP(key, period);

    assertNotEquals(initialTotp, subsequentTotp);
  }

  @Test
  public void testHMAC() {
    var key = "12345678901234567890";
    var hmacTable = Map.of(
        0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
        1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
        2, "0bacb7fa082fef30782211938bc1c5e70416ff44",
        3, "66c28227d03a2d5529262ff016a1e6ef76557ece",
        4, "a904c900a64b35909874b33e61c5938a8e15ed1c",
        5, "a37e783d7b7233c083d4f62926c7a25f238d0316",
        6, "bc9cd28561042c83f219324d3c607256c03272ae",
        7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
        8, "1b3c89f65e6c9e883012052823443f048b4332db",
        9, "1637409809a679dc698207310c8c7fc07290d9e5");
    hmacTable.entrySet().stream().forEach(e -> {
      var countBytes = ByteBuffer.allocate(Long.BYTES).putLong(e.getKey()).array();
      var expected = e.getValue();
      var hash = App.computeHash(key.getBytes(), countBytes);
      var actual = IntStream.range(0, hash.length)
          .mapToObj(i -> String.format("%02x", hash[i]))
          .collect(Collectors.joining());
      assertEquals(expected, actual);
    });
  }

  @Test
  public void testHOTP() {
    var key = "12345678901234567890";
    var hotpTable = Map.of(
        0, "755224",
        1, "287082",
        2, "359152",
        3, "969429",
        4, "338314",
        5, "254676",
        6, "287922",
        7, "162583",
        8, "399871",
        9, "520489");
    hotpTable.entrySet().stream().forEach(e -> {
      var countBytes = ByteBuffer.allocate(Long.BYTES).putLong(e.getKey()).array();
      var expected = e.getValue();
      var actual = App.generateHOTP(key.getBytes(), countBytes, e.getValue().length());
      assertEquals(expected, actual);
    });
  }

  @Test
  public void testTOTP() {
    var key = "12345678901234567890";
    var totpTable = Map.of(
        59L, "94287082",
        1111111109L, "07081804",
        1111111111L, "14050471",
        1234567890L, "89005924",
        2000000000L, "69279037",
        20000000000L, "65353130");
    totpTable.entrySet().stream().forEach(e -> {
      var expected = e.getValue();
      var actual = App.generateTOTP(key.getBytes(), 30, e.getKey(), e.getValue().length());
      assertEquals(expected, actual);
    });
  }

}
