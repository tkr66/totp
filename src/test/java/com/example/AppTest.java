package com.example;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

public class AppTest {

  @Test
  public void testGenerateTOTP_ValidKeyAndTimeStep() {
    var key = "secret";
    var timeStepSeconds = 30;

    var totp = App.generateTOTP(key, timeStepSeconds);

    assertNotNull(totp);
    assertEquals(6, totp.length());
    assertTrue(totp.matches("\\d{6}"));
  }

  @Test
  public void testGenerateTOTP_DifferentKeys() {
    var key1 = "secret";
    var key2 = "key";
    var timeStepSeconds = 30;

    var totp1 = App.generateTOTP(key1, timeStepSeconds);
    var totp2 = App.generateTOTP(key2, timeStepSeconds);

    assertNotEquals(totp1, totp2);
  }

  @Test
  public void testGenerateTOTP_DifferentTimeSteps() {
    var key = "secret";
    var timeStepSeconds1 = 30;
    var timeStepSeconds2 = 60;

    var totp1 = App.generateTOTP(key, timeStepSeconds1);
    var totp2 = App.generateTOTP(key, timeStepSeconds2);

    assertNotEquals(totp1, totp2);
  }

  @Test
  public void testGenerateTOTP_EmptyKey() {
    var key = "";
    var timeStepSeconds = 30;

    var ex = assertThrows(IllegalArgumentException.class, () -> {
      App.generateTOTP(key, timeStepSeconds);
    });
    assertEquals("Empty key", ex.getMessage());
  }

  @Test
  public void testGenerateTOTP_ChangesAfterTimeStep() throws InterruptedException {
    var key = "secret";
    var timeStepSeconds = 3;

    var initialTotp = App.generateTOTP(key, timeStepSeconds);

    TimeUnit.SECONDS.sleep(timeStepSeconds);

    var subsequentTotp = App.generateTOTP(key, timeStepSeconds);

    assertNotEquals(initialTotp, subsequentTotp);
  }
}
