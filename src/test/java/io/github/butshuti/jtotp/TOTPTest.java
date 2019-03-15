package io.github.butshuti.jtotp;

import junit.framework.TestCase;

import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

public class TOTPTest extends TestCase {
    private static final class Test{
        String utcTime, code, secret, mode;
        Test(String utcTime, String code, String secret, String mode){
            this.utcTime = utcTime;
            this.code = code;
            this.secret = secret;
            this.mode = mode;
        }
    }


    Test tests[] = new Test[]{
            new Test("1970-01-01T00:00:59Z", "94287082", "3132333435363738393031323334353637383930", "HmacSHA1"),
            new Test("2005-03-18T01:58:29Z", "07081804", "3132333435363738393031323334353637383930", "HmacSHA1"),
            new Test("2005-03-18T01:58:31Z", "14050471", "3132333435363738393031323334353637383930", "HmacSHA1"),
            new Test("2009-02-13T23:31:30Z", "89005924", "3132333435363738393031323334353637383930", "HmacSHA1"),
            new Test("2033-05-18T03:33:20Z", "69279037", "3132333435363738393031323334353637383930", "HmacSHA1"),
            new Test("2603-10-11T11:33:20Z", "65353130", "3132333435363738393031323334353637383930", "HmacSHA1")
    };

    @org.junit.Test
    public void testValidateCode() throws Exception {
        for(Test test: tests){
            Clock clock = Clock.fixed(Instant.parse(test.utcTime), ZoneOffset.UTC);
            TOTP totp = new TOTP(test.mode){
                @Override
                protected long getCurrentTimeMillis(){
                    return clock.millis();
                }
            };
            assertTrue(totp.validateCode(test.secret, test.code));
        }
    }

    @org.junit.Test
    public void testGenerateTruncatedOTP() throws GeneralSecurityException, TOTP.InvalidCodeFormatException {
        for(Test test: tests){
            Clock clock = Clock.fixed(Instant.parse(test.utcTime), ZoneOffset.UTC);
            TOTP totp = new TOTP(test.mode){
                @Override
                protected long getCurrentTimeMillis(){
                    return clock.millis();
                }
            };
            assertTrue(Arrays.stream(totp.getOTPsInCurrentWindow(test.secret)).anyMatch(code -> Integer.valueOf(code).intValue() == Integer.valueOf(test.code).intValue()));
        }
    }
}