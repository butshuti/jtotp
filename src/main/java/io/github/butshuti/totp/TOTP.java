package io.github.butshuti.totp;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TOTP {
    public static final class InvalidCodeFormatException extends Exception {
        InvalidCodeFormatException(Exception e){
            super(e);
        }
    }
    //Charset as defined by RFC3548
    private final static String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
    //Window for clock differences (x30 seconds) , +/- skewx30sec
    private final static int SKEW = 2;
    //Default time-step
    private final static int DEFAULT_TIME_STEP = 30;
    //Default code length
    private final static int DEFAULT_CODE_LENGTH = 8;
    //Default HMAC mode
    private final static String DEFAULT_HMAC_MODE = "HMACSHA1";

    private int timeStep = DEFAULT_TIME_STEP;
    private int codeLength = DEFAULT_CODE_LENGTH;
    private String hmacMode;

    public TOTP(String mode) throws NoSuchAlgorithmException {
        hmacMode = mode;
        Mac.getInstance(hmacMode);
    }

    public TOTP() throws NoSuchAlgorithmException {
        this(DEFAULT_HMAC_MODE);
    }

    protected long getCurrentTimeMillis(){
        return System.currentTimeMillis();
    }

    public static TOTP getDefault() throws NoSuchAlgorithmException {
        return new TOTP();
    }

    private static byte[] hexStrToBytes(String hexStr) throws InvalidCodeFormatException {
        try{
            //Prepend a non-zero byte to correctly convert values that start with a '0'. That byte must also trimmed from the result.
            byte[] byteArray = new BigInteger("10" + hexStr, 16).toByteArray();
            //Return the byte array with the prepended byte removed.
            byte[] ret = new byte[byteArray.length - 1];
            for (int i = 0; i < ret.length; i++) {
                ret[i] = byteArray[i + 1];
            }
            return ret;
        }catch (NumberFormatException e){
            throw new InvalidCodeFormatException(e);
        }
    }

    private static String adaptToHexStr(String str){
        try{
            BigInteger bigInteger = new BigInteger(str, 16);
            return bigInteger.toString(16);
        }catch (NumberFormatException e){
            return bytesToHexStr(str.getBytes());
        }
    }

    private static String bytesToHexStr(byte[] bytes){
        String ret = "";
        for(int i=0; i<bytes.length; i++){
            ret += Integer.toHexString(bytes[i] & 0xff);
        }
        return ret;
    }

    /**
     * Turns an integer (counter) into the OATH specified byte string.
     * Compliant with RFC 4226 (HOTP), the movingFactor will be in the first 8 bytes.
     */
    private static String intToHexStr(long num){
        String ret = Long.toHexString(num);
        while (ret.length() < 16){
            ret = "0" + ret;
        }
        return ret;
    }

    private static byte[] hash_hmac(String algorithm, byte[] key, byte[] text) throws GeneralSecurityException{
        Mac hmac;
        hmac = Mac.getInstance(algorithm);
        SecretKeySpec macKey = new SecretKeySpec(key, "RAW");
        hmac.init(macKey);
        return hmac.doFinal(text);
    }

    private static final int[] POWERS = {
            1,10,100,1000,10000,100000,1000000,10000000,100000000
    };

    private static int pow(int exponent){
        if(exponent >=0 && exponent < POWERS.length){
            return POWERS[exponent];
        }
        return (int)Math.pow(10, exponent);
    }

    private long getTimeBaseCounter(){
        if(timeStep <= 0){
            timeStep = DEFAULT_TIME_STEP;
        }
        long time = getCurrentTimeMillis() / 1000;
        return time / timeStep;
    }

    public String[] getOTPsInCurrentWindow(String secret) throws InvalidCodeFormatException, GeneralSecurityException {
        long start = getTimeBaseCounter();
        String codes[] = new String[(SKEW * 2) + 1];
        for(int i = 0, offs = -SKEW; i<codes.length && offs <= SKEW; i++, offs++){
            codes[i] = generateTruncatedOTP(secret, start+offs);
        }
        return codes;
    }

    public String getOTP(String secret) throws GeneralSecurityException, InvalidCodeFormatException {
        return generateTruncatedOTP(secret, getTimeBaseCounter());
    }

    public static String maskSecret(String secret, String salt) throws GeneralSecurityException {
        return bytesToHexStr(hash_hmac("HmacSha1", secret.getBytes(), salt.getBytes()));
    }

    public boolean validateCode(String secret, String code) throws InvalidCodeFormatException, GeneralSecurityException {
        DateFormat dateFormat = new SimpleDateFormat();
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        for(String otp : getOTPsInCurrentWindow(secret)){
            if(Integer.valueOf(otp).intValue() == Integer.valueOf(code).intValue()){
                return true;
            }
        }
        return false;
    }

    private String generateTruncatedOTP(String secret, long counter) throws InvalidCodeFormatException, GeneralSecurityException {
        //Timecode derived from the counter
        String timecode = intToHexStr(counter);
        //Compute a HMAC-SHA1 MAC from the secret and timecode
        byte[] hash = hash_hmac(hmacMode, hexStrToBytes(adaptToHexStr(secret)), hexStrToBytes(timecode));
        //Put selected bytes into result int to produce the OTP
        //Algorithm from RFC 6238
        int offs = hash[hash.length - 1] & 0xf;
        int otp =
                ((hash[offs] & 0x7f) << 24) |
                        ((hash[offs + 1] & 0xff) << 16) |
                        ((hash[offs + 2] & 0xff) << 8) |
                        (hash[offs + 3] & 0xff);
        otp %= pow(codeLength);
        String ret = Integer.toString(otp);
        while (ret.length() < codeLength) {
            ret = "0" + ret;
        }
        return ret;
    }

}