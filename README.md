# jtotp
Very simple Java library for generating and/or validating time-based one-time passwords, following the TOTP (RFC6238) algorithm.

## Installation
Adding a dependency to the library, using Gradle: 
 
   ```gradle
   repositories { 
        jcenter()
   }
   dependencies {
         implementation 'io.github.butshuti:jtotp:1.0.+'
   }
   ```

## Usage

```java
//Create an instance with the default HMAC mode ("HMACSHA1")
TOTP totp = new TOTP();

/*
  Create an instance with a given HMAC mode 
  (validity and availability will depend on JDK or crypto engines)
*/
TOTP totp = new TOTP("HMACSHA1");

/*
  Generate new OTP code using a given secret
  String secret = "some secret....";
*/
String code = totp.getOTP(secret);

//Validate a given OTP code
boolean isValid = totp.validateCode(code, secret);
```
## References
[RFC6238 -- TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
