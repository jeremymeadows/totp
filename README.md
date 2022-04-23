# totp

An implementation of the TOTP algorithm from [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
It can be used client-side in an authenticator app by using a URL like: `otpauth://totp/Test:email@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, usually in the form of a [QR code](https://www.qr-code-generator.com/).
