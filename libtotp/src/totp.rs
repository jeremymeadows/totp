//! Implementation of the SHA1-HMAC Time-Based One-Time Password Algorithm.
//! 
//! Passes the IETF test vectors from [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

use crate::Sha1;
use std::time::{Duration, SystemTime};

/// A TOTP generator.
pub struct Totp {
    secret: Vec<u8>,
    interval: Duration,
    length: u8,
}

impl Totp {
    /// Creates a new TOTP generator using the given secret.
    pub fn new<T: Into<Vec<u8>>>(secret: T) -> Self {
        Self {
            secret: secret.into(),
            interval: Duration::from_secs(30),
            length: 8,
        }
    }

    /// Sets the interval period before the password changes (default: 30 seconds).
    pub fn with_interval(mut self, period: Duration) -> Self {
        self.interval = period;
        self
    }

    /// Sets the length of the calculated password, which must be <= 10 (default: 8 digits).
    pub fn with_length(mut self, length: u8) -> Result<Self, &'static str> {
        if length <= 10 {
            self.length = length;
            Ok(self)
        } else {
            Err("TOTP password length cannot be > 10 digits")
        }
    }

    /// Caculates the password for the provided time.
    pub fn at(&self, time: SystemTime) -> String {
        let time = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / self.interval.as_secs();
        let hmac = Sha1::hmac(&self.secret, &time.to_be_bytes()).as_bytes();

        let offset = hmac[hmac.len() - 1] as usize & 0xf;
        let code = ((hmac[offset] as u64 & 0x7f) << 24
            | (hmac[offset + 1] as u64 & 0xff) << 16
            | (hmac[offset + 2] as u64 & 0xff) << 8
            | (hmac[offset + 3] as u64 & 0xff))
            % 10_u64.pow(self.length.into());

        let mut code = code.to_string();
        while code.len() < self.length.into() {
            code = format!("0{}", code);
        }

        code
    }

    /// Calculates the password for the current time.
    pub fn now(&self) -> String {
        self.at(SystemTime::now())
    }

    /// Calculates the password one interval in the past.
    pub fn prev(&self) -> String {
        self.at(SystemTime::now() - self.interval)
    }

    /// Calculates the password one interval in the future.
    pub fn next(&self) -> String {
        self.at(SystemTime::now() + self.interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 20] = *b"12345678901234567890";

    #[test]
    fn test_epoch() {
        let totp = Totp::new(SECRET).with_length(6).unwrap();
        assert_eq!(totp.at(SystemTime::UNIX_EPOCH), "755224");
    }

    #[test]
    fn test_short_duration() {
        let totp = Totp::new(SECRET).with_interval(Duration::from_secs(1)).with_length(6).unwrap();
        assert_eq!(totp.at(SystemTime::UNIX_EPOCH + Duration::from_secs(1)), "287082");
    }

    #[test]
    fn test_too_long() {
        let totp = Totp::new(SECRET).with_length(11);
        assert!(totp.is_err());
    }

    #[test]
    fn test_1() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(59);

        assert_eq!(totp.at(time), "94287082");
    }

    #[test]
    fn test_2() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1111111109);

        assert_eq!(totp.at(time), "07081804");
    }

    #[test]
    fn test_3() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1111111111);

        assert_eq!(totp.at(time), "14050471");
    }

    #[test]
    fn test_4() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1234567890);

        assert_eq!(totp.at(time), "89005924");
    }

    #[test]
    fn test_5() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(2000000000);

        assert_eq!(totp.at(time), "69279037");
    }

    #[test]
    fn test_6() {
        let totp = Totp::new(SECRET);
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(20000000000);

        assert_eq!(totp.at(time), "65353130");
    }
}
