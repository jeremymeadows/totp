use libtotp::{encoding, Totp};

fn main() {
    let mut args = std::env::args();

    let secret = if let Some(code) = args.nth(1) {
        encoding::b32_decode(&code)
    } else {
        encoding::b32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    };
    let totp = Totp::new(secret).with_length(6).unwrap();

    println!("{}", totp.prev());
    println!("{}", totp.now());
    println!("{}", totp.next());
}
