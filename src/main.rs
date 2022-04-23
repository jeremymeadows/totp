use libtotp::{encoding, Totp};

fn main() {
    let secret = encoding::b32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    let totp = Totp::new(secret).with_length(6).unwrap();

    println!("{}", totp.prev());
    println!("{}", totp.now());
    println!("{}", totp.next());
}
