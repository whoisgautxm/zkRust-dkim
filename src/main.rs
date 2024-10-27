use cfdkim::{
    dns, header::HEADER, public_key::retrieve_public_key, validate_header,
    verify_email_with_public_key, DkimPublicKey,
};
use mailparse::{parse_mail, MailHeaderMap};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::TokioAsyncResolver;


 pub fn main() {

    let from_domain = zk_rust_io::read::<String>();
    let raw_email: Vec<u8> = zk_rust_io::read();
    let public_key_type = zk_rust_io::read::<String>();
    let public_key_vec: Vec<u8> = zk_rust_io::read();

    println!("public_key_type: {}", public_key_type);
    println!("public_key_vec: {:?}", public_key_vec);

    let email = parse_mail(&raw_email).unwrap();
    let public_key = DkimPublicKey::from_vec_with_type(&public_key_vec, &public_key_type);
    let result = verify_email_with_public_key(&from_domain, &email, &public_key).unwrap();
    if let Some(_) = &result.error() {
        zk_rust_io::commit(&false);
    } else {
        zk_rust_io::commit(&true);
    }
}

#[tokio::main]
pub async fn input() -> Result<(), Box<dyn std::error::Error>> {
    let from_domain = "phonepe.com";

    let mut file = File::open("/home/whoisgautxm/Desktop/zkRust-dkim/src/email.eml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let raw_email = contents.replace('\n', "\r\n");
    let email = mailparse::parse_mail(raw_email.as_bytes())?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let resolver = dns::from_tokio_resolver(resolver);

    for h in email.headers.get_all_headers(HEADER) {
        let value = String::from_utf8_lossy(h.get_value_raw());
        let dkim_header = validate_header(&value).unwrap();

        let signing_domain = dkim_header.get_required_tag("d");
        if signing_domain.to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let public_key = retrieve_public_key(
            Arc::clone(&resolver),
            dkim_header.get_required_tag("d"),
            dkim_header.get_required_tag("s"),
        )
        .await
        .unwrap();

        let raw_email_vec = raw_email.as_bytes().to_vec();
        let pub_key_vec = public_key.to_vec();

        println!("from_domain: {}", from_domain);
        println!("raw_email_vec: {:?}", raw_email_vec);
        println!("public_key_type: {}", public_key.get_type());
        println!("pub_key_vec: {:?}", pub_key_vec);

        zk_rust_io::write(&from_domain.to_string());
        zk_rust_io::write(&raw_email_vec);
        zk_rust_io::write(&public_key.get_type());
        zk_rust_io::write(&pub_key_vec);
        return Ok(());
    }

    println!("Invalid from_domain.");
    Ok(())
}

pub fn output() {
    let result: bool = zk_rust_io::out();

    println!("result{}", result)
}
