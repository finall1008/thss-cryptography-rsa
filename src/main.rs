#![feature(exclusive_range_pattern)]

use iced::{Application, Error, Settings};
use random_string;

mod algorithms;
mod app;
mod bigint;
mod rsa;
mod utils;

#[derive(Debug)]
enum AppError {
    IcedError(Error),
    OtherError(&'static str),
}

fn main() -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().collect();
    if args.is_empty() || args.len() == 1 {
        return app::App::run(Settings::default()).map_err(|e| AppError::IcedError(e));
    } else if args.len() >= 3 {
        let keylen: usize = args[2]
            .parse()
            .map_err(|_| AppError::OtherError("parse arg failed"))?;
        match args[1].as_str() {
            "genkey" => {
                for _ in 0..10 {
                    let (t, _) = utils::count_time(|| rsa::gen_keys(keylen));
                    println!("{}", t)
                }
            }
            "encrypt" => {
                let (n, _) = rsa::gen_keys(keylen);
                let m = n.barrett_m();
                let msglen: usize = args[3]
                    .parse()
                    .map_err(|_| AppError::OtherError("parse arg failed"))?;
                for _ in 0..10 {
                    let msg =
                        random_string::generate(msglen, random_string::charsets::ALPHANUMERIC);
                    let (t, _) = utils::count_time(|| rsa::encrypt(&msg, &n, &m));
                    println!("{}", t)
                }
            }
            _ => return Ok(()),
        }
    }
    Ok(())
}
