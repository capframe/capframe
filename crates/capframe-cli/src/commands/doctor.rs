use anyhow::Result;

use crate::modules::{resolve, Module};

pub fn run() -> Result<()> {
    println!("capframe doctor — module resolution\n");
    for (label, m) in [
        ("find", Module::Find),
        ("bind", Module::Bind),
        ("guard", Module::Guard),
    ] {
        match resolve(m) {
            Ok(p) => println!("  {label:<6} OK  {}", p.display()),
            Err(e) => println!("  {label:<6} --  {e}"),
        }
    }
    Ok(())
}
