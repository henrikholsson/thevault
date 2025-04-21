use std::io::{self, Write};
mod file;
mod encryption;
mod compression;
use crate::file::file::KvStore;



fn main() {
    let mut db = KvStore::new("kvstore.log", "cat");
    loop {
        print!("Enter command (SET key value | GET key | ALL | DELETE key | EXIT): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        println!("{:?}", parts);

        match parts.as_slice() {
            [cmd, key, value]  if cmd.to_lowercase() == "set" => {
                db.set(key.to_string(), value.to_string());
                println!("OK");
            }
            [cmd, key] if cmd.to_lowercase() == "get" => {
                match db.get(key) {
                    Some(value) => println!("{}", value),
                    None => println!("Key not found"),
                }
            }
            [cmd, key] if cmd.to_lowercase() ==  "delete" => {
                db.delete(key);
                println!("DELETED");
            }
            [cmd] if cmd.to_lowercase() == "exit" => {
                println!("Exiting...");
                break;
            }
            [cmd] if cmd.to_lowercase() == "all" => 
            {
                match db.getall() {
                    Some(keys) => {
                        for (index, key) in keys.iter().enumerate() {
                            println!("{}: {}", index + 1, key);
                        }
                    }
                    None => println!("No keys found")
                } 
            }
            [cmd] if cmd.to_lowercase() == "nuke" =>
            {
                db.nuke();
            }
            _ => println!("Invalid Command! Enter command (SET key value | GET key | DELETE key | EXIT): "),
        }
    }
}