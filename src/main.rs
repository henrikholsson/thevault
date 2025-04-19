use std::collections::HashMap;
use std::fs::{OpenOptions};
use std::io::{self, Write};
mod encryption;
use encryption::encryption::{decrypt_with_password, encrypt_with_password};
mod compression;
use compression::compression::{compress, decompress};

struct KvStore {
    store: HashMap<String, String>,
    log_path: String,
    key: String,
}


impl KvStore {

    pub fn new(log_path: &str, password: &str) -> Self {
        
        let mut store = HashMap::new();

        if let Ok(data) = std::fs::read(log_path) {
            if !data.is_empty() {
                let decrypted = decrypt_with_password(&data, &password); 

                let decompressed = decompress(&decrypted);
                let contents = String::from_utf8(decompressed)
                    .expect("Invalid UTF-8 in decrypted log");

                for line in contents.lines() {
                    let parts: Vec<&str> = line.splitn(2, ':').collect(); // safer than .split()
                    if parts.len() == 2 {
                        store.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
            }
        }

        KvStore {
            store,
            log_path: log_path.to_string(),
            key: password.to_string(),
        }
    }
    

    fn save_to_file(&self) -> std::io::Result<()> {
        let mut content = String::new();
        for (key, value) in &self.store{
            content.push_str(&format!("{}:{}\n", key, value));
        }

        let compressed = compress(content.as_bytes());
        let encrypted  = encrypt_with_password(&compressed, &self.key);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.log_path)?;

        file.write_all(&encrypted)?;
        println!("Encrypted KvStore saved to: {}", self.log_path);
        Ok(())
    }

    fn set(&mut self, key: String, value: String) {
        print!("{}, {}", key, value);
        self.store.insert(key.clone(), value.clone());
        if let Err(e) = self.save_to_file() {
            eprintln!("Failed to save KvStore: {}", e);
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        self.store.get(key).cloned()
    }

    fn delete(&mut self, key: &str) {
        if self.store.remove(key).is_some() {
            if let Err(e) = self.save_to_file() {
                eprintln!("Failed to save KvStore: {}", e);
            }
        }
    }
    fn getall(&self) -> Option<Vec<String>> {
        let keys: Vec<String> = self.store.keys().cloned().collect();
        if keys.is_empty() {
            None
        } else {
            Some(keys)
        }
    }
}

fn main() {
    let mut db = KvStore::new("kvstore.log", "scat");
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
            _ => println!("Invalid Command! Enter command (SET key value | GET key | DELETE key | EXIT): "),
        }
    }
}