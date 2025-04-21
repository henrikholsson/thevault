use std::collections::HashMap;
use std::fs::{OpenOptions};
use std::io::{Write};
use crate::encryption::{decrypt_with_password, encrypt_with_password};
use crate::compression::compression::{compress, decompress};

pub struct KvStore {
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
                    let parts: Vec<&str> = line.splitn(2, ':').collect(); 
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

    pub fn load_file(file_path: &str) -> io::Result<Vec<u8>> {
        match fs::read(file_path) {
            Ok(data) => {
                println!("Loaded {} bytes from '{}'", data.len(), file_path);
                Ok(data)
            },
            Err(e) => {
                eprintln!("Failed to read file '{}': {}", file_path, e);
                Err(e)
            }
        }
    }

    pub fn write_file(path: &str, data: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)
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

    pub fn set(&mut self, key: String, value: String) {
        print!("{}, {}", key, value);
        self.store.insert(key.clone(), value.clone());
        if let Err(e) = self.save_to_file() {
            eprintln!("Failed to save KvStore: {}", e);
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.store.get(key).cloned()
    }

    pub fn delete(&mut self, key: &str) {
        if self.store.remove(key).is_some() {
            if let Err(e) = self.save_to_file() {
                eprintln!("Failed to save KvStore: {}", e);
            }
        }
    }
    pub fn getall(&self) -> Option<Vec<String>> {
        let keys: Vec<String> = self.store.keys().cloned().collect();
        if keys.is_empty() {
            None
        } else {
            Some(keys)
        }
    }

    pub fn nuke(&mut self) {
        self.store.clear();
        if let Err(e) = self.save_to_file() {
            eprintln!("Failed to save KvStore: {}", e);
        }
    }
}