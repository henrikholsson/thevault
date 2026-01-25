use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use crate::encryption::{decrypt_with_password, encrypt_with_password};
use crate::compression::compression::{compress, decompress};

fn parse_tags_string(tags: &str) -> Vec<String> {
    let mut results = Vec::new();
    for tag in tags.split(',') {
        let tag = tag.trim().trim_start_matches('#');
        if tag.is_empty() {
            continue;
        }
        let tag = tag.to_lowercase();
        if !results.contains(&tag) {
            results.push(tag);
        }
    }
    results
}

#[derive(Clone)]
pub struct KvEntry {
    pub value: String,
    pub description: String,
    pub color: Option<String>,
    pub tags: Vec<String>,
    pub created_at: Option<i64>,
}

pub struct KvStore {
    store: HashMap<String, KvEntry>,
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
                    if line.trim().is_empty() {
                        continue;
                    }
                    if line.contains('\t') {
                        let mut parts = line.splitn(6, '\t');
                        let key = parts.next().unwrap_or("").to_string();
                        let value = parts.next().unwrap_or("").to_string();
                        let description = parts.next().unwrap_or("").to_string();
                        let color = parts.next().unwrap_or("").to_string();
                        let tags = parts.next().unwrap_or("");
                        let created_at = parts.next().unwrap_or("");

                        let color = if color.trim().is_empty() {
                            None
                        } else {
                            Some(color)
                        };
                        let tags = parse_tags_string(tags);
                        let created_at = created_at.trim().parse::<i64>().ok();
                        if !key.is_empty() {
                            store.insert(
                                key,
                                KvEntry {
                                    value,
                                    description,
                                    color,
                                    tags,
                                    created_at,
                                },
                            );
                        }
                    } else {
                        let parts: Vec<&str> = line.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            store.insert(
                                parts[0].to_string(),
                                KvEntry {
                                    value: parts[1].to_string(),
                                    description: String::new(),
                                    color: None,
                                    tags: Vec::new(),
                                    created_at: None,
                                },
                            );
                        }
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

    pub fn new_empty(log_path: &str, password: &str) -> Self {
        KvStore {
            store: HashMap::new(),
            log_path: log_path.to_string(),
            key: password.to_string(),
        }
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
        let mut keys: Vec<&String> = self.store.keys().collect();
        keys.sort();
        for key in keys {
            if let Some(entry) = self.store.get(key) {
                let color = entry.color.clone().unwrap_or_default();
                let tags = if entry.tags.is_empty() {
                    String::new()
                } else {
                    entry.tags.join(",")
                };
                let created_at = entry
                    .created_at
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                content.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    key, entry.value, entry.description, color, tags, created_at
                ));
            }
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

    pub fn set(
        &mut self,
        key: String,
        value: String,
        description: String,
        color: Option<String>,
        tags: Vec<String>,
        created_at: Option<i64>,
    ) {
        self.store.insert(
            key,
            KvEntry {
                value,
                description,
                color,
                tags,
                created_at,
            },
        );
        if let Err(e) = self.save_to_file() {
            eprintln!("Failed to save KvStore: {}", e);
        }
    }

    pub fn get(&self, key: &str) -> Option<KvEntry> {
        self.store.get(key).cloned()
    }

    pub fn delete(&mut self, key: &str) {
        if self.store.remove(key).is_some() {
            if let Err(e) = self.save_to_file() {
                eprintln!("Failed to save KvStore: {}", e);
            }
        }
    }
    pub fn list_entries(&self) -> Vec<(String, KvEntry)> {
        let mut entries: Vec<(String, KvEntry)> = self
            .store
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    pub fn nuke(&mut self) {
        self.store.clear();
        if let Err(e) = self.save_to_file() {
            eprintln!("Failed to save KvStore: {}", e);
        }
    }
}
