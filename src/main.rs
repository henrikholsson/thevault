use std::io::{self, Write};
use arboard::Clipboard;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};
use chrono::{Local, TimeZone};
use pbkdf2::pbkdf2_hmac;
use rand::{thread_rng, RngCore};
use rpassword::read_password;
use sha2::Sha256;
mod file;
mod encryption;
mod compression;
use crate::file::file::{KvEntry, KvStore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let password = read_password().unwrap_or_else(|err| {
        eprintln!("Failed to read password: {}", err);
        std::process::exit(1);
    });
    println!();
    password
}

const CLIPBOARD_CLEAR_SECONDS: u64 = 45;

struct PasswordRecord {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let pair = format!("{}{}", hi, lo);
        let byte = u8::from_str_radix(&pair, 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

fn parse_password_record(contents: &str) -> Option<PasswordRecord> {
    let mut parts = contents.trim().split('\t');
    let version = parts.next()?;
    if version != "v1" {
        return None;
    }
    let iterations = parts.next()?.parse::<u32>().ok()?;
    let salt_hex = parts.next()?;
    let hash_hex = parts.next()?;
    let salt = hex_to_bytes(salt_hex)?;
    let hash = hex_to_bytes(hash_hex)?;
    Some(PasswordRecord {
        iterations,
        salt,
        hash,
    })
}

fn read_password_record(path: &str) -> io::Result<Option<PasswordRecord>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let record = parse_password_record(&contents)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid password file"))?;
            Ok(Some(record))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn write_password_record(path: &str, record: &PasswordRecord) -> io::Result<()> {
    let contents = format!(
        "v1\t{}\t{}\t{}\n",
        record.iterations,
        bytes_to_hex(&record.salt),
        bytes_to_hex(&record.hash)
    );
    std::fs::write(path, contents)
}

fn derive_password_hash(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut hash = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut hash);
    hash
}

fn prompt_new_password() -> String {
    loop {
        let password = prompt_password("Create vault password: ");
        if password.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        let confirm = prompt_password("Confirm password: ");
        if password != confirm {
            println!("Passwords do not match.");
            continue;
        }
        return password;
    }
}

fn init_password(password_path: &str, log_path: &str) -> io::Result<(String, bool)> {
    const ITERATIONS: u32 = 100_000;
    if let Some(record) = read_password_record(password_path)? {
        loop {
            let password = prompt_password("Enter vault password: ");
            let hash = derive_password_hash(&password, &record.salt, record.iterations);
            if hash == record.hash {
                return Ok((password, true));
            }
            println!("Incorrect password.");
        }
    }

    let log_has_data = match std::fs::read(log_path) {
        Ok(data) => !data.is_empty(),
        Err(_) => false,
    };
    if log_has_data {
        println!("Warning: existing vault data found, but no password file.");
        println!("A new password will start a fresh vault.");
    }

    let password = prompt_new_password();
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    let hash = derive_password_hash(&password, &salt, ITERATIONS);
    let record = PasswordRecord {
        iterations: ITERATIONS,
        salt: salt.to_vec(),
        hash,
    };
    write_password_record(password_path, &record)?;
    Ok((password, false))
}

fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn format_created(created_at: Option<i64>) -> String {
    if let Some(timestamp) = created_at {
        if let Some(datetime) = Local.timestamp_opt(timestamp, 0).single() {
            return format!("Created: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
        }
    }
    "Created: unknown".to_string()
}

fn normalize_tag(tag: &str) -> Option<String> {
    let tag = tag.trim().trim_start_matches('#');
    if tag.is_empty() {
        return None;
    }
    Some(tag.to_lowercase())
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut results = Vec::new();
    for tag in tags {
        if let Some(tag) = normalize_tag(&tag) {
            if !results.contains(&tag) {
                results.push(tag);
            }
        }
    }
    results
}

fn parse_tags_list(value: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for tag in value.split(',') {
        if let Some(tag) = normalize_tag(tag) {
            tags.push(tag);
        }
    }
    normalize_tags(tags)
}

fn parse_tags_token(token: &str) -> Option<Vec<String>> {
    let token = token.trim();
    let token = token.trim_matches(|c: char| {
        !c.is_ascii_alphanumeric() && c != '=' && c != ':' && c != ',' && c != '#'
    });
    let token = token.to_lowercase();
    if let Some(rest) = token.strip_prefix("tags=") {
        return Some(parse_tags_list(rest));
    }
    if let Some(rest) = token.strip_prefix("tags:") {
        return Some(parse_tags_list(rest));
    }
    if let Some(rest) = token.strip_prefix("tag=") {
        return Some(parse_tags_list(rest));
    }
    if let Some(rest) = token.strip_prefix("tag:") {
        return Some(parse_tags_list(rest));
    }
    None
}

fn entry_tags(entry: &KvEntry) -> Vec<String> {
    let mut tags = entry.tags.clone();
    for token in entry.description.split_whitespace() {
        if let Some(extra_tags) = parse_tags_token(token) {
            tags.extend(extra_tags);
        }
    }
    normalize_tags(tags)
}

fn color_from_name(value: &str) -> Option<String> {
    let value = value
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_lowercase();
    match value.as_str() {
        "red" | "green" | "yellow" | "blue" | "magenta" | "cyan" | "white" => Some(value),
        _ => None,
    }
}

fn parse_color_value(token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let token = token
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '=' && c != ':')
        .to_lowercase();
    if let Some(rest) = token.strip_prefix("color=") {
        return color_from_name(rest);
    }
    if let Some(rest) = token.strip_prefix("color:") {
        return color_from_name(rest);
    }
    color_from_name(&token)
}

fn parse_color_tag(token: &str) -> Option<String> {
    let token = token.trim();
    let token = token
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '=' && c != ':')
        .to_lowercase();
    if let Some(rest) = token.strip_prefix("color=") {
        return color_from_name(rest);
    }
    if let Some(rest) = token.strip_prefix("color:") {
        return color_from_name(rest);
    }
    None
}

fn color_to_crossterm(value: &str) -> Color {
    match value {
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "white" => Color::White,
        _ => Color::White,
    }
}

fn entry_color(entry: &KvEntry, key: &str) -> Color {
    if let Some(color) = entry.color.as_deref().and_then(parse_color_value) {
        return color_to_crossterm(&color);
    }
    if let Some(color) = entry
        .description
        .split_whitespace()
        .find_map(parse_color_tag)
    {
        return color_to_crossterm(&color);
    }

    let key = key.to_lowercase();
    if key.contains("prod") || key.contains("live") || key.contains("critical") {
        Color::Red
    } else if key.contains("stage") || key.contains("staging") {
        Color::Yellow
    } else if key.contains("dev") || key.contains("test") {
        Color::Green
    } else {
        Color::White
    }
}

fn truncate_ascii(text: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_len {
        return text.to_string();
    }
    if max_len <= 3 {
        return text.chars().take(max_len).collect();
    }
    let mut out: String = text.chars().take(max_len - 3).collect();
    out.push_str("...");
    out
}

fn display_description(description: &str) -> String {
    let mut parts = Vec::new();
    for token in description.split_whitespace() {
        if parse_color_tag(token).is_some() {
            continue;
        }
        if parse_tags_token(token).is_some() {
            continue;
        }
        parts.push(token);
    }
    parts.join(" ")
}

fn format_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        String::new()
    } else {
        tags.join(",")
    }
}

fn display_entry_summary(entry: &KvEntry) -> String {
    let mut description = display_description(&entry.description);
    let tags = entry_tags(entry);
    if !tags.is_empty() {
        let tags_display = format!("tags: {}", format_tags(&tags));
        if description.is_empty() {
            description = tags_display;
        } else {
            description = format!("{} [{}]", description, tags_display);
        }
    }
    description
}

fn entry_search_blob(key: &str, entry: &KvEntry) -> String {
    let description = display_description(&entry.description);
    let tags = entry_tags(entry).join(" ");
    let color = entry.color.clone().unwrap_or_default();
    format!("{} {} {} {}", key, description, tags, color).to_lowercase()
}

fn filter_entries(entries: &[(String, KvEntry)], query: &str) -> Vec<(String, KvEntry)> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return entries.to_vec();
    }
    let terms: Vec<&str> = query.split_whitespace().collect();
    entries
        .iter()
        .filter(|(key, entry)| {
            let blob = entry_search_blob(key, entry);
            terms.iter().all(|term| blob.contains(term))
        })
        .cloned()
        .collect()
}

fn mask_value(value: &str, reveal: bool) -> String {
    let len = value.chars().count();
    if len == 0 {
        return String::new();
    }
    if !reveal {
        return "*".repeat(len);
    }
    if len <= 2 {
        return "*".repeat(len);
    }
    if len <= 4 {
        let mut chars = value.chars();
        let first = chars.next().unwrap();
        let last = value.chars().last().unwrap();
        let stars = "*".repeat(len.saturating_sub(2));
        return format!("{}{}{}", first, stars, last);
    }
    let prefix: String = value.chars().take(2).collect();
    let suffix: String = value.chars().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
    let stars = "*".repeat(len.saturating_sub(4));
    format!("{}{}{}", prefix, stars, suffix)
}

fn parse_description_color_tags(remainder: &str) -> (String, Option<String>, Vec<String>, bool, bool) {
    let remainder = remainder.trim();
    if remainder.is_empty() {
        return (String::new(), None, Vec::new(), false, false);
    }

    let mut tags = Vec::new();
    let mut tags_explicit = false;
    let mut color = None;

    if remainder.starts_with('"') {
        let after_open = &remainder[1..];
        if let Some(end) = after_open.find('"') {
            let mut description = after_open[..end].to_string();
            let tail = after_open[end + 1..].trim();
            let mut extra = Vec::new();
            if !tail.is_empty() {
                let tokens: Vec<&str> = tail.split_whitespace().collect();
                for token in tokens {
                    if let Some(found) = parse_tags_token(token) {
                        tags.extend(found);
                        tags_explicit = true;
                        continue;
                    }
                    if color.is_none() {
                        if let Some(found) = parse_color_tag(token) {
                            color = Some(found);
                            continue;
                        }
                    }
                    extra.push(token.to_string());
                }
            }
            if color.is_none() && !extra.is_empty() {
                if let Some(found) = parse_color_value(&extra[extra.len() - 1]) {
                    color = Some(found);
                    extra.pop();
                }
            }
            if !extra.is_empty() {
                if description.is_empty() {
                    description = extra.join(" ");
                } else {
                    description = format!("{} {}", description, extra.join(" "));
                }
            }
            return (description, color, normalize_tags(tags), true, tags_explicit);
        }
        return (after_open.to_string(), None, Vec::new(), true, false);
    }

    let tokens: Vec<&str> = remainder.split_whitespace().collect();
    let mut description_parts = Vec::new();
    for token in tokens {
        if let Some(found) = parse_tags_token(token) {
            tags.extend(found);
            tags_explicit = true;
            continue;
        }
        if color.is_none() {
            if let Some(found) = parse_color_tag(token) {
                color = Some(found);
                continue;
            }
        }
        description_parts.push(token.to_string());
    }

    if color.is_none() && !description_parts.is_empty() {
        if let Some(found) = parse_color_value(&description_parts[description_parts.len() - 1]) {
            color = Some(found);
            description_parts.pop();
        }
    }

    let description = description_parts.join(" ");
    let description_explicit = !description.is_empty();
    (
        description,
        color,
        normalize_tags(tags),
        description_explicit,
        tags_explicit,
    )
}

fn parse_set_command(
    input: &str,
) -> Option<(String, String, String, Option<String>, Vec<String>, bool, bool)> {
    let mut iter = input.trim().splitn(2, |c: char| c.is_whitespace());
    let cmd = iter.next()?;
    if !cmd.eq_ignore_ascii_case("set") {
        return None;
    }
    let rest = iter.next().unwrap_or("").trim();
    if rest.is_empty() {
        return None;
    }
    let mut rest_iter = rest.splitn(3, |c: char| c.is_whitespace());
    let key = rest_iter.next()?.to_string();
    let value = rest_iter.next()?.to_string();
    let remainder = rest_iter.next().unwrap_or("");
    let (description, color, tags, description_explicit, tags_explicit) =
        parse_description_color_tags(remainder);
    Some((
        key,
        value,
        description,
        color,
        tags,
        description_explicit,
        tags_explicit,
    ))
}

fn parse_command_with_key(input: &str, command: &str) -> Option<(String, String)> {
    let mut iter = input.trim().splitn(2, |c: char| c.is_whitespace());
    let cmd = iter.next()?;
    if !cmd.eq_ignore_ascii_case(command) {
        return None;
    }
    let rest = iter.next().unwrap_or("").trim();
    if rest.is_empty() {
        return None;
    }
    let mut rest_iter = rest.splitn(2, |c: char| c.is_whitespace());
    let key = rest_iter.next()?.to_string();
    let remainder = rest_iter.next().unwrap_or("").trim().to_string();
    Some((key, remainder))
}

fn draw_browser(
    entries: &[(String, KvEntry)],
    selected: usize,
    offset: usize,
    reveal_value: bool,
    confirm_delete: bool,
    search_query: &str,
    search_active: bool,
) -> io::Result<()> {
    let mut stdout = io::stdout();
    let (cols, rows) = terminal::size()?;
    let cols = cols as usize;
    let show_search = search_active || !search_query.is_empty();
    let reserved_lines = 6 + if show_search { 1 } else { 0 };
    let max_rows = usize::max(rows.saturating_sub(reserved_lines) as usize, 1);
    let key_width = usize::min(24, cols.saturating_sub(1));
    let desc_width = cols.saturating_sub(key_width + 1);

    execute!(stdout, cursor::MoveTo(0, 0), Clear(ClearType::All))?;
    let reveal_state = if reveal_value { "ON" } else { "OFF" };
    execute!(
        stdout,
        Print(format!(
            "Use Up/Down to move, Enter to execute, R to reveal ({}), D to delete, / to search, Esc to exit.\n",
            reveal_state
        ))
    )?;
    if show_search {
        let label = if search_active { "Search: " } else { "Filter: " };
        let available = cols.saturating_sub(label.len());
        let display = truncate_ascii(search_query, available);
        execute!(stdout, Print(format!("{}{}\n", label, display)))?;
    }
    execute!(stdout, Print("\n\n"))?;

    if entries.is_empty() {
        execute!(stdout, Print("No matches\n"))?;
    } else {
        for (index, (key, entry)) in entries.iter().enumerate().skip(offset).take(max_rows) {
            let is_selected = index == selected;
            let color = entry_color(entry, key);
            let description = display_entry_summary(entry);
            let key_display = truncate_ascii(key, key_width);
            let key_display = format!("{:<width$}", key_display, width = key_width);
            let description = truncate_ascii(&description, desc_width);
            if is_selected {
                execute!(stdout, SetAttribute(Attribute::Reverse))?;
            }
            execute!(
                stdout,
                SetForegroundColor(color),
                Print(key_display),
                ResetColor,
                Print(if desc_width == 0 || description.is_empty() {
                    String::new()
                } else {
                    format!(" {}", description)
                }),
                SetAttribute(Attribute::Reset),
                Print("\n")
            )?;
        }
    }

    let value_line = if let Some((_, entry)) = entries.get(selected) {
        let masked = mask_value(&entry.value, reveal_value);
        let label = if reveal_value { "Value: " } else { "Value: " };
        let available = cols.saturating_sub(label.len());
        format!("{}{}", label, truncate_ascii(&masked, available))
    } else {
        String::new()
    };
    let info_line = if confirm_delete {
        if let Some((key, _)) = entries.get(selected) {
            let message = format!("Delete '{}' ? (y/n)", key);
            truncate_ascii(&message, cols)
        } else {
            String::new()
        }
    } else if let Some((_, entry)) = entries.get(selected) {
        truncate_ascii(&format_created(entry.created_at), cols)
    } else {
        String::new()
    };
    let footer = if entries.is_empty() {
        "Showing 0 of 0".to_string()
    } else {
        format!(
            "Showing {}-{} of {}",
            offset + 1,
            usize::min(offset + max_rows, entries.len()),
            entries.len()
        )
    };
    execute!(
        stdout,
        Print("\n"),
        Print(value_line),
        Print("\n"),
        Print(info_line),
        Print("\n"),
        Print(footer)
    )?;
    stdout.flush()?;
    Ok(())
}

enum BrowserOutcome {
    Copied(KvEntry),
    Cancelled,
    Empty,
}

fn run_key_browser(db: &mut KvStore) -> io::Result<BrowserOutcome> {
    let mut all_entries = db.list_entries();
    if all_entries.is_empty() {
        return Ok(BrowserOutcome::Empty);
    }
    let mut search_query = String::new();
    let mut search_active = false;
    let mut entries = filter_entries(&all_entries, &search_query);
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;

    let mut selected = 0usize;
    let mut offset = 0usize;
    let mut reveal_value = false;
    let mut confirm_delete = false;
    let mut selected_result: Option<usize> = None;
    let mut error: Option<io::Error> = None;

    while event::poll(Duration::from_millis(0))? {
        let _ = event::read();
    }

    loop {
        if entries.is_empty() {
            selected = 0;
            offset = 0;
            confirm_delete = false;
        } else if selected >= entries.len() {
            selected = entries.len() - 1;
        }

        if let Err(err) = draw_browser(
            &entries,
            selected,
            offset,
            reveal_value,
            confirm_delete,
            &search_query,
            search_active,
        ) {
            error = Some(err);
            break;
        }

        match event::read() {
            Ok(Event::Key(key_event)) => {
                if matches!(key_event.kind, KeyEventKind::Release) {
                    continue;
                }
                if search_active {
                    match key_event.code {
                        KeyCode::Enter => {
                            search_active = false;
                        }
                        KeyCode::Esc => {
                            search_active = false;
                            search_query.clear();
                            entries = filter_entries(&all_entries, &search_query);
                            selected = 0;
                            offset = 0;
                        }
                        KeyCode::Backspace => {
                            search_query.pop();
                            entries = filter_entries(&all_entries, &search_query);
                            selected = 0;
                            offset = 0;
                        }
                        KeyCode::Char(ch) => {
                            if !ch.is_control() {
                                search_query.push(ch);
                                entries = filter_entries(&all_entries, &search_query);
                                selected = 0;
                                offset = 0;
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                match key_event.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') if confirm_delete => {
                        if let Some((key, _)) = entries.get(selected) {
                            db.delete(key);
                            all_entries = db.list_entries();
                            entries = filter_entries(&all_entries, &search_query);
                            if all_entries.is_empty() {
                                selected_result = None;
                                break;
                            }
                        }
                        confirm_delete = false;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc if confirm_delete => {
                        confirm_delete = false;
                    }
                    _ if confirm_delete => {}
                    KeyCode::Up => {
                        if selected > 0 {
                            selected -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if selected + 1 < entries.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if !entries.is_empty() {
                            selected_result = Some(selected);
                            break;
                        }
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        reveal_value = !reveal_value;
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        if !entries.is_empty() {
                            confirm_delete = true;
                        }
                    }
                    KeyCode::Char('/') => {
                        search_active = true;
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        selected_result = None;
                        break;
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(err) => {
                error = Some(err);
                break;
            }
        }

        let (_, rows) = terminal::size()?;
        let reserved_lines = 6 + if search_active || !search_query.is_empty() { 1 } else { 0 };
        let max_rows = usize::max(rows.saturating_sub(reserved_lines) as usize, 1);
        if selected < offset {
            offset = selected;
        } else if selected >= offset + max_rows {
            offset = selected + 1 - max_rows;
        }
    }

    let _ = execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
    if let Some(err) = error {
        return Err(err);
    }
    match selected_result {
        Some(index) => Ok(entries
            .get(index)
            .map(|(_, entry)| BrowserOutcome::Copied(entry.clone()))
            .unwrap_or(BrowserOutcome::Cancelled)),
        None => {
            if all_entries.is_empty() {
                Ok(BrowserOutcome::Empty)
            } else {
                Ok(BrowserOutcome::Cancelled)
            }
        }
    }
}

fn show_entry(entry: &KvEntry) {
    let description = display_description(&entry.description);
    if !description.trim().is_empty() {
        println!("Description: {}", description);
    }
    let tags = entry_tags(entry);
    if !tags.is_empty() {
        println!("Tags: {}", format_tags(&tags));
    }
    println!("{}", format_created(entry.created_at));
    match Clipboard::new() {
        Ok(mut clipboard) => {
            if let Err(err) = clipboard.set_text(entry.value.clone()) {
                eprintln!("Failed to copy to clipboard: {}", err);
                println!("{}", entry.value);
            } else {
                let value = entry.value.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECONDS));
                    if let Ok(mut clipboard) = Clipboard::new() {
                        if let Ok(current) = clipboard.get_text() {
                            if current == value {
                                let _ = clipboard.set_text(String::new());
                            }
                        }
                    }
                });
                println!("Copied to clipboard (clears in {}s)", CLIPBOARD_CLEAR_SECONDS);
            }
        }
        Err(err) => {
            eprintln!("Clipboard unavailable: {}", err);
            println!("{}", entry.value);
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  set <key> <value> [\"description\"] [color] [tags=env,personal]");
    println!("  get <key>");
    println!("  describe <key> \"description\" [color] [tags=env,personal]");
    println!("  all");
    println!("  delete <key>");
    println!("  exit");
    println!();
    println!("Colors: red, green, yellow, blue, magenta, cyan, white.");
    println!("List view: Up/Down to move, Enter to copy, R to reveal, D to delete, / to search, Esc to exit.");
    println!("Delete confirmation: Y to confirm, N or Esc to cancel.");
    println!("Clipboard: clears copied values after {} seconds.", CLIPBOARD_CLEAR_SECONDS);
}

fn main() {
    const LOG_PATH: &str = "kvstore.log";
    const PASSWORD_PATH: &str = "kvstore.pw";
    let (password, load_existing) = init_password(PASSWORD_PATH, LOG_PATH).unwrap_or_else(|err| {
        eprintln!("Failed to initialize password: {}", err);
        std::process::exit(1);
    });
    let mut db = if load_existing {
        KvStore::new(LOG_PATH, &password)
    } else {
        KvStore::new_empty(LOG_PATH, &password)
    };
    println!("Welcome to the Rock");
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if input.eq_ignore_ascii_case("-h")
            || input.eq_ignore_ascii_case("help")
            || input == "?"
        {
            print_help();
            continue;
        }
        if let Some((
            key,
            value,
            mut description,
            mut color,
            mut tags,
            description_explicit,
            tags_explicit,
        )) = parse_set_command(input)
        {
            let created_at = if let Some(existing) = db.get(&key) {
                if !description_explicit {
                    description = existing.description;
                }
                if color.is_none() {
                    color = existing.color;
                }
                if !tags_explicit {
                    tags = existing.tags;
                }
                existing.created_at
            } else {
                Some(now_timestamp())
            };
            db.set(key, value, description, color, normalize_tags(tags), created_at);
            println!("OK");
            continue;
        }

        if let Some((key, remainder)) = parse_command_with_key(input, "describe") {
            let (description, color, tags, description_explicit, tags_explicit) =
                parse_description_color_tags(&remainder);
            if !description_explicit && !tags_explicit && color.is_none() {
                println!("Missing description");
                continue;
            }
            match db.get(&key) {
                Some(entry) => {
                    let mut new_description = entry.description;
                    let mut new_color = entry.color;
                    let mut new_tags = entry.tags;
                    if description_explicit {
                        new_description = description;
                    }
                    if color.is_some() {
                        new_color = color;
                    }
                    if tags_explicit {
                        new_tags = tags;
                    }
                    db.set(
                        key,
                        entry.value,
                        new_description,
                        new_color,
                        normalize_tags(new_tags),
                        entry.created_at,
                    );
                    println!("OK");
                }
                None => println!("Key not found"),
            }
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();

        match parts.as_slice() {
            [cmd, key] if cmd.to_lowercase() == "get" => {
                match db.get(key) {
                    Some(entry) => {
                        show_entry(&entry);
                    }
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
            [cmd] if cmd.to_lowercase() == "all" => {
                match run_key_browser(&mut db) {
                    Ok(BrowserOutcome::Copied(entry)) => {
                        show_entry(&entry);
                    }
                    Ok(BrowserOutcome::Empty) => {
                        println!("No keys found");
                    }
                    Ok(BrowserOutcome::Cancelled) => {}
                    Err(err) => eprintln!("Browser error: {}", err),
                }
            }
            [cmd] if cmd.to_lowercase() == "nuke" => {
                db.nuke();
            }
            _ => println!("Invalid Command! Use -h for help."),
        }
    }
}
