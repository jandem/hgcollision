extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use std::collections::HashSet;
use std::io::Write;
use std::process::Command;
use rand::random;

fn get_rev_hash(rev: &str) -> String {
    let p = Command::new("hg").arg("log").arg("-r").arg(rev).arg("--template").arg("{node}")
        .output().ok().expect("Failed to execute.");
    String::from_utf8(p.stdout).unwrap()
}

fn get_revlog(rev: &str) -> String {
    let p = Command::new("hg").arg("debugdata").arg("-c").arg(rev)
        .output().ok().expect("Failed to execute.");
    String::from_utf8(p.stdout).unwrap()
}

fn get_all_hashes() -> String {
    let p = Command::new("hg").arg("log").arg("--template").arg("{node}\n")
        .output().ok().expect("Failed to execute.");
    String::from_utf8(p.stdout).unwrap()
}

// This function was copied from libserialize/hex.rs...
fn from_hex(input: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(input.len() / 2);
    let mut modulus = 0;
    let mut buf = 0u8;

    for (_, byte) in input.bytes().enumerate() {
        buf <<= 4;

        match byte as char {
            'A'...'F' => buf |= byte - ('A' as u8) + 10,
            'a'...'f' => buf |= byte - ('a' as u8) + 10,
            '0'...'9' => buf |= byte - ('0' as u8),
            ' '|'\r'|'\n'|'\t' => {
                buf >>= 4;
                continue
            }
            _ => panic!()
        }

        modulus += 1;
        if modulus == 2 {
            modulus = 0;
            b.push(buf);
        }
    }

    b
}

fn main() {
    let current = get_rev_hash("tip");
    let parent = get_rev_hash("tip^");

    println!("Current hash: {}", current);
    println!("Parent hash: {}", parent);

    let revlog = get_revlog(&current);
    println!("--------------");
    println!("Revlog: {}", revlog);
    println!("--------------");

    println!("Loading hashes..");
    let hashes_str = get_all_hashes();

    println!("Creating prefix set");

    let mut prefixes : HashSet<String> = HashSet::new();

    for h in hashes_str.split("\n") {
        let prefix : String = h.chars().take(12).collect();
        if prefix.len() != 12 {
            continue //XXX
        }
        if prefixes.contains(&prefix) {
            println!("Repo already has short hash collision! {}", prefix);
        }
        prefixes.insert(prefix);
    }

    println!("Got {} prefixes", prefixes.len());

    let null_id = [0; 20];

    let mut hasher = Sha1::new();
    hasher.input(&null_id);
    hasher.input(&from_hex(&parent));
    hasher.input_str(&revlog);

    // Append a random number to allow running the program in multiple processes.
    let r = random::<u32>();
    hasher.input_str(&r.to_string());
    hasher.input_str("_");
    println!("Generated random prefix: {}_", r);

    let mut stdout = std::io::stdout();

    let mut i = 0u64;
    loop {
        let mut hasher1 = hasher; // Copy.

        hasher1.input_str(&i.to_string());

        let hex = hasher1.result_str();
        let prefix : String = hex.chars().take(12).collect();

        if prefixes.contains(&prefix) {
            print!("\n");
            println!("Found collision! Prefix: {}, hash: {}", prefix, hex);
            println!("Add this to the end of your commit message: {}_{}", r, i);
            break;
        }

        if i % (1 << 18) == 0 {
            print!("Tried {} hashes\r", i);
            stdout.flush().unwrap();
        }

        i += 1;
    }

    println!("Done!");
}
