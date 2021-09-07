use std::fs::{File, read_to_string};
use std::path::Path;
use std::io::{self, BufRead};

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn read_no_newlines(filename: &str) -> String {
    read_to_string(filename).expect("Error reading file")
        .chars().into_iter().filter(|c| *c != '\n').collect()
}
