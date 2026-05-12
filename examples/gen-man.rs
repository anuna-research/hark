use std::io::Write;

use clap::CommandFactory;

fn main() {
    let cmd = hark::cli::Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf).expect("render man page");
    std::io::stdout()
        .write_all(&buf)
        .expect("write man page to stdout");
}
