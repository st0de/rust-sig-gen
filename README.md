# rust-sig-gen
A vibe-coded tool to generate IDA signatures of the most popular Rust crates.

This tool download the top 100 Rust crates, compile them for Linux and x86_64 Windows and generate their FLAIR signatures.

## Dependencies
- Python pip requests.
- IDA Pro sigmake, pelf and pcf tools.
- Rust compiler

## Setup
- Copy sigmake, pelf and pcf from `$IDA_HOME/tools/flair` into the `flair` folder.
- Install reuqests `pip install requests`
- Install rustc, https://rust-lang.org/tools/install/

## Execution
Simply run `python3 main.py`.
