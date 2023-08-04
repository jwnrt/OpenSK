//! An extremely simple libtock-rs example. Just prints out a message
//! using the Console capsule, then terminates.

#![no_main]
#![no_std]

extern crate lang_items;

use core::fmt::Write;
use libtock_console::Console;
use libtock_runtime::{set_main, stack_size, TockSyscalls};

set_main! {main}
stack_size! {0x100}

fn main() {
    writeln!(Console::<TockSyscalls>::writer(), "Hello world!").unwrap();
}
