#![feature(const_fn)]

extern crate hex;

pub mod dis_z80;
pub use dis_z80::*;
pub use dis_z80::insn::{Insn, InsnGroup, Opcode};

mod tests;
