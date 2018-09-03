pub const PREFIXES: [u8; 4] = [0xCB, 0xDD, 0xED, 0xFD];
pub const PREFIX_2: u8 = 0xCB;

#[derive(Debug, Copy, Clone)]
pub enum InsnGroup {
    Invalid,
    Regular,
    Jump,
    JumpCond,
    Call,
    CallCond,
    Ret,
    RetCond,
    Int,
    Iret,
    BranchRel,
    BranchRelCond,
}

#[derive(Debug, Clone, Copy)]
pub struct Opcode {
    pub mnemonic_fmt: &'static str,
    pub cycles: (u8, u8),
    pub pre_len: u8,
    pub op_len: u8,
    pub arg_len: u8,
    pub group: InsnGroup,
}

impl Opcode {
    pub const fn new(
        mnemonic_fmt: &'static str,
        cycles: (u8, u8),
        pre_len: u8,
        op_len: u8,
        arg_len: u8,
        group: InsnGroup,
    ) -> Opcode {
        Opcode{mnemonic_fmt, cycles, pre_len, op_len, arg_len, group}
    }

    pub const fn base() -> Opcode {
        Opcode{mnemonic_fmt: "", cycles: (0, 0), pre_len: 0, op_len: 0, arg_len: 0, group: InsnGroup::Invalid}
    }

    #[inline]
    pub fn size(&self) -> usize {
        (self.pre_len + self.op_len + self.arg_len) as usize
    }
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub address: usize,
    pub mnemonic: String,
    pub bytes: Vec<u8>,
    pub arg: u16,
    pub opcode: Opcode,
}

impl Insn {
    pub fn base() -> Insn {
        Insn{
            address: 0,
            mnemonic: String::new(),
            bytes: Vec::default(),
            arg: 0,
            opcode: Opcode::base()
        }
    }
}

pub static OPCODES: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${arg}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${arg}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${arg }",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_CB: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_DD: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_ED: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_FD: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_DDCB: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];

pub static OPCODES_FDCB: [Opcode; 16] = [
    Opcode::new("nop",            (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld bc, ${:04x}", (10, 0), 0, 1, 2, InsnGroup::Regular),
    Opcode::new("ld (bc), a",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec b",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld b, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rlca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ex af, af",      (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("add hl, bc",     (11, 0), 0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld a, (bc)",     (7, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec bc",         (6, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("inc c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("dec c",          (4, 0),  0, 1, 0, InsnGroup::Regular),
    Opcode::new("ld c, ${:02x}",  (7, 0),  0, 1, 1, InsnGroup::Regular),
    Opcode::new("rrca",           (4, 0),  0, 1, 0, InsnGroup::Regular),
];


// #[derive(Debug)]
// pub struct Opcode {
//     mnemonic_fmt: String,
//     group: InsnGroup,
//     cycles: u8,

// }
