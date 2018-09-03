pub mod insn;
use hex;
use self::insn::*;


pub fn disass_insn(stream: &Vec<u8>, offset: usize, address: usize) -> Result<Insn, &'static str> {
    let tmp_op: Opcode;
    let mut tmp_insn: Insn = Insn::base();

    if stream.len() >= offset + 1 && PREFIXES.contains(&stream[offset]) ||
       stream.len() >= offset + 2 && PREFIXES.contains(&stream[offset+1]) {
           return Err("Instruction stream ends in a prefix and can't be decoded.")
       }

    let (table, op_pos, arg_pos) = match stream[offset] {
        0xDD if stream[offset + 1] == 0xCB => (OPCODES_DDCB, 3, 2),
        0xFD if stream[offset + 1] == 0xCB => (OPCODES_DDCB, 3, 2),
        0xCB => (OPCODES_CB, 1, 2),
        0xDD => (OPCODES_DD, 1, 2),
        0xED => (OPCODES_ED, 1, 2),
        0xFD => (OPCODES_FD, 1, 2),
        _ => (OPCODES, 0, 1)
    };

    tmp_op = table[stream[offset + op_pos] as usize];
    tmp_insn.opcode = tmp_op;
    tmp_insn.address = address;
    tmp_insn.bytes = stream[offset..offset+tmp_op.size()].to_vec();

    let arg_idx = offset + arg_pos;
    tmp_insn.arg = match tmp_op.arg_len {
        1 => stream[arg_idx] as u16,
        2 => stream[arg_idx] as u16 + (stream[arg_idx + 1] as u16) << 8,
        _ => 0
    };

    tmp_insn.mnemonic = match tmp_op.arg_len {
        1 => tmp_op.mnemonic_fmt.replace("{arg}", format!("{:02x}", tmp_insn.arg).as_str()),
        2 => tmp_op.mnemonic_fmt.replace("{arg}", format!("{:04x}", tmp_insn.arg).as_str()),
        _ => tmp_op.mnemonic_fmt.to_owned()
    };

    Ok(tmp_insn)
}


pub fn disass_hex_string(hex_string: &str, address: usize) -> Result<Vec<Insn>, &'static str> {
    let mut insns: Vec<Insn> = Vec::new();
    let mut idx: usize = 0;
    let mut tmp_insn: Insn;

    let stream = hex::decode(hex_string)
        .expect("Invalid hex string passed to disass_hex_string");

    while idx < stream.len() {
        tmp_insn = match disass_insn(&stream, idx, address) {
            Ok(v) => v,
            Err(_e) => panic!("Disassembling instruction at 0x{:x} failed")
        };  

        idx += tmp_insn.opcode.size();

        insns.push(tmp_insn.clone());
    }

    Ok(insns)
}
