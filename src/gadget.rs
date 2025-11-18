use crate::types::Gadget;
use crate::pac::{detect_pac_instruction, detect_pac_vulnerabilities};

pub fn is_control_flow_instruction(mnemonic: &str) -> bool {
    matches!(mnemonic,
        // Unsigned control flow
        "ret" | "br" | "blr" |
        // PAC-authenticated returns
        "retaa" | "retab" | "eretaa" | "eretab" |
        // PAC-authenticated branches (register modifier)
        "braa" | "brab" | "blraa" | "blrab" |
        // PAC-authenticated branches (zero modifier)
        "braaz" | "brabz" | "blraaz" | "blrabz"
    )
}

pub fn find_gadgets(instructions: &capstone::Instructions, max_gadget_size: usize) -> Vec<Vec<(u64, String, String)>> {
    let mut gadgets = Vec::new();
    let insns: Vec<_> = instructions.iter().collect();

    for (i, insn) in insns.iter().enumerate() {
        let mnemonic = insn.mnemonic().unwrap();

        // Check if this is a control flow instruction (potential gadget ending)
        if is_control_flow_instruction(mnemonic) {
            // Look backwards to collect the gadget
            for size in 1..=max_gadget_size.min(i + 1) {
                let start_idx = i + 1 - size;
                let gadget: Vec<(u64, String, String)> = insns[start_idx..=i]
                    .iter()
                    .map(|ins| (ins.address(), ins.mnemonic().unwrap().to_string(), ins.op_str().unwrap_or("").to_string()))
                    .collect();
                gadgets.push(gadget);
            }
        }
    }

    gadgets
}

pub fn analyze_gadget(gadget_insns: &[(u64, String, String)], data_sections: &[(u64, u64, String)]) -> Gadget {
    let mut pac_instructions = Vec::new();
    let mut instructions = Vec::new();
    let mut vulnerability_notes = Vec::new();
    let address = gadget_insns.first().map(|i| i.0).unwrap_or(0);

    // Collect instruction strings and detect PAC instructions
    for (_, mnemonic, op_str) in gadget_insns {
        instructions.push(format!("{} {}", mnemonic, op_str));

        if let Some(pac_insn) = detect_pac_instruction(mnemonic) {
            pac_instructions.push(pac_insn);
        }
    }

    // Always run full vulnerability detection to check for br/blr and other patterns
    let gadget_type = detect_pac_vulnerabilities(&pac_instructions, &gadget_insns, data_sections, &mut vulnerability_notes);

    Gadget::new(
        address,
        instructions,
        gadget_type,
        pac_instructions,
        vulnerability_notes,
    )
}
