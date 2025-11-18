use crate::types::{PacInstruction, GadgetType};

/// Parse load address from ldr instruction operands
/// Handles PC-relative loads: "ldr x0, [pc, #0x1000]"
/// Returns the absolute address being loaded from
fn parse_load_address(op_str: &str, insn_addr: u64) -> Option<u64> {
    // Look for PC-relative loads: [pc, #offset] or [pc, offset]
    if op_str.contains("pc") {
        // Extract offset from something like "x0, [pc, #0x1000]"
        let parts: Vec<&str> = op_str.split(',').collect();
        if parts.len() >= 3 {
            let offset_str = parts[2].trim().trim_end_matches(']');
            let offset_str = offset_str.trim_start_matches('#');

            // Parse hex or decimal
            let offset = if offset_str.starts_with("0x") {
                i64::from_str_radix(offset_str.trim_start_matches("0x"), 16).ok()?
            } else {
                offset_str.parse::<i64>().ok()?
            };

            // PC-relative addressing: PC + offset
            // On ARM64, PC points to current instruction
            Some((insn_addr as i64 + offset) as u64)
        } else {
            None
        }
    } else {
        // For non-PC relative loads, we can't determine the address statically
        None
    }
}

pub fn detect_pac_instruction(mnemonic: &str) -> Option<PacInstruction> {
    match mnemonic {
        // Sign instructions
        "paciasp" => Some(PacInstruction::PacIASP),
        "paciaz" => Some(PacInstruction::PacIAZ),
        "pacia" => Some(PacInstruction::PacIA),
        "pacda" => Some(PacInstruction::PacDA),
        "pacibsp" => Some(PacInstruction::PacIBSP),
        "pacibz" => Some(PacInstruction::PacIBZ),
        "pacib" => Some(PacInstruction::PacIB),
        "pacdb" => Some(PacInstruction::PacDB),
        // Authenticate instructions
        "autiasp" => Some(PacInstruction::AutIASP),
        "autiaz" => Some(PacInstruction::AutIAZ),
        "autia" => Some(PacInstruction::AutIA),
        "autda" => Some(PacInstruction::AutDA),
        "autibsp" => Some(PacInstruction::AutIBSP),
        "autibz" => Some(PacInstruction::AutIBZ),
        "autib" => Some(PacInstruction::AutIB),
        "autdb" => Some(PacInstruction::AutDB),
        // Combined operations: auth + return
        "retaa" => Some(PacInstruction::RetAA),
        "retab" => Some(PacInstruction::RetAB),
        "eretaa" => Some(PacInstruction::RetAA),  // Exception return with A key
        "eretab" => Some(PacInstruction::RetAB),  // Exception return with B key
        // Combined operations: auth + branch (register modifier)
        "braa" => Some(PacInstruction::AutIA),    // Branch with A key auth, register modifier
        "brab" => Some(PacInstruction::AutIB),    // Branch with B key auth, register modifier
        "blraa" => Some(PacInstruction::AutIA),   // Branch-link with A key auth, register modifier
        "blrab" => Some(PacInstruction::AutIB),   // Branch-link with B key auth, register modifier
        // Combined operations: auth + branch (zero modifier)
        "braaz" => Some(PacInstruction::AutIAZ),  // Branch with A key auth, zero modifier
        "brabz" => Some(PacInstruction::AutIBZ),  // Branch with B key auth, zero modifier
        "blraaz" => Some(PacInstruction::AutIAZ), // Branch-link with A key auth, zero modifier
        "blrabz" => Some(PacInstruction::AutIBZ), // Branch-link with B key auth, zero modifier
        _ => None,
    }
}

pub fn detect_pac_vulnerabilities(
    pac_insns: &[PacInstruction],
    gadget_insns: &[(u64, String, String)],
    data_sections: &[(u64, u64, String)],
    notes: &mut Vec<String>,
) -> GadgetType {
    let mut has_sign = false;
    let mut has_auth = false;
    let mut uses_zero_modifier = false;
    let mut modifies_context = false;

    // Track key usage for key confusion detection
    let mut uses_a_key_sign = false;
    let mut uses_b_key_sign = false;
    let mut uses_a_key_auth = false;
    let mut uses_b_key_auth = false;

    // Track modifier types for modifier confusion
    let mut uses_sp_modifier_sign = false;
    let mut uses_zero_modifier_sign = false;
    let mut uses_sp_modifier_auth = false;
    let mut uses_zero_modifier_auth = false;

    // Analyze PAC instructions
    for pac_insn in pac_insns {
        match pac_insn {
            // A key sign operations
            PacInstruction::PacIASP => {
                has_sign = true;
                uses_a_key_sign = true;
                uses_sp_modifier_sign = true;
            }
            PacInstruction::PacIAZ => {
                has_sign = true;
                uses_a_key_sign = true;
                uses_zero_modifier = true;
                uses_zero_modifier_sign = true;
                notes.push("Uses zero modifier - may be replay vulnerable".to_string());
            }
            PacInstruction::PacIA | PacInstruction::PacDA => {
                has_sign = true;
                uses_a_key_sign = true;
            }
            // B key sign operations
            PacInstruction::PacIBSP => {
                has_sign = true;
                uses_b_key_sign = true;
                uses_sp_modifier_sign = true;
            }
            PacInstruction::PacIBZ => {
                has_sign = true;
                uses_b_key_sign = true;
                uses_zero_modifier = true;
                uses_zero_modifier_sign = true;
                notes.push("Uses zero modifier - may be replay vulnerable".to_string());
            }
            PacInstruction::PacIB | PacInstruction::PacDB => {
                has_sign = true;
                uses_b_key_sign = true;
            }
            // A key auth operations
            PacInstruction::AutIASP => {
                has_auth = true;
                uses_a_key_auth = true;
                uses_sp_modifier_auth = true;
            }
            PacInstruction::AutIAZ => {
                has_auth = true;
                uses_a_key_auth = true;
                uses_zero_modifier = true;
                uses_zero_modifier_auth = true;
                notes.push("Uses zero modifier - may be replay vulnerable".to_string());
            }
            PacInstruction::AutIA | PacInstruction::AutDA => {
                has_auth = true;
                uses_a_key_auth = true;
            }
            // B key auth operations
            PacInstruction::AutIBSP => {
                has_auth = true;
                uses_b_key_auth = true;
                uses_sp_modifier_auth = true;
            }
            PacInstruction::AutIBZ => {
                has_auth = true;
                uses_b_key_auth = true;
                uses_zero_modifier = true;
                uses_zero_modifier_auth = true;
                notes.push("Uses zero modifier - may be replay vulnerable".to_string());
            }
            PacInstruction::AutIB | PacInstruction::AutDB => {
                has_auth = true;
                uses_b_key_auth = true;
            }
            // Combined operations
            PacInstruction::RetAA => {
                has_auth = true;
                uses_a_key_auth = true;
            }
            PacInstruction::RetAB => {
                has_auth = true;
                uses_b_key_auth = true;
            }
        }
    }

    // Check for unsigned indirect branches AND pre-authenticated loads
    let mut has_br_blr = false;
    let mut br_blr_register = None;

    for (_, mnemonic, op_str) in gadget_insns {
        if mnemonic == "br" || mnemonic == "blr" {
            has_br_blr = true;
            // Extract the register being branched to (e.g., "x0" from "br x0")
            br_blr_register = op_str.split(',').next().map(|s| s.trim().to_string());
            break;
        }
    }

    if has_br_blr {
        // Check if the br/blr register is loaded from a data section
        if let Some(ref target_reg) = br_blr_register {
            for (i, (_, mnemonic, op_str)) in gadget_insns.iter().enumerate() {
                // Look for loads into the target register
                if mnemonic.starts_with("ldr") && op_str.starts_with(target_reg) {
                    // Parse the load address if it's an immediate load
                    // Example: "ldr x0, [x1, #0x10]" or "ldr x0, [pc, #0x1000]"
                    if let Some(load_addr) = parse_load_address(op_str, gadget_insns[i].0) {
                        // Check if this address is in a data section
                        for (start, end, section_name) in data_sections {
                            if load_addr >= *start && load_addr < *end {
                                notes.push(format!("Loads from {} (likely PAC-signed pointer)", section_name));
                                notes.push(format!("Address: 0x{:x}", load_addr));
                                return GadgetType::PreAuthLoad;
                            }
                        }
                    }
                }
            }
        }

        // If no pre-auth load detected, it's just unsigned indirect
        notes.push("Unsigned indirect branch - no PAC check".to_string());
        return GadgetType::UnsignedIndirect;
    }

    // Check for stack pivot (SP manipulation before auth)
    let mut sp_modified_before_auth = false;
    for (i, (_, mnemonic, op_str)) in gadget_insns.iter().enumerate() {
        // Check if SP is modified
        if (mnemonic.starts_with("mov") || mnemonic.starts_with("add") ||
            mnemonic.starts_with("sub") || mnemonic.starts_with("ldr")) &&
           op_str.contains("sp") {

            // Check if there's an auth instruction after this
            for (_, later_mnem, _) in &gadget_insns[i+1..] {
                if later_mnem == "autiasp" || later_mnem == "autibsp" {
                    sp_modified_before_auth = true;
                    break;
                }
            }
        }
    }

    if sp_modified_before_auth {
        notes.push("Stack pivot before authentication".to_string());
        return GadgetType::StackPivot;
    }

    // Check for context manipulation (LR/X30 modification)
    for (_, mnemonic, op_str) in gadget_insns {
        if (mnemonic.starts_with("mov") || mnemonic.starts_with("add") ||
            mnemonic.starts_with("sub") || mnemonic.starts_with("ldr")) &&
           (op_str.contains("x30") || op_str.contains("lr")) {
            modifies_context = true;
            notes.push("Modifies PAC context (LR)".to_string());
        }
    }

    // Check for key confusion
    if (uses_a_key_sign && uses_b_key_auth) || (uses_b_key_sign && uses_a_key_auth) {
        notes.push("Key confusion: sign and auth use different keys".to_string());
        return GadgetType::KeyConfusion;
    }

    // Check for modifier confusion
    if (uses_sp_modifier_sign && uses_zero_modifier_auth) ||
       (uses_zero_modifier_sign && uses_sp_modifier_auth) {
        notes.push("Modifier confusion: sign and auth use different modifiers".to_string());
        return GadgetType::ModifierConfusion;
    }

    // Classify vulnerability
    if modifies_context {
        notes.push("PAC context can be manipulated".to_string());
        GadgetType::ContextManipulation
    } else if uses_zero_modifier {
        notes.push("Vulnerable to replay attacks".to_string());
        GadgetType::ReplayVulnerable
    } else if has_sign || has_auth {
        GadgetType::PacSafe
    } else {
        // No PAC instructions at all
        notes.push("No PAC protection".to_string());
        GadgetType::Unsigned
    }
}
