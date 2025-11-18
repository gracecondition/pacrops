use crate::types::{PacInstruction, GadgetType};

/// Parse offset from operand string (handles #0x1000, #4096, etc.)
fn parse_offset(offset_str: &str) -> Option<i64> {
    let offset_str = offset_str.trim().trim_start_matches('#');
    if offset_str.starts_with("0x") {
        i64::from_str_radix(offset_str.trim_start_matches("0x"), 16).ok()
    } else {
        offset_str.parse::<i64>().ok()
    }
}

/// Extract register name from operand (e.g., "x0" from "x0, [x1]")
fn extract_register(op_str: &str) -> Option<String> {
    op_str.split(',').next().map(|s| s.trim().to_string())
}

/// Analyze gadget for loads from data sections
/// Handles both PC-relative loads and adrp + add + ldr sequences
fn find_data_section_loads(
    gadget_insns: &[(u64, String, String)],
    target_reg: &str,
    data_sections: &[(u64, u64, String)],
) -> Option<(u64, String)> {
    use std::collections::HashMap;

    // Track register values computed by adrp and add instructions
    let mut reg_values: HashMap<String, u64> = HashMap::new();

    for (addr, mnemonic, op_str) in gadget_insns {
        // Track adrp instructions: adrp x0, #0x100000000
        if mnemonic == "adrp" {
            if let Some(dest_reg) = extract_register(op_str) {
                // Capstone gives us the absolute page address directly (already computed)
                let parts: Vec<&str> = op_str.split(',').collect();
                if parts.len() >= 2 {
                    if let Some(page_addr) = parse_offset(parts[1].trim()) {
                        let page_addr = page_addr as u64;
                        reg_values.insert(dest_reg, page_addr);
                    }
                }
            }
        }

        // Track add instructions: add x0, x0, #offset
        if mnemonic == "add" {
            let parts: Vec<&str> = op_str.split(',').collect();
            if parts.len() >= 3 {
                let dest_reg = parts[0].trim();
                let src_reg = parts[1].trim();

                // Only track if adding to itself or we already track the source
                if let Some(&base_val) = reg_values.get(src_reg) {
                    if let Some(offset) = parse_offset(parts[2].trim()) {
                        let final_addr = (base_val as i64 + offset) as u64;
                        reg_values.insert(dest_reg.to_string(), final_addr);
                    }
                }
            }
        }

        // Check for ldr into target register
        if mnemonic.starts_with("ldr") {
            let dest_reg_opt = extract_register(op_str);
            if let Some(dest_reg) = dest_reg_opt {
                // Check any ldr, not just into target_reg, because we want to find
                // if the target_reg gets loaded from an address computed via adrp

                // Case 1: PC-relative load: ldr x0, [pc, #offset]
                if op_str.contains("pc") {
                    let parts: Vec<&str> = op_str.split(',').collect();
                    if parts.len() >= 3 {
                        let offset_str = parts[2].trim().trim_end_matches(']');
                        if let Some(offset) = parse_offset(offset_str) {
                            let load_addr = (*addr as i64 + offset) as u64;

                            // Check if in data section and loading into target
                            if dest_reg == target_reg {
                                for (start, end, section_name) in data_sections {
                                    if load_addr >= *start && load_addr < *end {
                                        return Some((load_addr, section_name.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
                // Case 2: Load from computed address: ldr x0, [x1, #offset] or ldr x0, [x1]
                else if op_str.contains('[') {
                    // Parse: "x0, [x1, #0x10]" or "x0, [x1]"
                    let parts: Vec<&str> = op_str.split('[').collect();
                    if parts.len() >= 2 {
                        let addr_parts: Vec<&str> = parts[1].trim_end_matches(']').split(',').collect();
                        let base_reg = addr_parts[0].trim();

                        // Check if we have a computed value for the base register
                        if let Some(&base_addr) = reg_values.get(base_reg) {
                            let offset = if addr_parts.len() >= 2 {
                                parse_offset(addr_parts[1].trim()).unwrap_or(0)
                            } else {
                                0
                            };

                            let load_addr = (base_addr as i64 + offset) as u64;

                            // Check if loading into target register from data section
                            if dest_reg == target_reg {
                                for (start, end, section_name) in data_sections {
                                    if load_addr >= *start && load_addr < *end {
                                        return Some((load_addr, section_name.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
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

    // Check for indirect branches (both unsigned and authenticated) AND pre-authenticated loads
    let mut has_indirect_branch = false;
    let mut branch_register = None;
    let mut is_authenticated = false;

    for (_, mnemonic, op_str) in gadget_insns {
        if mnemonic == "br" || mnemonic == "blr" {
            has_indirect_branch = true;
            is_authenticated = false;
            // Extract the register being branched to (e.g., "x0" from "br x0")
            branch_register = op_str.split(',').next().map(|s| s.trim().to_string());
            break;
        } else if mnemonic == "braa" || mnemonic == "brab" || mnemonic == "blraa" || mnemonic == "blrab" ||
                  mnemonic == "braaz" || mnemonic == "brabz" || mnemonic == "blraaz" || mnemonic == "blrabz" {
            has_indirect_branch = true;
            is_authenticated = true;
            // Extract the register being branched to (e.g., "x0" from "braa x0, x1")
            branch_register = op_str.split(',').next().map(|s| s.trim().to_string());
            break;
        }
    }

    if has_indirect_branch {
        // Check if the branch register is loaded from a data section
        if let Some(ref target_reg) = branch_register {
            if let Some((load_addr, section_name)) = find_data_section_loads(gadget_insns, target_reg, data_sections) {
                notes.push(format!("Loads from {} (likely PAC-signed pointer)", section_name));
                notes.push(format!("Address: 0x{:x}", load_addr));
                if is_authenticated {
                    notes.push("Uses authenticated branch but pointer is pre-signed".to_string());
                }
                return GadgetType::PreAuthLoad;
            }
        }

        // If no pre-auth load detected
        if !is_authenticated {
            notes.push("Unsigned indirect branch - no PAC check".to_string());
            return GadgetType::UnsignedIndirect;
        }
        // If authenticated branch without pre-auth load, fall through to other checks
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
