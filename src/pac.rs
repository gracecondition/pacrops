use crate::types::{PacInstruction, GadgetType};

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
        // Combined operations
        "retaa" => Some(PacInstruction::RetAA),
        "retab" => Some(PacInstruction::RetAB),
        _ => None,
    }
}

pub fn detect_pac_vulnerabilities(
    pac_insns: &[PacInstruction],
    gadget_insns: &[(u64, String, String)],
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

    // Check for unsigned indirect branches
    for (_, mnemonic, _) in gadget_insns {
        if mnemonic == "br" || mnemonic == "blr" {
            notes.push("Unsigned indirect branch - no PAC check".to_string());
            return GadgetType::UnsignedIndirect;
        }
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
