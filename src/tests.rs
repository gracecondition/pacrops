use crate::types::{GadgetType, PacInstruction};
use crate::pac::{detect_pac_instruction, detect_pac_vulnerabilities};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pac_sign_instructions() {
        assert_eq!(detect_pac_instruction("paciasp"), Some(PacInstruction::PacIASP));
        assert_eq!(detect_pac_instruction("paciaz"), Some(PacInstruction::PacIAZ));
        assert_eq!(detect_pac_instruction("pacia"), Some(PacInstruction::PacIA));
        assert_eq!(detect_pac_instruction("pacibsp"), Some(PacInstruction::PacIBSP));
    }

    #[test]
    fn test_detect_pac_auth_instructions() {
        assert_eq!(detect_pac_instruction("autiasp"), Some(PacInstruction::AutIASP));
        assert_eq!(detect_pac_instruction("retaa"), Some(PacInstruction::RetAA));
        assert_eq!(detect_pac_instruction("retab"), Some(PacInstruction::RetAB));
    }

    #[test]
    fn test_detect_non_pac_instructions() {
        assert_eq!(detect_pac_instruction("ret"), None);
        assert_eq!(detect_pac_instruction("br"), None);
        assert_eq!(detect_pac_instruction("blr"), None);
        assert_eq!(detect_pac_instruction("mov"), None);
    }

    #[test]
    fn test_unsigned_gadget_no_pac() {
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "mov".to_string(), "x0, x1".to_string()),
            (0x1004, "ret".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::Unsigned);
        assert!(notes.iter().any(|n| n.contains("No PAC protection")));
    }

    #[test]
    fn test_unsigned_indirect_branch() {
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "mov".to_string(), "x16, x0".to_string()),
            (0x1004, "br".to_string(), "x16".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::UnsignedIndirect);
        assert!(notes.iter().any(|n| n.contains("Unsigned indirect branch")));
    }

    #[test]
    fn test_pac_safe_gadget() {
        let pac_insns = vec![PacInstruction::PacIASP, PacInstruction::RetAA];
        let gadget_insns = vec![
            (0x1000, "paciasp".to_string(), "".to_string()),
            (0x1004, "mov".to_string(), "x0, x1".to_string()),
            (0x1008, "retaa".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::PacSafe);
    }

    #[test]
    fn test_key_confusion() {
        // Sign with A key, auth with B key
        let pac_insns = vec![PacInstruction::PacIASP, PacInstruction::RetAB];
        let gadget_insns = vec![
            (0x1000, "paciasp".to_string(), "".to_string()),
            (0x1004, "retab".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::KeyConfusion);
        assert!(notes.iter().any(|n| n.contains("Key confusion")));
    }

    #[test]
    fn test_modifier_confusion() {
        // Sign with SP modifier, auth with zero modifier
        let pac_insns = vec![PacInstruction::PacIASP, PacInstruction::AutIAZ];
        let gadget_insns = vec![
            (0x1000, "paciasp".to_string(), "".to_string()),
            (0x1004, "autiaz".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::ModifierConfusion);
        assert!(notes.iter().any(|n| n.contains("Modifier confusion")));
    }

    #[test]
    fn test_replay_vulnerable() {
        // Uses zero modifier
        let pac_insns = vec![PacInstruction::PacIAZ];
        let gadget_insns = vec![
            (0x1000, "paciaz".to_string(), "".to_string()),
            (0x1004, "ret".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::ReplayVulnerable);
        assert!(notes.iter().any(|n| n.contains("Vulnerable to replay")));
    }

    #[test]
    fn test_context_manipulation() {
        // Modifies LR before auth
        let pac_insns = vec![PacInstruction::PacIASP];
        let gadget_insns = vec![
            (0x1000, "paciasp".to_string(), "".to_string()),
            (0x1004, "ldr".to_string(), "x30, [sp]".to_string()),
            (0x1008, "ret".to_string(), "".to_string()),
        ];
        let data_sections = vec![];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::ContextManipulation);
        assert!(notes.iter().any(|n| n.contains("Modifies PAC context")));
    }

    #[test]
    fn test_stack_pivot() {
        // Modifies SP before auth
        let pac_insns = vec![PacInstruction::AutIASP];
        let gadget_insns = vec![
            (0x1000, "mov".to_string(), "sp, x0".to_string()),
            (0x1004, "autiasp".to_string(), "".to_string()),
        ];
        let mut notes = vec![];
        let data_sections = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::StackPivot);
        assert!(notes.iter().any(|n| n.contains("Stack pivot")));
    }

    #[test]
    fn test_preauth_load_unsigned_branch() {
        // Load from __auth_got then unsigned br - CRITICAL vulnerability
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "adrp".to_string(), "x17, #0xdc000".to_string()),
            (0x1004, "add".to_string(), "x17, x17, #0x9c0".to_string()),
            (0x1008, "ldr".to_string(), "x16, [x17]".to_string()),
            (0x100c, "br".to_string(), "x16".to_string()),
        ];
        let data_sections = vec![
            (0xdc000, 0xdc9d0, "__auth_got".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::PreAuthLoad);
        assert!(notes.iter().any(|n| n.contains("__auth_got")));
        assert!(notes.iter().any(|n| n.contains("0xdc9c0")));
    }

    #[test]
    fn test_preauth_load_authenticated_branch() {
        // Load from __auth_got then authenticated braa - still vulnerable!
        let pac_insns = vec![PacInstruction::AutIA];
        let gadget_insns = vec![
            (0x1000, "adrp".to_string(), "x17, #0xdc000".to_string()),
            (0x1004, "add".to_string(), "x17, x17, #0x28".to_string()),
            (0x1008, "ldr".to_string(), "x16, [x17]".to_string()),
            (0x100c, "braa".to_string(), "x16, x17".to_string()),
        ];
        let data_sections = vec![
            (0xdc000, 0xdc9d0, "__auth_got".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::PreAuthLoad);
        assert!(notes.iter().any(|n| n.contains("__auth_got")));
        assert!(notes.iter().any(|n| n.contains("authenticated branch but pointer is pre-signed")));
    }

    #[test]
    fn test_preauth_load_pc_relative() {
        // PC-relative load from data section
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "ldr".to_string(), "x16, [pc, #0x100]".to_string()),
            (0x1004, "br".to_string(), "x16".to_string()),
        ];
        let data_sections = vec![
            (0x1100, 0x1200, "__const".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::PreAuthLoad);
        assert!(notes.iter().any(|n| n.contains("__const")));
    }

    #[test]
    fn test_preauth_load_auth_ptr_section() {
        // Load from __auth_ptr section
        let pac_insns = vec![PacInstruction::AutIA];
        let gadget_insns = vec![
            (0x1000, "adrp".to_string(), "x17, #0xdd000".to_string()),
            (0x1004, "add".to_string(), "x17, x17, #0x770".to_string()),
            (0x1008, "ldr".to_string(), "x16, [x17]".to_string()),
            (0x100c, "blraa".to_string(), "x16, x17".to_string()),
        ];
        let data_sections = vec![
            (0xdd770, 0xdd788, "__auth_ptr".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::PreAuthLoad);
        assert!(notes.iter().any(|n| n.contains("__auth_ptr")));
    }

    #[test]
    fn test_no_preauth_load_wrong_section() {
        // Load from address NOT in any data section - should be unsigned indirect
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "adrp".to_string(), "x17, #0x50000".to_string()),
            (0x1004, "add".to_string(), "x17, x17, #0x100".to_string()),
            (0x1008, "ldr".to_string(), "x16, [x17]".to_string()),
            (0x100c, "br".to_string(), "x16".to_string()),
        ];
        let data_sections = vec![
            (0xdc000, 0xdc9d0, "__auth_got".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::UnsignedIndirect);
    }

    #[test]
    fn test_no_preauth_load_wrong_register() {
        // Loads into x16 but branches to x17 - should be unsigned indirect
        let pac_insns = vec![];
        let gadget_insns = vec![
            (0x1000, "adrp".to_string(), "x17, #0xdc000".to_string()),
            (0x1004, "ldr".to_string(), "x16, [x17]".to_string()),
            (0x1008, "br".to_string(), "x17".to_string()),  // Different register!
        ];
        let data_sections = vec![
            (0xdc000, 0xdc9d0, "__auth_got".to_string()),
        ];
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &data_sections, &mut notes);
        assert_eq!(result, GadgetType::UnsignedIndirect);
    }

    #[test]
    fn test_authenticated_branch_instructions() {
        // Test all authenticated branch variants are recognized
        assert_eq!(detect_pac_instruction("braa"), Some(PacInstruction::AutIA));
        assert_eq!(detect_pac_instruction("brab"), Some(PacInstruction::AutIB));
        assert_eq!(detect_pac_instruction("blraa"), Some(PacInstruction::AutIA));
        assert_eq!(detect_pac_instruction("blrab"), Some(PacInstruction::AutIB));
        assert_eq!(detect_pac_instruction("braaz"), Some(PacInstruction::AutIAZ));
        assert_eq!(detect_pac_instruction("brabz"), Some(PacInstruction::AutIBZ));
        assert_eq!(detect_pac_instruction("blraaz"), Some(PacInstruction::AutIAZ));
        assert_eq!(detect_pac_instruction("blrabz"), Some(PacInstruction::AutIBZ));
    }
}
