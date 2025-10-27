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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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
        let mut notes = vec![];

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
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

        let result = detect_pac_vulnerabilities(&pac_insns, &gadget_insns, &mut notes);
        assert_eq!(result, GadgetType::StackPivot);
        assert!(notes.iter().any(|n| n.contains("Stack pivot")));
    }
}
