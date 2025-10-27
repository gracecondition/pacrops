use serde::{Serialize, Deserialize};

// PAC instruction types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PacInstruction {
    // Sign with A key
    PacIASP,  // pac instruction, A key, SP modifier
    PacIAZ,   // pac instruction, A key, zero modifier
    PacIA,    // pac instruction, A key, register modifier
    PacDA,    // pac data, A key
    // Sign with B key
    PacIBSP,
    PacIBZ,
    PacIB,
    PacDB,
    // Authenticate with A key
    AutIASP,
    AutIAZ,
    AutIA,
    AutDA,
    // Authenticate with B key
    AutIBSP,
    AutIBZ,
    AutIB,
    AutDB,
    // Combined operations
    RetAA,    // authenticate and return with A key
    RetAB,    // authenticate and return with B key
}

// Gadget vulnerability types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GadgetType {
    Unsigned,           // No PAC protection at all
    ReplayVulnerable,   // Has PAC but vulnerable to replay attacks
    ContextManipulation, // PAC present but context can be manipulated
    KeyConfusion,       // Sign with one key, auth with another
    ModifierConfusion,  // Sign with one modifier, auth with different modifier
    UnsignedIndirect,   // br/blr without PAC on target
    StackPivot,         // SP manipulation before auth
    PacSafe,            // Properly protected by PAC
}

// ROP gadget structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gadget {
    pub address: u64,
    pub instructions: Vec<String>,
    pub gadget_type: GadgetType,
    #[allow(dead_code)]
    pub pac_instructions: Vec<PacInstruction>,
    #[allow(dead_code)]
    pub vulnerability_notes: Vec<String>,
}

impl Gadget {
    pub fn new(
        address: u64,
        instructions: Vec<String>,
        gadget_type: GadgetType,
        pac_instructions: Vec<PacInstruction>,
        vulnerability_notes: Vec<String>,
    ) -> Self {
        Self {
            address,
            instructions,
            gadget_type,
            pac_instructions,
            vulnerability_notes,
        }
    }
}
