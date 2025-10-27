use capstone::prelude::*;
use clap::Parser;

mod types;
mod pac;
mod gadget;
mod output;
mod binary;

#[cfg(test)]
mod tests;

use types::GadgetType;
use pac::detect_pac_instruction;
use gadget::{find_gadgets, analyze_gadget};
use output::{print_gadget, print_summary, output_json};
use binary::load_binary;

#[derive(Parser, Debug)]
#[command(name = "pacrops")]
#[command(about = "PAC-aware ROP gadget detector for ARM64 binaries", long_about = None)]
struct Args {
    /// Binary file to analyze
    binary: String,

    /// Maximum gadget size (number of instructions, default: 10, use 0 for unlimited)
    #[arg(short = 's', long, default_value_t = 10)]
    max_size: usize,

    /// Show only unsigned gadgets (no PAC protection)
    #[arg(long)]
    unsigned_only: bool,

    /// Show only context manipulation gadgets (modifies LR before auth)
    #[arg(long)]
    context_vuln: bool,

    /// Show only gadgets with zero modifier (replay vulnerable)
    #[arg(long)]
    no_context: bool,

    /// Show only vulnerable gadgets (replay/context manipulation)
    #[arg(long)]
    vulnerable_only: bool,

    /// Show all gadgets including PAC-safe ones
    #[arg(short = 'a', long)]
    show_all: bool,

    /// Show only signed/authenticated gadgets (PAC-protected)
    #[arg(long)]
    signed_only: bool,

    /// Search for gadgets containing specific instruction pattern (regex)
    #[arg(long)]
    search: Option<String>,

    /// Output in JSON format (for tool integration)
    #[arg(long)]
    json: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let binary_info = load_binary(&args.binary)?;

    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;

    // Process all executable sections
    let mut all_instructions = Vec::new();
    let mut pac_count = 0;
    let mut pac_locations = Vec::new();

    for (code, addr, _section_name) in &binary_info.sections {
        if let Ok(instructions) = cs.disasm_all(code, *addr) {
            // Count PAC instructions
            for insn in instructions.iter() {
                if let Some(pac_type) = detect_pac_instruction(insn.mnemonic().unwrap()) {
                    pac_count += 1;
                    pac_locations.push((insn.address(), pac_type, insn.mnemonic().unwrap().to_string()));
                }
            }
            all_instructions.push(instructions);
        }
    }

    // If binary has PAC in header but no PAC instructions found in disassembly
    if binary_info.has_pac_header && pac_count == 0 {
        println!("Binary architecture: arm64e (PAC enabled in header)");
        println!("⚠️  Warning: Binary appears to be encrypted or obfuscated - cannot disassemble");
        println!("             PAC is enabled according to Mach-O header (cpusubtype=0x02)");
        println!("             but no PAC instructions found in disassembly.\n");
    } else {
        println!("Total PAC instructions found in binary: {}", pac_count);
        if pac_count > 0 && pac_count < 20 {
            println!("\nPAC instruction locations:");
            for (addr, pac_type, mnemonic) in &pac_locations {
                println!("  0x{:x}: {} ({:?})", addr, mnemonic, pac_type);
            }
        }
    }

    // Use unlimited if max_size is 0
    let effective_max_size = if args.max_size == 0 { usize::MAX } else { args.max_size };

    // Find gadgets across all sections
    let mut analyzed_gadgets = Vec::new();
    for instructions in &all_instructions {
        let raw_gadgets = find_gadgets(instructions, effective_max_size);
        for gadget in raw_gadgets {
            analyzed_gadgets.push(analyze_gadget(&gadget));
        }
    }

    // Count by type
    let mut unsigned = 0;
    let mut replay_vuln = 0;
    let mut context_vuln = 0;
    let mut key_confusion = 0;
    let mut modifier_confusion = 0;
    let mut unsigned_indirect = 0;
    let mut stack_pivot = 0;
    let mut pac_safe = 0;

    for gadget in &analyzed_gadgets {
        match gadget.gadget_type {
            GadgetType::Unsigned => unsigned += 1,
            GadgetType::ReplayVulnerable => replay_vuln += 1,
            GadgetType::ContextManipulation => context_vuln += 1,
            GadgetType::KeyConfusion => key_confusion += 1,
            GadgetType::ModifierConfusion => modifier_confusion += 1,
            GadgetType::UnsignedIndirect => unsigned_indirect += 1,
            GadgetType::StackPivot => stack_pivot += 1,
            GadgetType::PacSafe => pac_safe += 1,
        }
    }

    // Use header-based PAC detection if disassembly found nothing
    let effective_pac_count = if binary_info.has_pac_header && pac_count == 0 {
        1  // Indicate PAC is present based on header
    } else {
        pac_count
    };

    // Output in JSON format if requested
    if args.json {
        // Filter gadgets for JSON output
        let filtered_gadgets: Vec<_> = analyzed_gadgets.iter()
            .filter(|gadget| {
                if args.show_all {
                    true
                } else if args.unsigned_only {
                    gadget.gadget_type == GadgetType::Unsigned
                } else if args.context_vuln {
                    gadget.gadget_type == GadgetType::ContextManipulation
                } else if args.no_context {
                    gadget.gadget_type == GadgetType::ReplayVulnerable
                } else if args.signed_only {
                    !gadget.pac_instructions.is_empty()
                } else if args.vulnerable_only {
                    matches!(gadget.gadget_type,
                        GadgetType::ReplayVulnerable |
                        GadgetType::ContextManipulation |
                        GadgetType::KeyConfusion |
                        GadgetType::ModifierConfusion |
                        GadgetType::UnsignedIndirect |
                        GadgetType::StackPivot
                    )
                } else {
                    // Default: show only unsigned gadgets (no PAC protection at all)
                    matches!(gadget.gadget_type,
                        GadgetType::Unsigned |
                        GadgetType::UnsignedIndirect
                    )
                }
            })
            .cloned()
            .collect();

        output_json(
            &args.binary,
            effective_pac_count,
            &filtered_gadgets,
            unsigned,
            unsigned_indirect,
            key_confusion,
            modifier_confusion,
            replay_vuln,
            context_vuln,
            stack_pivot,
            pac_safe,
        );
    } else {
        // Print header
        println!();
        println!("\x1b[1m\x1b[96mGadgets:\x1b[0m");
        println!("{}", "─".repeat(90));

        // Filter and print gadgets based on command-line options
        let mut filtered_count = 0;
        for gadget in &analyzed_gadgets {
            let should_print = if args.show_all {
                true
            } else if args.unsigned_only {
                gadget.gadget_type == GadgetType::Unsigned
            } else if args.context_vuln {
                gadget.gadget_type == GadgetType::ContextManipulation
            } else if args.no_context {
                gadget.gadget_type == GadgetType::ReplayVulnerable
            } else if args.signed_only {
                // Show gadgets with PAC protection (has PAC instructions)
                !gadget.pac_instructions.is_empty()
            } else if args.vulnerable_only {
                matches!(gadget.gadget_type,
                    GadgetType::ReplayVulnerable |
                    GadgetType::ContextManipulation |
                    GadgetType::KeyConfusion |
                    GadgetType::ModifierConfusion |
                    GadgetType::UnsignedIndirect |
                    GadgetType::StackPivot
                )
            } else {
                // Default: show only unsigned gadgets (no PAC protection at all)
                matches!(gadget.gadget_type,
                    GadgetType::Unsigned |
                    GadgetType::UnsignedIndirect
                )
            };

            // Apply search filter if provided
            let matches_search = if let Some(ref pattern) = args.search {
                let re = regex::Regex::new(pattern).unwrap_or_else(|_| {
                    eprintln!("Invalid regex pattern: {}", pattern);
                    std::process::exit(1);
                });
                gadget.instructions.iter().any(|insn| re.is_match(insn))
            } else {
                true
            };

            if should_print && matches_search {
                print_gadget(gadget);
                filtered_count += 1;
            }
        }

        // Show filter info if search was used
        if args.search.is_some() {
            println!();
            println!("Showing {} gadgets matching search pattern", filtered_count);
        }

        // Determine active filter for summary display
        let filter_mode = if args.show_all {
            "all"
        } else if args.unsigned_only {
            "unsigned"
        } else if args.context_vuln {
            "context_vuln"
        } else if args.no_context {
            "no_context"
        } else if args.signed_only {
            "signed"
        } else if args.vulnerable_only {
            "vulnerable"
        } else {
            "default"  // default = unsigned
        };

        print_summary(
            &args.binary,
            args.max_size,
            analyzed_gadgets.len(),
            unsigned,
            unsigned_indirect,
            key_confusion,
            modifier_confusion,
            replay_vuln,
            context_vuln,
            stack_pivot,
            pac_safe,
            effective_pac_count,
            filter_mode,
            filtered_count,
        );
    }

    Ok(())
}
