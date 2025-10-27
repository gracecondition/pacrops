use crate::types::{Gadget, GadgetType};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct JsonOutput {
    pub binary: String,
    pub pac_count: usize,
    pub total_gadgets: usize,
    pub exploitable_gadgets: usize,
    pub statistics: Statistics,
    pub gadgets: Vec<Gadget>,
}

#[derive(Serialize, Deserialize)]
pub struct Statistics {
    pub unsigned: usize,
    pub unsigned_indirect: usize,
    pub key_confusion: usize,
    pub modifier_confusion: usize,
    pub replay_vulnerable: usize,
    pub context_manipulation: usize,
    pub stack_pivot: usize,
    pub pac_safe: usize,
}

pub fn format_gadget_type(gadget_type: &GadgetType) -> (&str, &str) {
    match gadget_type {
        GadgetType::Unsigned => ("UNSIGNED", "\x1b[91m"),  // Red
        GadgetType::ReplayVulnerable => ("REPLAY-VULN", "\x1b[93m"),  // Yellow
        GadgetType::ContextManipulation => ("CONTEXT-VULN", "\x1b[93m"),  // Yellow
        GadgetType::KeyConfusion => ("KEY-CONFUSION", "\x1b[91m"),  // Red
        GadgetType::ModifierConfusion => ("MODIFIER-VULN", "\x1b[93m"),  // Yellow
        GadgetType::UnsignedIndirect => ("UNSIGNED-BR", "\x1b[91m"),  // Red
        GadgetType::StackPivot => ("STACK-PIVOT", "\x1b[91m"),  // Red
        GadgetType::PacSafe => ("PAC-SAFE", "\x1b[92m"),  // Green
    }
}

pub fn print_gadget(gadget: &Gadget) {
    let (type_str, color) = format_gadget_type(&gadget.gadget_type);
    let reset = "\x1b[0m";
    //let gray = "\x1b[90m";
    let bold = "\x1b[1m";

    // Join instructions with cleaner separator
    let insn_chain = gadget.instructions.join(" ; ");

    // Clean up instruction formatting - remove extra spaces
    let insn_chain = insn_chain.replace("  ", " ");

    // Format address more compactly
    print!("{bold}{:#018x}{reset}  ", gadget.address, bold=bold, reset=reset);

    // Print instructions with appropriate padding
    let max_width = 70;
    if insn_chain.len() > max_width {
        let truncated = &insn_chain[..max_width-3];
        print!("{:<width$}...", truncated, width=max_width-3);
    } else {
        print!("{:<width$}", insn_chain, width=max_width);
    }

    // Add type tag at end
    print!("  {color}{type_str}{reset}", color=color, type_str=type_str, reset=reset);

    println!();
}

pub fn print_summary(
    binary_name: &str,
    max_size: usize,
    total: usize,
    unsigned: usize,
    unsigned_indirect: usize,
    key_confusion: usize,
    modifier_confusion: usize,
    replay_vuln: usize,
    context_vuln: usize,
    stack_pivot: usize,
    pac_safe: usize,
    pac_count: usize,
    filter_mode: &str,
    _shown_count: usize,  // Reserved for future use
) {
    let cyan = "\x1b[96m";
    let red = "\x1b[91m";
    let yellow = "\x1b[93m";
    let green = "\x1b[92m";
    let blue = "\x1b[94m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";
    let dim = "\x1b[2m";

    println!();
    println!("{cyan}{bold}╔════════════════════════════════════════════════════════════════════════╗{reset}", cyan=cyan, bold=bold, reset=reset);
    println!("{cyan}{bold}║                  PAC-Aware ROP Gadget Analysis                         ║{reset}", cyan=cyan, bold=bold, reset=reset);
    println!("{cyan}{bold}╚════════════════════════════════════════════════════════════════════════╝{reset}", cyan=cyan, bold=bold, reset=reset);

    println!();
    println!("  {blue}Binary:{reset}              {bold}{}{reset}", binary_name, blue=blue, reset=reset, bold=bold);
    println!("  {blue}Max gadget size:{reset}     {}", max_size, blue=blue, reset=reset);
    println!("  {blue}PAC instructions:{reset}    {}", pac_count, blue=blue, reset=reset);

    println!();

    // Calculate exploitable count
    let exploitable = unsigned + unsigned_indirect + key_confusion + modifier_confusion + replay_vuln + context_vuln + stack_pivot;
    let exploit_percent = if total > 0 { (exploitable * 100) / total } else { 0 };

    println!("  {bold}Total gadgets:{reset}       {}", total, bold=bold, reset=reset);
    println!("  {bold}Exploitable:{reset}         {} / {} {dim}({}%){reset}",
        exploitable,
        total,
        exploit_percent,
        bold=bold, reset=reset, dim=dim);

    // Check if binary has no PAC
    if pac_count == 0 {
        println!();
        println!("{green}{bold}╔═══════════════════════════════════════════════════════════════════╗{reset}", green=green, bold=bold, reset=reset);
        println!("{green}{bold}║  GOOD NEWS! IT SEEMS LIKE THE BINARY ISN'T PAC AUTHENTICATED!    ║{reset}", green=green, bold=bold, reset=reset);
        println!("{green}{bold}╚═══════════════════════════════════════════════════════════════════╝{reset}", green=green, bold=bold, reset=reset);
    }

    println!();

    // Show breakdown based on active filter
    match filter_mode {
        "default" | "unsigned" => {
            println!("  {bold}Showing:{reset} Unsigned gadgets only (default)", bold=bold, reset=reset);
            println!();
            println!("  {bold}Displayed Counts:{reset}", bold=bold, reset=reset);
            println!("    {dim}├─{reset} {red}Unsigned (no PAC):{reset}           {}", unsigned, dim=dim, reset=reset, red=red);
            println!("    {dim}└─{reset} {red}Unsigned indirect (br/blr):{reset}  {}", unsigned_indirect, dim=dim, reset=reset, red=red);
            println!();
            println!("  {bold}Full Vulnerability Breakdown:{reset} {dim}(use --show-all to see all){reset}", bold=bold, reset=reset, dim=dim);
            println!("    {dim}├─{reset} {red}Key confusion:{reset}                {}", key_confusion, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {yellow}Modifier confusion:{reset}           {}", modifier_confusion, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Replay vulnerable:{reset}            {}", replay_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {red}Stack pivot:{reset}                  {}", stack_pivot, dim=dim, reset=reset, red=red);
            println!("    {dim}└─{reset} {green}PAC-safe:{reset}                     {}", pac_safe, dim=dim, reset=reset, green=green);
        },
        "context_vuln" => {
            println!("  {bold}Showing:{reset} Context manipulation gadgets only", bold=bold, reset=reset);
            println!();
            println!("  {bold}Displayed:{reset}", bold=bold, reset=reset);
            println!("    {dim}└─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
        },
        "no_context" => {
            println!("  {bold}Showing:{reset} Replay vulnerable gadgets only (zero modifier)", bold=bold, reset=reset);
            println!();
            println!("  {bold}Displayed:{reset}", bold=bold, reset=reset);
            println!("    {dim}└─{reset} {yellow}Replay vulnerable:{reset}            {}", replay_vuln, dim=dim, reset=reset, yellow=yellow);
        },
        "signed" => {
            println!("  {bold}Showing:{reset} Signed/authenticated gadgets only (PAC-protected)", bold=bold, reset=reset);
            println!();
            println!("  {bold}Displayed Counts:{reset}", bold=bold, reset=reset);
            println!("    {dim}├─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}└─{reset} {green}PAC-safe:{reset}                     {}", pac_safe, dim=dim, reset=reset, green=green);
        },
        "vulnerable" => {
            println!("  {bold}Showing:{reset} All vulnerable gadgets", bold=bold, reset=reset);
            println!();
            println!("  {bold}Displayed Counts:{reset}", bold=bold, reset=reset);
            println!("    {dim}├─{reset} {red}Unsigned (no PAC):{reset}           {}", unsigned, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Unsigned indirect (br/blr):{reset}  {}", unsigned_indirect, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Key confusion:{reset}                {}", key_confusion, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {yellow}Modifier confusion:{reset}           {}", modifier_confusion, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Replay vulnerable:{reset}            {}", replay_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}└─{reset} {red}Stack pivot:{reset}                  {}", stack_pivot, dim=dim, reset=reset, red=red);
        },
        "all" => {
            println!("  {bold}Showing:{reset} All gadgets (including PAC-safe)", bold=bold, reset=reset);
            println!();
            println!("  {bold}Full Vulnerability Breakdown:{reset}", bold=bold, reset=reset);
            println!("    {dim}├─{reset} {red}Unsigned (no PAC):{reset}           {}", unsigned, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Unsigned indirect (br/blr):{reset}  {}", unsigned_indirect, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Key confusion:{reset}                {}", key_confusion, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {yellow}Modifier confusion:{reset}           {}", modifier_confusion, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Replay vulnerable:{reset}            {}", replay_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {red}Stack pivot:{reset}                  {}", stack_pivot, dim=dim, reset=reset, red=red);
            println!("    {dim}└─{reset} {green}PAC-safe:{reset}                     {}", pac_safe, dim=dim, reset=reset, green=green);
        },
        _ => {
            // Fallback - show everything
            println!("  {bold}Vulnerability Breakdown:{reset}", bold=bold, reset=reset);
            println!("    {dim}├─{reset} {red}Unsigned (no PAC):{reset}           {}", unsigned, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Unsigned indirect (br/blr):{reset}  {}", unsigned_indirect, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {red}Key confusion:{reset}                {}", key_confusion, dim=dim, reset=reset, red=red);
            println!("    {dim}├─{reset} {yellow}Modifier confusion:{reset}           {}", modifier_confusion, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Replay vulnerable:{reset}            {}", replay_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {yellow}Context manipulation:{reset}         {}", context_vuln, dim=dim, reset=reset, yellow=yellow);
            println!("    {dim}├─{reset} {red}Stack pivot:{reset}                  {}", stack_pivot, dim=dim, reset=reset, red=red);
            println!("    {dim}└─{reset} {green}PAC-safe:{reset}                     {}", pac_safe, dim=dim, reset=reset, green=green);
        }
    }

    println!();
    if exploitable > 0 {
        println!("{red}{bold}⚠️  Exploitable gadgets: {}{reset}", exploitable, red=red, bold=bold, reset=reset);
    } else {
        println!("{green}{bold}✓  No exploitable gadgets found{reset}", green=green, bold=bold, reset=reset);
    }
    println!();
}

pub fn output_json(
    binary_name: &str,
    pac_count: usize,
    gadgets: &[Gadget],
    unsigned: usize,
    unsigned_indirect: usize,
    key_confusion: usize,
    modifier_confusion: usize,
    replay_vuln: usize,
    context_vuln: usize,
    stack_pivot: usize,
    pac_safe: usize,
) {
    let exploitable = unsigned + unsigned_indirect + key_confusion + modifier_confusion + replay_vuln + context_vuln + stack_pivot;

    let output = JsonOutput {
        binary: binary_name.to_string(),
        pac_count,
        total_gadgets: gadgets.len(),
        exploitable_gadgets: exploitable,
        statistics: Statistics {
            unsigned,
            unsigned_indirect,
            key_confusion,
            modifier_confusion,
            replay_vulnerable: replay_vuln,
            context_manipulation: context_vuln,
            stack_pivot,
            pac_safe,
        },
        gadgets: gadgets.to_vec(),
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
