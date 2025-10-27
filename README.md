<div align="center">
<img src="assets/logo.png" alt="machsec logo" width="180">
</div>

# Pacropper

**PAC-aware ROP Gadget Finder for ARM64 Binaries**

Pacropper is a specialized tool for finding exploitable ROP gadgets in ARM64 binaries that use Pointer Authentication Codes (PAC). It identifies gadgets that are either unprotected by PAC or vulnerable to known PAC bypass techniques.

## Features

- ✅ **PAC-Aware Analysis**: Detects and classifies PAC instructions (PACIASP, RETAA, etc.)
- ✅ **Vulnerability Detection**: Identifies multiple PAC vulnerability classes
- ✅ **JSON Output**: Machine-readable output for tool integration
- ✅ **Python Bindings**: Easy integration with pwntools and exploit scripts
- ✅ **Fast & Accurate**: Built with Rust and Capstone for reliable disassembly

## Vulnerability Classes Detected

| Class | Description | Exploitability | Severity |
|-------|-------------|----------------|----------|
| **Unsigned** | No PAC protection at all | Direct | 🔴 Critical |
| **Unsigned Indirect** | `br`/`blr` without PAC | Direct | 🔴 Critical |
| **Key Confusion** | Sign with key A, auth with key B | Direct | 🔴 Critical |
| **Modifier Confusion** | Different modifiers for sign/auth | Requires additional primitives | 🟡 High |
| **Replay Vulnerable** | Uses zero modifier like `paciaz` (predictable PAC) | Requires additional primitives | 🟡 High |
| **Context Manipulation** | Loads LR/x30 from memory before `retaa`/`retab` | Requires memory leak or oracle | 🟡 Medium |
| **Stack Pivot** | SP modified before authentication | Direct | 🔴 Critical |
| **PAC-Safe** | Properly protected by PAC | Very difficult | 🟢 Safe |

### Understanding Exploitability

- **Direct**: Can be exploited with just a memory corruption primitive (buffer overflow, use-after-free, etc.)
- **Requires additional primitives**: Needs memory leaks, PAC oracle, or other info leak vulnerabilities
- **Very difficult**: Would require breaking PAC itself or finding implementation flaws

**Note**: Context Manipulation gadgets are classified conservatively. While they load the return address from the stack before authentication, an attacker would still need:
1. A valid PAC for the target address (via memory leak), or
2. A PAC oracle to brute force valid pointers, or
3. Another vulnerability to bypass PAC entirely

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- Python 3.7+ (for Python bindings)
- pwntools (optional, for exploit integration)

### Building from Source

```bash
git clone https://github.com/yourusername/pacrops
cd pacrops
cargo build --release
```

The binary will be available at `./target/release/pacrops`.

## Usage

### Command Line

```bash
# Basic usage - show unsigned gadgets (default behavior)
# By default, only shows gadgets with no PAC protection (UNSIGNED + UNSIGNED-BR)
./target/release/pacrops ./binary

# Explicitly show only unsigned gadgets (same as default)
./target/release/pacrops ./binary --unsigned-only

# Show only context manipulation gadgets (modifies LR before auth)
./target/release/pacrops ./binary --context-vuln

# Show only replay vulnerable gadgets (zero modifier)
./target/release/pacrops ./binary --no-context

# Show only signed/authenticated gadgets (PAC-protected)
./target/release/pacrops ./binary --signed-only

# Show all vulnerable gadgets
./target/release/pacrops ./binary --vulnerable-only

# Show all gadgets including PAC-safe ones
./target/release/pacrops ./binary --show-all

# Search for specific instruction patterns (regex)
./target/release/pacrops ./binary --search "ldr x0"
./target/release/pacrops ./binary --search "bl.*ret"

# Combine search with filters
./target/release/pacrops ./binary --search "ldr.*ret" --unsigned-only

# Limit gadget size
./target/release/pacrops ./binary --max-size 5

# Output in JSON format (for tool integration)
./target/release/pacrops ./binary --json
```

### Example Output

```
Total PAC instructions found in binary: 4

PAC instruction locations:
  0x100000568: paciasp (PacIASP)
  0x100000594: retaa (RetAA)

0x10000054c: ldr x0, [sp], #8; ret                                        [UNSIGNED]
0x100000558: hint #0x22; bl #0x100000668; ret                             [UNSIGNED]

╔═══════════════════════════════════════════════════════════════════╗
║           PAC-Aware ROP Gadget Analysis Summary                   ║
╚═══════════════════════════════════════════════════════════════════╝

Binary:           ./demo
Max gadget size:  10
PAC instructions: 4

Total ROP gadgets: 70
Exploitable:       50 / 70 (71%)

Vulnerability Breakdown:
  ├─ Unsigned (no PAC):        22
  ├─ Unsigned indirect (br/blr): 28
  ├─ Key confusion:             0
  ├─ Modifier confusion:        0
  ├─ Replay vulnerable:         0
  ├─ Context manipulation:      0
  ├─ Stack pivot:               0
  └─ PAC-safe:                  20

⚠️  Exploitable gadgets: 50
```

## Python Bindings

Pacropper includes Python bindings for easy integration with exploit development workflows.

### Quick Start

```python
from pacrops import Pacropper, GadgetType

# Analyze a binary
p = Pacropper('./target/binary')

# Get statistics
print(f"Found {p.pac_count} PAC instructions")
print(f"Found {len(p.exploitable_gadgets())} exploitable gadgets")

# Find specific gadgets
unsigned = p.find(gadget_type=GadgetType.UNSIGNED)
pop_gadgets = p.search(r'ldr x0.*ret')

# Iterate through gadgets
for gadget in unsigned[:5]:
    print(f"{hex(gadget.address)}: {' ; '.join(gadget.instructions)}")
```

### Integration with Pwntools

```python
#!/usr/bin/env python3
from pwn import *
from pacrops import Pacropper

context.arch = 'aarch64'

# Find gadgets
p = Pacropper('./binary')
pop_x0 = p.pop_register('x0')[0]
system = p.call_gadgets()[0]

log.success(f"pop x0 @ {hex(pop_x0.address)}")
log.success(f"system @ {hex(system.address)}")

# Build ROP chain
rop = b'A' * 128
rop += p64(pop_x0.address)
rop += p64(binsh_addr)
rop += p64(system.address)

# Send exploit
io = process('./binary')
io.sendline(rop)
io.interactive()
```

### Python API Reference

#### `Pacropper(binary_path, pacrops_path=None, max_gadget_size=10)`

Initialize a Pacropper instance for analyzing a binary.

**Properties:**
- `gadgets` - List of all gadgets
- `statistics` - Vulnerability statistics dict
- `pac_count` - Number of PAC instructions

**Methods:**
- `find(gadget_type=None, min_length=1, max_length=100)` - Filter gadgets by type/length
- `search(pattern, regex=True)` - Search for instruction patterns
- `pop_register(register='x0')` - Find gadgets that pop a register
- `syscall_gadgets()` - Find gadgets with `svc` instructions
- `call_gadgets()` - Find gadgets with `bl`/`blr` instructions
- `ret_gadgets()` - Find gadgets ending with `ret`
- `unsigned_gadgets()` - Find all unsigned gadgets
- `exploitable_gadgets()` - Find all exploitable gadgets
- `dump(output_file=None)` - Dump all gadgets to stdout or file

## Demo

The repository includes a demonstration vulnerable binary and exploit:

```bash
# Build the demo
make

# Analyze with pacrops
./target/release/pacrops ./demo

# Run the exploit (demonstrates gadget usage)
python3 exploit_clean.py
```

## How It Works

Pacropper analyzes ARM64 binaries by:

1. **Disassembly**: Uses Capstone to disassemble executable sections
2. **PAC Detection**: Identifies PAC instructions (PACIA*, RETAA, etc.)
3. **Gadget Discovery**: Finds all gadgets ending in control-flow instructions
4. **Vulnerability Analysis**: Classifies each gadget based on:
   - Presence/absence of PAC instructions
   - PAC key usage (A vs B)
   - PAC modifier usage (SP vs zero vs register)
   - Context manipulation opportunities
   - Stack pivot potential

### Detection Logic

**Gadget Discovery Process:**
1. Disassemble all executable sections using Capstone
2. Find all control-flow instructions: `ret`, `retaa`, `retab`, `br`, `blr`
3. Look backwards up to max_gadget_size (default: 10) instructions
4. Collect all instruction sequences ending at each control-flow instruction
5. Analyze each gadget for PAC instructions and vulnerability patterns

**Vulnerability Classification (in priority order):**

| Type | Detection Logic |
|------|-----------------|
| **UNSIGNED-BR** | Contains `br` or `blr` instruction without PAC authentication (checked first) |
| **STACK-PIVOT** | Modifies `sp` register (mov/add/sub/ldr sp) before `autiasp`/`autibsp` instruction |
| **KEY-CONFUSION** | Signs with A key (`pacia*`) but authenticates with B key (`retab`/`autib*`), or vice versa |
| **MODIFIER-CONFUSION** | Signs with SP modifier (`paciasp`) but authenticates with zero (`autiaz`), or vice versa |
| **CONTEXT-VULN** | Contains `ldr`/`mov`/`add`/`sub` that modifies `x30` or `lr` register (loads return address from memory) |
| **REPLAY-VULN** | Uses zero modifier PAC instructions: `paciaz`, `pacibz`, `autiaz`, `autibz` (predictable PAC values) |
| **PAC-SAFE** | Contains PAC sign or auth instructions with proper key/modifier matching |
| **UNSIGNED** | No PAC instructions found at all - plain `ret` with no protection |

**Note:** Detection proceeds in order - first match wins. For example, a gadget with `br` is immediately classified as UNSIGNED-BR before checking other patterns.

## Research & Background

Pointer Authentication Codes (PAC) is a security feature introduced in ARMv8.3-A to mitigate return-oriented programming (ROP) and jump-oriented programming (JOP) attacks. However, several vulnerability classes exist:

- **Improper PAC Usage**: Functions without PAC protection
- **PAC Bypass Techniques**: Key/modifier confusion attacks
- **Implementation Flaws**: Replay attacks, context manipulation

Pacropper helps security researchers and exploit developers identify these weaknesses.

## Contributing

Contributions are welcome! Please open issues or pull requests on GitHub.

## License

MIT License - see LICENSE file for details.

## Citation

If you use Pacropper in your research, please cite:

```bibtex
@software{pacrops2025,
  author = {Your Name},
  title = {Pacropper: PAC-aware ROP Gadget Finder for ARM64},
  year = {2025},
  url = {https://github.com/yourusername/pacrops}
}
```

## Acknowledgments

- Built with [Capstone](http://www.capstone-engine.org/) disassembly framework
- Inspired by ROPgadget and ropper
- Special thanks to the ARM security research community

## See Also

- [ARM Pointer Authentication](https://developer.arm.com/documentation/102446/0100/Overview-of-Pointer-Authentication)
- [PAC Security Research Papers](https://www.usenix.org/conference/usenixsecurity20/presentation/liljestrand)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
