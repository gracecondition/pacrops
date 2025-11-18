<div align="center">
<img src="assets/logo.png" alt="machsec logo" width="180">
</div>

# pacrops

**PAC-aware ROP Gadget Finder for ARM64 Binaries**

A specialized tool for finding exploitable ROP gadgets in ARM64 binaries with Pointer Authentication Codes (PAC). Identifies gadgets unprotected by PAC or vulnerable to known bypass techniques.

## Quick Start

```bash
cargo build --release
./target/release/pacrops ./binary
./target/release/pacrops ./binary --help  # See all options
```

## Vulnerability Classes

| Severity | Class | Description |
|----------|-------|-------------|
| 🔴 **CRITICAL** | **Pre-Auth Load** | Loads pre-signed pointers from `__auth_got`/`__auth_ptr` before branch |
| 🔴 **CRITICAL** | **Unsigned** | No PAC protection at all |
| 🔴 **CRITICAL** | **Unsigned Indirect** | `br`/`blr` without authentication |
| 🔴 **CRITICAL** | **Stack Pivot** | Modifies SP before `autiasp`/`autibsp` |
| 🔴 **CRITICAL** | **Key Confusion** | Signs with key A, authenticates with key B |
| 🟡 **HIGH** | **Context Manipulation** | Modifies LR/x30 before authentication |
| 🟡 **HIGH** | **Modifier Confusion** | Different modifiers for sign/auth (e.g., `paciasp` + `autiaz`) |
| 🟡 **MEDIUM** | **Replay Vulnerable** | Uses zero modifier (`paciaz`/`autiaz`) |
| 🟢 **SAFE** | **PAC-Safe** | Properly protected by PAC |

## Usage

```bash
# Show only Pre-Auth Load gadgets (loads from __auth_got, etc.)
./target/release/pacrops ./binary --preauth-only

# Show only unsigned gadgets (default)
./target/release/pacrops ./binary --unsigned-only

# Show all vulnerable gadgets
./target/release/pacrops ./binary --vulnerable-only

# Show only stack pivot gadgets
./target/release/pacrops ./binary --stack-pivot-only

# Show all gadgets including PAC-safe
./target/release/pacrops ./binary --show-all

# Search for specific patterns
./target/release/pacrops ./binary --search "ldr x0.*ret"

# JSON output for tool integration
./target/release/pacrops ./binary --json

# Limit gadget size
./target/release/pacrops ./binary --max-size 5
```

### Available Filters

All vulnerability-specific flags with clear severity levels:
- `--preauth-only` - [CRITICAL] Pre-authenticated pointer loads
- `--unsigned-only` - [CRITICAL] No PAC protection
- `--unsigned-indirect-only` - [CRITICAL] Unsigned `br`/`blr`
- `--stack-pivot-only` - [CRITICAL] SP modification before auth
- `--context-only` - [HIGH] LR/x30 modification before auth
- `--key-confusion-only` - [HIGH] Sign/auth key mismatch
- `--modifier-confusion-only` - [MEDIUM] Modifier mismatch
- `--replay-only` - [MEDIUM] Zero modifier usage
- `--vulnerable-only` - All exploitable gadgets
- `--show-all` - Include PAC-safe gadgets

## Example Output

```
Total PAC instructions found in binary: 1167

Gadgets:
──────────────────────────────────────────────────────────────────────────────────────────
0x0000000000096c80  adrp x17, #0xdc000 ; add x17, x17, #0 ; ldr x16, [x17] ; braa x16, x17  [PREAUTH-LOAD]
0x0000000000096c90  adrp x17, #0xdc000 ; add x17, x17, #8 ; ldr x16, [x17] ; braa x16, x17  [PREAUTH-LOAD]

╔════════════════════════════════════════════════════════════════════════╗
║                  PAC-Aware ROP Gadget Analysis                         ║
╚════════════════════════════════════════════════════════════════════════╝

  Binary:              ./iMessage
  Max gadget size:     10
  PAC instructions:    1167

  Total gadgets:       6502
  Exploitable:         2566 / 6502 (39%)

  Vulnerability Breakdown:
    ├─ Unsigned (no PAC):           269
    ├─ Unsigned indirect (br/blr):  10
    ├─ Pre-auth load (data section): 2176
    ├─ Key confusion:                0
    ├─ Modifier confusion:           0
    ├─ Replay vulnerable:            10
    ├─ Context manipulation:         82
    ├─ Stack pivot:                  19
    └─ PAC-safe:                     3936

⚠️  Exploitable gadgets: 2566
```

## Python Bindings

```python
from pacrops import pacrops, GadgetType

# Analyze binary
p = pacrops('./binary')

# Get statistics
print(f"Found {p.pac_count} PAC instructions")
print(f"Found {len(p.exploitable_gadgets())} exploitable gadgets")

# Find specific gadgets
unsigned = p.unsigned_gadgets()
preauth = p.preauth_load_gadgets()
pop_x0 = p.pop_register('x0')

# Search patterns
system_calls = p.search(r'bl.*x0')

# Integration with pwntools
from pwn import *
context.arch = 'aarch64'

rop = b'A' * 128
rop += p64(pop_x0[0].address)
rop += p64(binsh_addr)
rop += p64(system_calls[0].address)
```

## How It Works

pacrops uses a priority-based detection pipeline:

<div align="center">
<img src="assets/detection-flow.svg" alt="PAC Detection Flow" width="100%">
</div>

### Detection Flow

1. **Disassemble** binary and locate all control-flow instructions (`ret`, `br`, `blr`, `braa`, etc.)
2. **Extract gadgets** by looking backwards from each control-flow instruction
3. **Identify PAC instructions** in each gadget (`paciasp`, `autiasp`, `retaa`, etc.)
4. **Analyze vulnerabilities** in priority order:
   - Pre-Auth Load: Check if `br`/`blr` target is loaded from data sections
   - Unsigned Indirect: Check for `br`/`blr` without authentication
   - Stack Pivot: SP modification before `autiasp`/`autibsp`
   - Key Confusion: Sign with key A, auth with key B
   - Modifier Confusion: Different sign/auth modifiers
   - Context Manipulation: LR/x30 modification before auth
   - Replay Vulnerable: Zero modifier usage
5. **Classify** as PAC-safe or unsigned if no vulnerabilities found

**Key Innovation - Pre-Auth Load Detection:**
ARM64 binaries store pre-signed function pointers in `__auth_got`, `__auth_ptr`, `__const` sections at compile time. Gadgets that load from these sections bypass PAC entirely by reusing valid authenticated pointers. pacrops tracks register values through `adrp`+`add`+`ldr` instruction chains to detect this.

## Demo

```bash
make                                    # Build demo binary
./target/release/pacrops ./demo         # Analyze it
python3 exploit_clean.py                # Run exploit
```

## Research

Pointer Authentication (PAC) is an ARMv8.3-A security feature designed to prevent ROP/JOP attacks. However, implementation flaws and improper usage create exploitable gadgets. This tool helps identify them.

**References:**
- [ARM Pointer Authentication](https://developer.arm.com/documentation/102446/0100/Overview-of-Pointer-Authentication)
- [PAC Bypass Research](https://www.usenix.org/conference/usenixsecurity20/presentation/liljestrand)

## License

MIT License - see LICENSE file for details.
