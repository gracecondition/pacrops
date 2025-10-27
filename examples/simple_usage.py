#!/usr/bin/env python3
"""
Simple Pacropper Usage Examples
"""

from pathlib import Path
import sys

# Add parent directory to path for importing pacrops
sys.path.insert(0, str(Path(__file__).parent.parent))

from pacrops import Pacropper, GadgetType

def main():
    # Analyze the demo binary
    print("=" * 70)
    print("Pacropper Usage Examples")
    print("=" * 70)
    print()

    binary = Path(__file__).parent.parent / 'demo'
    if not binary.exists():
        print(f"Error: {binary} not found. Run 'make' first.")
        return

    p = Pacropper(str(binary))

    # Example 1: Basic statistics
    print("📊 Example 1: Basic Statistics")
    print("-" * 70)
    print(f"Binary: {binary.name}")
    print(f"PAC Instructions: {p.pac_count}")
    print(f"Total Gadgets: {len(p.gadgets)}")
    print(f"Exploitable Gadgets: {len(p.exploitable_gadgets())}")
    print()
    print("Statistics:")
    for key, value in p.statistics.items():
        print(f"  {key:25s}: {value}")
    print()

    # Example 2: Find unsigned gadgets
    print("🔍 Example 2: Find Unsigned Gadgets")
    print("-" * 70)
    unsigned = p.unsigned_gadgets()
    print(f"Found {len(unsigned)} unsigned gadgets")
    for gadget in unsigned[:5]:
        print(f"  {hex(gadget.address)}: {' ; '.join(gadget.instructions)}")
    print()

    # Example 3: Search for specific patterns
    print("🎯 Example 3: Search for Specific Patterns")
    print("-" * 70)

    # Find gadgets that load x0
    pop_x0 = p.pop_register('x0')
    print(f"Gadgets that load x0: {len(pop_x0)}")
    if pop_x0:
        print(f"  Best: {hex(pop_x0[0].address)}: {' ; '.join(pop_x0[0].instructions)}")

    # Find gadgets with function calls
    calls = p.call_gadgets()
    print(f"Gadgets with bl/blr: {len(calls)}")
    if calls:
        print(f"  Best: {hex(calls[0].address)}: {' ; '.join(calls[0].instructions)}")

    # Find syscall gadgets
    syscalls = p.syscall_gadgets()
    print(f"Gadgets with svc: {len(syscalls)}")
    print()

    # Example 4: Build a ROP chain
    print("🔗 Example 4: Building a ROP Chain")
    print("-" * 70)
    if pop_x0 and calls:
        print("ROP Chain:")
        print(f"  1. {hex(pop_x0[0].address)} - {' ; '.join(pop_x0[0].instructions)}")
        print(f"  2. <data: address of '/bin/sh'>")
        print(f"  3. {hex(calls[0].address)} - {' ; '.join(calls[0].instructions)}")
        print()
        print("Python code:")
        print(f"  rop = b'A' * 128")
        print(f"  rop += p64(0)  # Saved FP")
        print(f"  rop += p64({hex(pop_x0[0].address)})  # pop x0")
        print(f"  rop += p64(binsh_addr)  # argument")
        print(f"  rop += p64(0)  # padding")
        print(f"  rop += p64({hex(calls[0].address)})  # system")
    print()

    # Example 5: Filter by gadget type
    print("🏷️  Example 5: Filter by Type")
    print("-" * 70)
    types = [
        (GadgetType.UNSIGNED, "Unsigned (no PAC)"),
        (GadgetType.UNSIGNED_INDIRECT, "Unsigned indirect (br/blr)"),
        (GadgetType.PAC_SAFE, "PAC-safe"),
    ]
    for gtype, desc in types:
        gadgets = p.find(gadget_type=gtype)
        print(f"  {desc:30s}: {len(gadgets)} gadgets")
    print()

    print("=" * 70)
    print("✅ Analysis complete!")
    print("=" * 70)

if __name__ == '__main__':
    main()
