#!/usr/bin/env python3
"""
Pacropper - PAC-aware ROP Gadget Finder for ARM64 binaries
Python bindings for pwntools integration
"""

import json
import subprocess
from typing import List, Dict, Optional
from pathlib import Path

__version__ = "0.1.0"
__all__ = ['Pacropper', 'Gadget', 'GadgetType', 'PacropperError']


class PacropperError(Exception):
    """Exception raised for pacrops errors"""
    pass


class GadgetType:
    """Gadget vulnerability types"""
    UNSIGNED = "Unsigned"
    UNSIGNED_INDIRECT = "UnsignedIndirect"
    PRE_AUTH_LOAD = "PreAuthLoad"
    REPLAY_VULNERABLE = "ReplayVulnerable"
    CONTEXT_MANIPULATION = "ContextManipulation"
    KEY_CONFUSION = "KeyConfusion"
    MODIFIER_CONFUSION = "ModifierConfusion"
    STACK_PIVOT = "StackPivot"
    PAC_SAFE = "PacSafe"


class Gadget:
    """Represents a single ROP gadget"""

    def __init__(self, data: Dict):
        self.address = data['address']
        self.instructions = data['instructions']
        self.gadget_type = data['gadget_type']
        self.pac_instructions = data.get('pac_instructions', [])
        self.vulnerability_notes = data.get('vulnerability_notes', [])

    def __str__(self) -> str:
        insns = ' ; '.join(self.instructions)
        return f"0x{self.address:x}: {insns} [{self.gadget_type}]"

    def __repr__(self) -> str:
        return f"Gadget(0x{self.address:x}, {self.gadget_type})"

    @property
    def is_exploitable(self) -> bool:
        """Returns True if this gadget can be used in exploits"""
        return self.gadget_type != GadgetType.PAC_SAFE


class Pacropper:
    """
    Python wrapper for the pacrops binary analysis tool.

    Example usage:
        p = Pacropper('./target/binary')

        # Get all unsigned gadgets
        unsigned = p.unsigned_gadgets()
        for gadget in unsigned:
            print(f"{hex(gadget.address)}: {' ; '.join(gadget.instructions)}")

        # Get Pre-Auth Load gadgets (loads pre-signed pointers)
        preauth = p.preauth_load_gadgets()

        # Search for specific instruction patterns
        pop_gadgets = p.search(r'ldr x0.*ret')

        # Get statistics
        stats = p.statistics
        print(f"Found {stats['exploitable_gadgets']} exploitable gadgets")
    """

    def __init__(self, binary_path: str, pacrops_path: Optional[str] = None,
                 max_gadget_size: int = 10):
        """
        Initialize Pacropper with a binary to analyze.

        Args:
            binary_path: Path to the ARM64 binary to analyze
            pacrops_path: Path to the pacrops binary (defaults to ./target/release/pacrops)
            max_gadget_size: Maximum number of instructions per gadget
        """
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise PacropperError(f"Binary not found: {binary_path}")

        # Find pacrops binary
        if pacrops_path:
            self.pacrops_path = Path(pacrops_path)
        else:
            # Try common locations
            possible_paths = [
                Path(__file__).parent / 'target' / 'release' / 'pacrops',
                Path(__file__).parent / 'target' / 'debug' / 'pacrops',
                Path('pacrops'),  # In PATH
            ]
            for path in possible_paths:
                if path.exists() or path.name == 'pacrops':
                    self.pacrops_path = path
                    break
            else:
                raise PacropperError("Could not find pacrops binary. Please build it or specify the path.")

        self.max_gadget_size = max_gadget_size
        self._data = None
        self._gadgets = None

    def _run_pacrops(self, *args) -> Dict:
        """Run pacrops and return JSON output"""
        cmd = [str(self.pacrops_path), str(self.binary_path),
               '--json', '-s', str(self.max_gadget_size)] + list(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Parse JSON from stdout (skip any stderr output)
            output_lines = result.stdout.strip().split('\n')
            # Find the JSON output (starts with '{')
            json_start = next(i for i, line in enumerate(output_lines) if line.strip().startswith('{'))
            json_output = '\n'.join(output_lines[json_start:])
            return json.loads(json_output)
        except subprocess.CalledProcessError as e:
            raise PacropperError(f"Pacropper failed: {e.stderr}")
        except json.JSONDecodeError as e:
            raise PacropperError(f"Failed to parse pacrops output: {e}")

    def _load_data(self):
        """Load gadget data from pacrops"""
        if self._data is None:
            self._data = self._run_pacrops()
            self._gadgets = [Gadget(g) for g in self._data['gadgets']]

    @property
    def gadgets(self) -> List[Gadget]:
        """Get all gadgets found by pacrops"""
        self._load_data()
        return self._gadgets

    @property
    def statistics(self) -> Dict:
        """Get vulnerability statistics"""
        self._load_data()
        return self._data['statistics']

    @property
    def pac_count(self) -> int:
        """Number of PAC instructions found in the binary"""
        self._load_data()
        return self._data['pac_count']

    def find(self, gadget_type: Optional[str] = None,
             min_length: int = 1, max_length: int = 100) -> List[Gadget]:
        """
        Find gadgets matching specific criteria.

        Args:
            gadget_type: Filter by GadgetType (e.g., GadgetType.UNSIGNED)
            min_length: Minimum number of instructions
            max_length: Maximum number of instructions

        Returns:
            List of matching Gadget objects
        """
        self._load_data()
        results = self._gadgets

        if gadget_type:
            results = [g for g in results if g.gadget_type == gadget_type]

        results = [g for g in results
                  if min_length <= len(g.instructions) <= max_length]

        return results

    def search(self, pattern: str, regex: bool = True) -> List[Gadget]:
        """
        Search for gadgets containing specific instruction patterns.

        Args:
            pattern: Search pattern (regex or plain text)
            regex: Whether to treat pattern as regex (default: True)

        Returns:
            List of matching Gadget objects
        """
        import re
        self._load_data()

        if regex:
            pat = re.compile(pattern, re.IGNORECASE)
            return [g for g in self._gadgets
                   if any(pat.search(insn) for insn in g.instructions)]
        else:
            pattern_lower = pattern.lower()
            return [g for g in self._gadgets
                   if any(pattern_lower in insn.lower() for insn in g.instructions)]

    def pop_register(self, register: str = 'x0') -> List[Gadget]:
        """
        Find gadgets that pop a specific register from the stack.

        Args:
            register: Register name (e.g., 'x0', 'x1', 'lr')

        Returns:
            List of gadgets that load into the specified register
        """
        pattern = f'ldr {register}'
        return self.search(pattern)

    def syscall_gadgets(self) -> List[Gadget]:
        """Find gadgets containing syscall instructions (svc)"""
        return self.search(r'svc\s+')

    def call_gadgets(self) -> List[Gadget]:
        """Find gadgets that call functions (bl, blr)"""
        return self.search(r'bl[r]?\s+')

    def ret_gadgets(self) -> List[Gadget]:
        """Find gadgets ending with ret"""
        return [g for g in self.gadgets
               if g.instructions and 'ret' in g.instructions[-1].lower()]

    def unsigned_gadgets(self) -> List[Gadget]:
        """Find all gadgets without PAC protection"""
        return self.find(gadget_type=GadgetType.UNSIGNED)

    def preauth_load_gadgets(self) -> List[Gadget]:
        """Find all Pre-Auth Load gadgets (loads pre-signed pointers from data sections)"""
        return self.find(gadget_type=GadgetType.PRE_AUTH_LOAD)

    def exploitable_gadgets(self) -> List[Gadget]:
        """Find all exploitable gadgets (excludes PAC-safe)"""
        return [g for g in self.gadgets if g.is_exploitable]

    def dump(self, output_file: Optional[str] = None):
        """
        Dump all gadgets to stdout or a file.

        Args:
            output_file: Optional file path to write output
        """
        self._load_data()

        lines = []
        lines.append(f"Pacropper Analysis: {self.binary_path}")
        lines.append(f"PAC Instructions: {self.pac_count}")
        lines.append(f"Total Gadgets: {len(self._gadgets)}")
        lines.append(f"Exploitable: {self._data['exploitable_gadgets']}")
        lines.append("")
        lines.append("Statistics:")
        for key, value in self.statistics.items():
            lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("Gadgets:")
        for gadget in self._gadgets:
            lines.append(str(gadget))

        output = '\n'.join(lines)

        if output_file:
            Path(output_file).write_text(output)
        else:
            print(output)


# Convenience function for quick analysis
def analyze(binary_path: str, **kwargs) -> Pacropper:
    """
    Quickly analyze a binary and return a Pacropper instance.

    Example:
        p = analyze('./binary')
        print(f"Found {len(p.unsigned_gadgets())} unsigned gadgets")
    """
    return Pacropper(binary_path, **kwargs)


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        print()
        print("Example:")
        print(f"  python3 {sys.argv[0]} ./demo")
        sys.exit(1)

    p = analyze(sys.argv[1])
    p.dump()
