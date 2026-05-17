"""
core/parser.py — ELF Parser
 
Responsibility: Open an ELF file, locate executable sections, return their
raw bytes and virtual addresses. Knows nothing about gadgets, searching,
or libc.
"""
 
from elftools.elf.elffile import ELFFile
 
 
# SHF_EXECINSTR flag — marks a section as containing executable instructions.
_SHF_EXECINSTR = 0x4
 
 
def parse_elf(binary_path):
    """
    Open an ELF binary and return its executable sections.
 
    Args:
        binary_path (str): Path to the target ELF binary or .so library.
 
    Returns:
        list[dict]: One dict per executable section, each containing:
            name      (str)   -- section name, e.g. ".text"
            data      (bytes) -- raw opcodes of the section
            base_addr (int)   -- virtual memory start address of the section
 
    Raises:
        FileNotFoundError: If binary_path does not exist.
        ValueError:        If the file is not a valid ELF.
    """
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
 
            sections = []
            for section in elf.iter_sections():
                if is_executable_section(section):
                    sections.append(
                        {
                            "name": section.name,
                            "data": section.data(),
                            "base_addr": section["sh_addr"],
                        }
                    )
 
            return sections
 
    except IsADirectoryError:
        raise FileNotFoundError(f"Expected a file, got a directory: {binary_path}")
    except Exception as exc:
        # pyelftools raises various exceptions for malformed files;
        # normalise them all to ValueError so the caller has one case to handle.
        if isinstance(exc, (FileNotFoundError, ValueError)):
            raise
        raise ValueError(f"Could not parse ELF file '{binary_path}': {exc}") from exc
 
 
def is_executable_section(section):
    """
    Return True if the section has the SHF_EXECINSTR flag set.
 
    Args:
        section (elftools.elf.sections.Section): A section object from pyelftools.
 
    Returns:
        bool: True if the section contains executable instructions.
    """
    return bool(section["sh_flags"] & _SHF_EXECINSTR)
