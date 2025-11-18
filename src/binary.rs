use object::{Object, ObjectSection};
use std::fs;

pub struct BinaryInfo {
    pub sections: Vec<(Vec<u8>, u64, String)>,  // (code, addr, name)
    pub data_sections: Vec<(u64, u64, String)>,  // (start_addr, end_addr, name) for data sections
    pub has_pac_header: bool,
    #[allow(dead_code)]
    pub is_arm64e: bool,
}

pub fn load_binary(path: &str) -> Result<BinaryInfo, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;

    let mut has_pac_header = false;
    let mut is_arm64e = false;

    // Try to parse as universal binary first
    let obj = match object::File::parse(&*data) {
        Ok(obj) => obj,
        Err(_) => {
            // If it fails, try parsing as a fat/universal binary
            use object::read::macho::{MachOFatFile32, MachOFatFile64, FatArch};
            use object::macho;

            let mut slice_obj = None;

            // Try 32-bit fat first
            if let Ok(fat) = MachOFatFile32::parse(&*data) {
                for arch in fat.arches() {
                    // ARM64E/ARM64 is cputype=0x0100000c
                    if arch.cputype() == macho::CPU_TYPE_ARM64 {
                        let slice_data = arch.data(&*data)?;

                        // Check for arm64e subtype (0x02 or 0x80000002)
                        let cpusubtype = arch.cpusubtype();
                        if (cpusubtype & 0xFF) == 0x02 {
                            is_arm64e = true;
                            has_pac_header = true;
                        }

                        slice_obj = Some(object::File::parse(slice_data)?);
                        break;
                    }
                }
            }

            // Try 64-bit fat if we didn't find it in 32-bit
            if slice_obj.is_none() {
                if let Ok(fat) = MachOFatFile64::parse(&*data) {
                    for arch in fat.arches() {
                        if arch.cputype() == macho::CPU_TYPE_ARM64 {
                            let slice_data = arch.data(&*data)?;

                            // Check for arm64e subtype
                            let cpusubtype = arch.cpusubtype();
                            if (cpusubtype & 0xFF) == 0x02 {
                                is_arm64e = true;
                                has_pac_header = true;
                            }

                            slice_obj = Some(object::File::parse(slice_data)?);
                            break;
                        }
                    }
                }
            }

            slice_obj.ok_or_else(|| -> Box<dyn std::error::Error> {
                "No ARM64/ARM64E slice found in universal binary".into()
            })?
        }
    };

    // Also check if it's a direct arm64e binary by checking raw header bytes
    // Mach-O 64-bit header is 32 bytes, cpusubtype is at offset 8 (4 bytes after cputype)
    if data.len() >= 12 {
        // Check for MH_MAGIC_64 (0xfeedfacf)
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xfeedfacf {
            // CPU type at offset 4, cpusubtype at offset 8
            let cpusubtype = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            if (cpusubtype & 0xFF) == 0x02 {
                is_arm64e = true;
                has_pac_header = true;
            }
        }
    }

    // Collect all executable sections and data sections
    let mut sections = Vec::new();
    let mut data_sections = Vec::new();

    for section in obj.sections() {
        if let Ok(name) = section.name() {
            // Collect executable sections (typically __text, __stubs, __stub_helper, etc.)
            if name.starts_with("__text") || name.starts_with("__stub") || name.starts_with("__auth_stub") {
                if let Ok(data) = section.data() {
                    let addr = section.address();
                    sections.push((data.to_vec(), addr, name.to_string()));
                }
            }
            // Collect data sections that may contain PAC-signed pointers
            else if name.starts_with("__const") ||
                    name.starts_with("__data") ||
                    name.starts_with("__rodata") ||
                    name.starts_with("__auth_got") ||
                    name.starts_with("__auth_ptr") ||
                    name.starts_with("__got") {
                let addr = section.address();
                let size = section.size();
                data_sections.push((addr, addr + size, name.to_string()));
            }
        }
    }

    if sections.is_empty() {
        return Err("No executable sections found".into());
    }

    Ok(BinaryInfo {
        sections,
        data_sections,
        has_pac_header,
        is_arm64e,
    })
}
