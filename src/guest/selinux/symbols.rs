//! Read only the early symbol tables, following libsepol policydb_read/type_read.
use super::*;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> io::Result<&'a [u8]> {
        if size > self.0.len() {
            return Err(invalid("truncated SELinux symbol tables"));
        }
        let (bytes, rest) = self.0.split_at(size);
        self.0 = rest;
        Ok(bytes)
    }

    fn word(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bitmap(&mut self) -> io::Result<()> {
        self.bitmap_nodes().map(|_| ())
    }

    fn bitmap_nodes(&mut self) -> io::Result<&[u8]> {
        let size = self.word()?;
        let highbit = self.word()?;
        let count = self.word()? as usize;
        if size != 64 || highbit % 64 != 0 || (highbit == 0) != (count == 0) {
            return Err(invalid("invalid SELinux bitmap header"));
        }
        self.take(
            count
                .checked_mul(12)
                .ok_or_else(|| invalid("bitmap size overflow"))?,
        )
    }

    fn permissions(&mut self, count: u32) -> io::Result<()> {
        for _ in 0..count {
            let len = self.word()? as usize;
            self.word()?;
            self.take(len)?;
        }
        Ok(())
    }

    fn constraints(&mut self, count: u32, version: u32) -> io::Result<()> {
        for _ in 0..count {
            self.word()?;
            let expressions = self.word()?;
            for _ in 0..expressions {
                let kind = self.word()?;
                self.take(8)?;
                match kind {
                    1..=4 => (),
                    5 => {
                        self.bitmap()?;
                        if version >= 29 {
                            self.bitmap()?;
                            self.bitmap()?;
                            self.word()?;
                        }
                    }
                    _ => return Err(invalid("unknown SELinux constraint expression")),
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Symbols {
    pub names: BTreeSet<String>,
    pub permissive: BTreeSet<String>,
}

pub(super) fn read(policy: &[u8]) -> io::Result<Symbols> {
    let mut r = Reader(policy);
    if r.word()? != 0xf97cff8c {
        return Err(invalid("not a SELinux kernel policy"));
    }
    let len = r.word()? as usize;
    if r.take(len)? != b"SE Linux" {
        return Err(invalid("unsupported SELinux policy target"));
    }
    let version = r.word()?;
    // shortcut: early symbol layout verified for v24-v33; review newer formats before extending.
    if !(24..=33).contains(&version) {
        return Err(invalid(format!(
            "unsupported SELinux symbol-table version: {version}"
        )));
    }
    r.word()?;
    if r.word()? != 8 {
        return Err(invalid("unexpected SELinux symbol table count"));
    }
    r.word()?;
    r.bitmap()?; // policy capabilities
    let permissive_nodes = r.bitmap_nodes()?;
    let permissive_bits: BTreeMap<_, _> = permissive_nodes
        .chunks_exact(12)
        .map(|node| {
            (
                u32::from_le_bytes(node[..4].try_into().unwrap()),
                u64::from_le_bytes(node[4..].try_into().unwrap()),
            )
        })
        .collect();
    let mut names = BTreeSet::new();
    let mut permissive = BTreeSet::new();
    for table in 0..4 {
        let primary = r.word()?;
        let count = r.word()?;
        if count != 0 && primary == 0 {
            return Err(invalid("SELinux symbol table has no primary symbols"));
        }
        for _ in 0..count {
            let len = r.word()? as usize;
            match table {
                0 => {
                    r.take(8)?;
                    let permissions = r.word()?;
                    r.take(len)?;
                    r.permissions(permissions)?;
                }
                1 => {
                    let common_len = r.word()? as usize;
                    r.take(8)?;
                    let permissions = r.word()?;
                    let constraints = r.word()?;
                    r.take(len)?;
                    r.take(common_len)?;
                    r.permissions(permissions)?;
                    r.constraints(constraints, version)?;
                    let transitions = r.word()?;
                    r.constraints(transitions, version)?;
                    if version >= 27 {
                        r.take(12)?;
                    }
                    if version >= 28 {
                        r.word()?;
                    }
                }
                2 => {
                    r.take(8)?;
                    r.take(len)?;
                    r.bitmap()?;
                    r.bitmap()?;
                }
                _ => {
                    let value = r.word()?;
                    let properties = r.word()?;
                    r.word()?;
                    let name =
                        std::str::from_utf8(r.take(len)?).map_err(|e| invalid(e.to_string()))?;
                    if name.is_empty()
                        || name.contains('\0')
                        || value == 0
                        || value > primary
                        || properties & !3 != 0
                        || !names.insert(name.into())
                    {
                        return Err(invalid(format!("invalid SELinux type/attribute symbol: {name:?}, value={value}/{primary}, properties={properties}")));
                    }
                    if permissive_bits
                        .get(&(value / 64 * 64))
                        .is_some_and(|bits| bits & (1 << (value % 64)) != 0)
                    {
                        permissive.insert(name.into());
                    }
                }
            }
        }
    }
    Ok(Symbols { names, permissive })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "set SSAL_HOST_POLICY_FIXTURE to a saved active binary policy"]
    fn saved_host_policy_symbols() -> io::Result<()> {
        let policy = fs::read(std::env::var("SSAL_HOST_POLICY_FIXTURE").unwrap())?;
        let symbols = read(&policy)?.names;
        assert!(symbols.contains("init"));
        assert!(symbols.contains("domain"));
        assert!(!symbols.contains("object_r"));
        println!(
            "type/attribute symbols={} iso9660={}",
            symbols.len(),
            symbols.contains("iso9660")
        );
        Ok(())
    }

    #[test]
    fn reads_types_and_attributes_without_confusing_other_names_and_rejects_truncation(
    ) -> io::Result<()> {
        for version in [24u32, 30, 33] {
            let mut bytes = Vec::new();
            let words = |bytes: &mut Vec<u8>, values: &[u32]| {
                for word in values {
                    bytes.extend(word.to_le_bytes());
                }
            };
            words(&mut bytes, &[0xf97cff8c, 8]);
            bytes.extend(b"SE Linux");
            words(&mut bytes, &[version, 1, 8, 9, 64, 0, 0, 64, 64, 1]);
            words(&mut bytes, &[0, 1 << 1, 0]); // type value 1 is permissive
            words(&mut bytes, &[1, 1, 7, 1, 0, 0]);
            bytes.extend(b"iso9660"); // common name, not a type
            words(&mut bytes, &[0, 0, 0, 0, 2, 2]); // empty classes/roles, two types
            words(&mut bytes, &[12, 1, 1, 0]);
            bytes.extend(b"ssal_p0001_x");
            words(&mut bytes, &[6, 2, 2, 0]);
            bytes.extend(b"domain");
            let symbols = read(&bytes)?;
            assert_eq!(
                symbols.names,
                BTreeSet::from(["ssal_p0001_x".into(), "domain".into()])
            );
            assert_eq!(symbols.permissive, BTreeSet::from(["ssal_p0001_x".into()]));
            for end in 0..bytes.len() {
                assert!(read(&bytes[..end]).is_err());
            }
        }
        Ok(())
    }
}
