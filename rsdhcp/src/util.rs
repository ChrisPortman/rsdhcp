use std::collections::HashMap;

pub fn domain_name_list_compression(names: &[&str]) -> Vec<u8> {
    let mut compressed: Vec<u8> = vec![];
    let names = names.to_owned();

    let mut part_offsets: HashMap<&str, usize> = HashMap::new();

    for mut name in names {
        let mut finished_name = false;
        let mut new_part_offsets: HashMap<&str, usize> = HashMap::new();
        loop {
            let this_name = name;
            if name == "." {
                // Root domain is represented as just a 0 len
                compressed.push(0);
                break;
            }

            if part_offsets.contains_key(name) {
                // add the offset reference to compressed
                let offset = part_offsets.get(name).expect("we already checked");
                let mut offset: u16 = (*offset).try_into().expect("has too");
                offset |= 3 << 14;
                compressed.extend(offset.to_be_bytes());
                break;
            }

            let part: &str;
            match name.split_once('.') {
                Some(s) => {
                    (part, name) = s;
                }
                None => {
                    part = name;
                    finished_name = true;
                }
            };

            new_part_offsets.insert(this_name, compressed.len());

            let len: u8 = part
                .len()
                .try_into()
                .expect("dns name parts must be less than 255 chars long");
            compressed.push(len);

            if len > 0 {
                compressed.extend(part.as_bytes());
            }

            if finished_name {
                compressed.push(0);
                break;
            }
        }
        part_offsets.extend(new_part_offsets);
    }

    compressed
}

#[cfg(test)]
mod tests {
    use super::domain_name_list_compression;

    #[test]
    fn test_dns_name_compression() {
        // test derived from https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
        let names = vec!["F.ISI.ARPA", "FOO.F.ISI.ARPA", "ARPA", "."];
        let expected: Vec<u8> = vec![
            1, 70, 3, 73, 83, 73, 4, 65, 82, 80, 65, 0, 3, 70, 79, 79, 192, 0, 192, 6, 0,
        ];
        let compressed = domain_name_list_compression(&names);
        assert_eq!(compressed, expected);
    }
}
