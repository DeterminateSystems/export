use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

#[derive(Hash, Eq, PartialEq)]
pub struct VariableName(String);
impl std::fmt::Display for VariableName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for VariableName {
    type Error = VariableError;
    fn try_from(key: String) -> Result<Self, Self::Error> {
        if key.is_empty() {
            return Err(VariableError::TooShort);
        }

        if let Some(first_char) = key.chars().nth(0) {
            if !"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_".contains(first_char) {
                return Err(VariableError::FirstCharNotAlphaUnder);
            }
        } else {
            // ... should have caught this earlier, but belt / suspenders I guess
            return Err(VariableError::TooShort);
        }

        if !key.chars().all(|char| {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_".contains(char)
        }) {
            return Err(VariableError::InvalidCharacter);
        }

        Ok(VariableName(key))
    }
}

impl TryFrom<&str> for VariableName {
    type Error = VariableError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.to_string().try_into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VariableError {
    #[error("The variable name has an invalid character. The name must be a-zA-Z0-9_.")]
    InvalidCharacter,
    #[error("The variable name is empty.")]
    TooShort,
    #[error("The variable name must start with a-zA-Z_.")]
    FirstCharNotAlphaUnder,
}

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("The data included a null byte.")]
    NullByte,
    #[error("The data was not UTF-8")]
    NotUtf8,
    #[error("The encoding target does not support some of the characters in the data.")]
    OutOfRange,
}

#[derive(Debug, Copy, Clone)]
pub enum Encoding {
    /// Ash, dash, bash, ksh, zsh
    PosixShell,
    Fish,
    Elvish,
    Ion,
    NuShell,
    PowerShell,
    Rc,
    Tcsh,
}

pub fn escape(
    target: Encoding,
    data: HashMap<VariableName, OsString>,
) -> Result<OsString, DataError> {
    let mut out = OsString::new();

    let enc: &dyn Fn(&VariableName, &OsStr) -> Result<OsString, DataError> = match target {
        Encoding::PosixShell => &escape_sh,
        Encoding::Fish => &escape_fish,
        Encoding::Elvish => &escape_elvish,
        Encoding::Ion => &escape_ion,
        Encoding::NuShell => &escape_nushell,
        Encoding::PowerShell => &escape_powershell,
        Encoding::Rc => &escape_rc,
        Encoding::Tcsh => &escape_tcsh,
    };
    for (k, v) in data {
        out.push(enc(&k, &v)?);
    }

    Ok(out)
}

pub(crate) fn escape_sh(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    let mut out = OsString::new();

    out.push(format!("export {var}='"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::OutOfRange);
        }
        if byte == &b'\'' || byte == &b'!' || byte == &b'\\' {
            out.push("'\\");
            out.push(OsStr::from_bytes(&[*byte]));
            out.push("'");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_fish(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    // Presumably, fish handles things that aren't UTF-8... but Fish uses Unicode's
    // "noncharacters" for in-band signalling. Because of that, we actually have to
    // examine this data in terms of unicode characters.
    //
    // Note: an OSString can actually contain null bytes. Check before we convert
    // it to a string, which seems to ignore or stop at null bytes.
    if value.as_bytes().iter().any(|byte| byte == &b'\0') {
        return Err(DataError::NullByte);
    }
    let value = value.to_str().ok_or(DataError::NotUtf8)?;

    let mut out = OsString::new();

    out.push(format!("set --export {var} '"));
    let mut buf = [0; 4];
    for c in value.chars() {
        if ('\u{FDD0}'..='\u{FDEF}').contains(&c) {
            // noncharacters, see: https://github.com/fish-shell/fish-shell/issues/2684
            return Err(DataError::OutOfRange);
        }

        let result = c.encode_utf8(&mut buf);
        if c == '\'' || c == '!' || c == '\\' {
            out.push("'\\");
            out.push(result);
            out.push("'");
        } else {
            out.push(result);
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_elvish(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    // Note: an OSString can actually contain null bytes, evidently. Check before we convert it to
    // a string, which seems to ignore or stop at null bytes.
    if value.as_bytes().iter().any(|byte| byte == &b'\0') {
        return Err(DataError::NullByte);
    }
    let value = value.to_str().ok_or(DataError::NotUtf8)?;

    let mut out: OsString = OsString::new();

    out.push(format!("set E:{var} = '"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::OutOfRange);
        }

        if byte == &b'\'' {
            // Elvish treats two 's in a single-quoted string as an escaped '.
            out.push("''");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_powershell(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    // Note: an OSString can actually contain null bytes, evidently. Check before we convert it to
    // a string, which seems to ignore or stop at null bytes.
    if value.as_bytes().iter().any(|byte| byte == &b'\0') {
        return Err(DataError::NullByte);
    }
    let value = value.to_str().ok_or(DataError::NotUtf8)?;

    let mut out: OsString = OsString::new();

    out.push(format!("$Env:{var} = '"));

    for char in value.chars() {
        if [
            '\'', // An ASCII single quote
            '‘',  // U+2018 e2 80 98 LEFT SINGLE QUOTATION MARK
            '’',  // +2019 e2 80 99 RIGHT SINGLE QUOTATION MARK
            '‚',  // U+201A e2 80 9a SINGLE LOW-9 QUOTATION MARK
            '‛',  // U+201B e2 80 9b SINGLE HIGH-REVERSED-9 QUOTATION MARK
        ]
        .contains(&char)
        {
            // Powershell treats two quotes in a single-quoted string as an escaped quote.
            let mut b = [0; 4];

            let result = char.encode_utf8(&mut b);
            out.push(OsStr::from_bytes(result.as_bytes()));
            out.push(OsStr::from_bytes(result.as_bytes()));
        } else {
            let mut b = [0; 4];

            let result = char.encode_utf8(&mut b);
            out.push(OsStr::from_bytes(result.as_bytes()));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_ion(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    // Note: an OSString can actually contain null bytes, evidently. Check before we convert it to
    // a string, which seems to ignore or stop at null bytes.
    if value.as_bytes().iter().any(|byte| byte == &b'\0') {
        return Err(DataError::NullByte);
    }
    let value = value.to_str().ok_or(DataError::NotUtf8)?;

    let mut out: OsString = OsString::new();

    out.push(format!("export {var}='"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::NullByte);
        }

        if byte == &b'{' // BLNS#445 @{[system "touch /tmp/blns.fail"]}
            || byte == &b'\'' || byte == &b'\\'
        {
            out.push("'\\");
            out.push(OsStr::from_bytes(&[*byte]));
            out.push("'");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_nushell(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    // Note: an OSString can actually contain null bytes, evidently. Check before we convert it to
    // a string, which seems to ignore or stop at null bytes.
    if value.as_bytes().iter().any(|byte| byte == &b'\0') {
        return Err(DataError::NullByte);
    }
    let value = value.to_str().ok_or(DataError::NotUtf8)?;

    let mut out: OsString = OsString::new();

    out.push(format!("$env.{var} = '"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::NullByte);
        }

        if byte == &b'\'' {
            out.push("' + \"\\");
            out.push(OsStr::from_bytes(&[*byte]));
            out.push("\" + '");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_tcsh(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    let mut out: OsString = OsString::new();

    out.push(format!("setenv {var} '"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::OutOfRange);
        }

        if byte > &127 {
            return Err(DataError::OutOfRange);
        }

        if byte == &b'\n' {
            out.push("\\");
            out.push(OsStr::from_bytes(&[*byte]));
        } else if byte == &b'\'' || byte == &b'!' || byte == &b'\\' {
            out.push("'\\");
            out.push(OsStr::from_bytes(&[*byte]));
            out.push("'");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

pub(crate) fn escape_rc(var: &VariableName, value: &OsStr) -> Result<OsString, DataError> {
    let mut out: OsString = OsString::new();

    out.push(format!("{var}='"));

    for byte in value.as_bytes() {
        if byte == &0x00 {
            return Err(DataError::OutOfRange);
        }

        if byte == &1 || byte == &2 || byte == &255 {
            return Err(DataError::OutOfRange);
        }

        if byte == &b'\'' {
            out.push("''");
        } else {
            out.push(OsStr::from_bytes(&[*byte]));
        }
    }

    out.push("'\n");

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::process::Command;

    use base64::Engine;

    #[cfg_attr(not(target_os = "linux"), ignore)]
    #[test]
    fn ash() {
        assert_roundtrips(Encoding::PosixShell, Command::new("ash")).unwrap();
    }

    #[test]
    fn bash() {
        assert_roundtrips(Encoding::PosixShell, Command::new("bash")).unwrap();
    }

    #[test]
    fn bash_eux() {
        let mut c = Command::new("bash");
        c.args(["-eu"]);

        assert_roundtrips(Encoding::PosixShell, c).unwrap();
    }

    #[test]
    fn bash_posix() {
        let mut c = Command::new("bash");
        c.args(["--posix"]);

        assert_roundtrips(Encoding::PosixShell, c).unwrap();
    }

    #[test]
    fn dash() {
        assert_roundtrips(Encoding::PosixShell, Command::new("dash")).unwrap();
    }

    #[test]
    fn elvish() {
        assert_roundtrips(Encoding::Elvish, Command::new("elvish")).unwrap();
    }

    #[test]
    fn fish() {
        assert_roundtrips(Encoding::Fish, Command::new("fish")).unwrap();
    }

    #[test]
    fn ion() {
        assert_roundtrips(Encoding::Ion, Command::new("ion")).unwrap();
    }

    #[test]
    fn ksh() {
        assert_roundtrips(Encoding::PosixShell, Command::new("ksh")).unwrap();
    }

    #[test]
    fn nushell() {
        assert_roundtrips(Encoding::NuShell, Command::new("nu")).unwrap();
    }

    #[test]
    fn powershell() {
        assert_roundtrips(Encoding::PowerShell, Command::new("pwsh")).unwrap();
    }

    #[test]
    fn rc() {
        assert_roundtrips(Encoding::Rc, Command::new("rc")).unwrap();
    }

    #[test]
    fn tcsh() {
        assert_roundtrips(Encoding::Tcsh, Command::new("tcsh")).unwrap();
    }

    #[test]
    fn zsh() {
        assert_roundtrips(Encoding::PosixShell, Command::new("zsh")).unwrap();
    }

    fn assert_roundtrips(encoding: Encoding, mut command: Command) -> Result<(), std::io::Error> {
        let temp_dir = tempfile::tempdir()?;

        let sampler = temp_dir.as_ref().join("sampler");
        let mut file = BufWriter::new(File::create(&sampler)?);
        file.write_all(include_bytes!("./sample-env.sh"))?;
        file.flush()?;
        drop(file);

        let testcase = temp_dir.as_ref().join("script");

        let corpus: Vec<(String, OsString)> = {
            let mut partial = (0..=255)
                .map(|i: u8| (format!("byte (decimal): {i}"), OsString::from_vec(vec![i])))
                .collect::<Vec<_>>();

            let mut buf = [0; 4];
            partial.extend(
                ('\0'..=(char::MAX))
                    .into_iter()
                    .map(|c: char| {
                        let result = c.encode_utf8(&mut buf);
                        result.to_string()
                    })
                    .collect::<Vec<_>>()
                    .chunks(1024)
                    .enumerate()
                    .map(|(idx, chunk)| {
                        (
                            format!("UTF-8 Chunk #{idx} -- {}", chunk.join("")),
                            OsString::from(chunk.join("")),
                        )
                    })
                    .collect::<Vec<(String, OsString)>>(),
            );

            partial.extend(vec![(
                "this-file".into(),
                OsString::from_vec(include_bytes!("./lib.rs").to_vec()),
            )]);

            partial.extend(vec![(
                "good-shit".into(),
                OsString::from_vec(include_bytes!("../corpus/good-shit").to_vec()),
            )]);

            partial.extend(
                serde_json::from_slice::<Vec<String>>(include_bytes!("../corpus/blns.json"))
                    .unwrap()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, data)| {
                        (
                            format!("BLNS #{idx}: '{data}'"),
                            OsString::from_vec(data.into()),
                        )
                    })
                    .collect::<Vec<(String, OsString)>>(),
            );

            println!("Corpus is {} elements", partial.len());

            partial
        };

        for (label, sample) in corpus.into_iter() {
            let escaped = match escape(
                encoding,
                HashMap::from([("MYVAR".try_into().unwrap(), sample.clone())]),
            ) {
                Err(e) => {
                    println!("Skipping {label}: {e:?}");
                    continue;
                }
                Ok(v) => v,
            };
            println!("Roundtripping {label}");
            let mut file = BufWriter::new(File::create(&testcase)?);

            println!(
                "Escaped as (base64'd) {:?}",
                base64::engine::general_purpose::STANDARD.encode(escaped.as_bytes())
            );

            file.write_all(&escaped.into_vec())?;

            file.write_all(b"bash ")?;
            file.write_all(&sampler.as_os_str().as_bytes())?;
            file.write_all(b"\n")?;
            file.flush()?;
            drop(file);

            let output = command.arg(&testcase).output()?;
            let stderr = std::str::from_utf8(&output.stderr).expect("Not valid utf-8 in stderr");

            assert_eq!(stderr, "", "Unexpected stderr output");

            let encoded_bytes =
                std::str::from_utf8(&output.stdout).expect("Not valid utf-8 in stdout");

            println!("Got output: {encoded_bytes}");

            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded_bytes.trim())
                .expect("not base64y");

            if let (Ok(sample), Ok(decoded)) = (
                sample.clone().into_string(),
                String::from_utf8(decoded.clone()),
            ) {
                assert_eq!(decoded, sample, "Failed to run testcase");
            } else {
                assert_eq!(decoded, sample.as_bytes(), "Failed to run testcase");
            }

            assert!(output.status.success(), "Failed to run testcase");
        }

        Ok(())
    }
}
