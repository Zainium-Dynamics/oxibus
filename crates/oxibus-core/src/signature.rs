// Signature string parsing/validation.

use crate::error::{CoreError, CoreResult};
use crate::types::{Type, MAX_ARRAY_DEPTH, MAX_STRUCT_DEPTH};

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    array_depth: u32,
    struct_depth: u32,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn parse_one(&mut self, allow_dict_entry: bool) -> CoreResult<Type> {
        let b = self.advance().ok_or(CoreError::InvalidSignature(
            String::new(),
            "unexpected end of signature",
        ))?;
        let ty = match b {
            b'y' => Type::Byte,
            b'b' => Type::Boolean,
            b'n' => Type::Int16,
            b'q' => Type::UInt16,
            b'i' => Type::Int32,
            b'u' => Type::UInt32,
            b'x' => Type::Int64,
            b't' => Type::UInt64,
            b'd' => Type::Double,
            b's' => Type::String,
            b'o' => Type::ObjectPath,
            b'g' => Type::Signature,
            b'h' => Type::UnixFd,
            b'v' => Type::Variant,
            b'a' => {
                self.array_depth += 1;
                if self.array_depth > MAX_ARRAY_DEPTH {
                    return Err(CoreError::NestingTooDeep {
                        max_array: MAX_ARRAY_DEPTH,
                        max_struct: MAX_STRUCT_DEPTH,
                    });
                }
                let elem = self.parse_one(true)?;
                self.array_depth -= 1;
                Type::Array(Box::new(elem))
            }
            b'(' => {
                self.struct_depth += 1;
                if self.struct_depth > MAX_STRUCT_DEPTH {
                    return Err(CoreError::NestingTooDeep {
                        max_array: MAX_ARRAY_DEPTH,
                        max_struct: MAX_STRUCT_DEPTH,
                    });
                }
                let mut fields = Vec::new();
                loop {
                    match self.peek() {
                        Some(b')') => {
                            self.advance();
                            break;
                        }
                        None => {
                            return Err(CoreError::InvalidSignature(
                                String::new(),
                                "unterminated struct: missing ')'",
                            ))
                        }
                        _ => fields.push(self.parse_one(false)?),
                    }
                }
                self.struct_depth -= 1;
                if fields.is_empty() {
                    return Err(CoreError::InvalidSignature(
                        String::new(),
                        "struct must have at least one field",
                    ));
                }
                Type::Struct(fields)
            }
            b'{' => {
                if !allow_dict_entry {
                    return Err(CoreError::InvalidSignature(
                        String::new(),
                        "dict-entry '{' only allowed as an array element type",
                    ));
                }
                self.struct_depth += 1;
                if self.struct_depth > MAX_STRUCT_DEPTH {
                    return Err(CoreError::NestingTooDeep {
                        max_array: MAX_ARRAY_DEPTH,
                        max_struct: MAX_STRUCT_DEPTH,
                    });
                }
                let key = self.parse_one(false)?;
                if !key.is_basic() {
                    return Err(CoreError::InvalidSignature(
                        String::new(),
                        "dict-entry key must be a basic type",
                    ));
                }
                let val = self.parse_one(false)?;
                match self.advance() {
                    Some(b'}') => {}
                    _ => {
                        return Err(CoreError::InvalidSignature(
                            String::new(),
                            "unterminated dict-entry: missing '}'",
                        ))
                    }
                }
                self.struct_depth -= 1;
                Type::DictEntry(Box::new(key), Box::new(val))
            }
            b')' | b'}' => {
                return Err(CoreError::InvalidSignature(
                    String::new(),
                    "unexpected closing bracket",
                ))
            }
            other => {
                return Err(CoreError::InvalidSignature(
                    (other as char).to_string(),
                    "unknown type code",
                ))
            }
        };
        Ok(ty)
    }
}

pub fn parse_signature(s: &str) -> CoreResult<Vec<Type>> {
    if s.len() > crate::types::MAX_SIGNATURE_LEN {
        return Err(CoreError::SignatureTooLong(s.len()));
    }
    if !s.is_ascii() {
        return Err(CoreError::InvalidSignature(
            s.to_string(),
            "signature must be ASCII",
        ));
    }
    let mut p = Parser {
        bytes: s.as_bytes(),
        pos: 0,
        array_depth: 0,
        struct_depth: 0,
    };
    let mut out = Vec::new();
    while p.peek().is_some() {
        out.push(p.parse_one(false)?);
    }
    Ok(out)
}

pub fn parse_single_complete_type(s: &str) -> CoreResult<Type> {
    let types = parse_signature(s)?;
    if types.len() != 1 {
        return Err(CoreError::InvalidSignature(
            s.to_string(),
            "expected exactly one complete type",
        ));
    }
    Ok(types.into_iter().next().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_types() {
        assert_eq!(parse_signature("y").unwrap(), vec![Type::Byte]);
        assert_eq!(
            parse_signature("sss").unwrap(),
            vec![Type::String, Type::String, Type::String]
        );
    }

    #[test]
    fn array_and_dict() {
        let t = parse_single_complete_type("a{sv}").unwrap();
        assert_eq!(
            t,
            Type::Array(Box::new(Type::DictEntry(
                Box::new(Type::String),
                Box::new(Type::Variant)
            )))
        );
    }

    #[test]
    fn struct_nested() {
        let t = parse_single_complete_type("(iai)").unwrap();
        assert_eq!(
            t,
            Type::Struct(vec![Type::Int32, Type::Array(Box::new(Type::Int32))])
        );
    }

    #[test]
    fn dict_entry_outside_array_rejected() {
        assert!(parse_signature("{sv}").is_err());
    }

    #[test]
    fn empty_struct_rejected() {
        assert!(parse_signature("()").is_err());
    }

    #[test]
    fn unterminated_struct_rejected() {
        assert!(parse_signature("(i").is_err());
    }

    #[test]
    fn dict_entry_non_basic_key_rejected() {
        assert!(parse_signature("a{vs}").is_err());
    }

    #[test]
    fn roundtrip_to_signature_string() {
        let t = parse_single_complete_type("a{sv}").unwrap();
        assert_eq!(t.to_signature_string(), "a{sv}");
        let t2 = parse_single_complete_type("(oa{sv})").unwrap();
        assert_eq!(t2.to_signature_string(), "(oa{sv})");
    }

    #[test]
    fn array_depth_limit() {
        let sig = "a".repeat(33) + "y";
        assert!(parse_signature(&sig).is_err());
        let sig_ok = "a".repeat(32) + "y";
        assert!(parse_signature(&sig_ok).is_ok());
    }
}
