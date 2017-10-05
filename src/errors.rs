error_chain! {
  foreign_links {
    Io(::std::io::Error);
    OpenSsl(::openssl::error::ErrorStack);
    ParseInt(::std::num::ParseIntError);
    Utf8Error(::std::str::Utf8Error);
  }

  errors {
    InvalidHexChar(c: char) {
      description("invalid hex char")
      display("invalid hex char: '{}'", c)
    }
    InvalidBase64Index(u: u8) {
      description("invalid base64 index")
      display("invalid base64 index: '{}'", u)
    }
    InvalidBase64Char(c: char) {
      description("invalid base64 char")
      display("invalid base64 char: '{}'", c)
    }
    InvalidPkcs7Padding(s: Vec<u8>) {
      description("invalid pkcs7 padding")
      display("invalid pkcs7 padding for string: {:?}", s)
    }
    ParseKvError(kv: Vec<u8>) {
      description("parse key value error")
      display("failed to parse string: {:?}", kv)
    }
    InvalidEmail(email: Vec<u8>) {
      description("invalid email")
      display("invalid email: {:?}", email)
    }
  }
}
