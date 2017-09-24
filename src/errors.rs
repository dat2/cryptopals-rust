error_chain! {
  foreign_links {
    Io(::std::io::Error);
    OpenSsl(::openssl::error::ErrorStack);
    ParseInt(::std::num::ParseIntError);
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
  }
}
