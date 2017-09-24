error_chain! {
  foreign_links {
    Io(::std::io::Error);
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
  }
}
