use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Parse Error; {0}")]
    ParseError(String),

    #[error("Error; {0}")]
    InvalidPacketStructure(String),
}
