use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub path: String,
    pub method: String,
}

#[unsafe(no_mangle)]
pub extern "C" fn handle(ptr: i32, len: i32) -> i32 {
    0
}
