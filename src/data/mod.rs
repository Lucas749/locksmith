use lazy_static::lazy_static;
use std::sync::{Mutex,MutexGuard};

mod library;

pub use library::Input;
pub use library::DataLibrary;
pub use library::create_data_library;

lazy_static! {
    static ref LIBRARY: Mutex<DataLibrary> = Mutex::new(create_data_library());
}

pub fn get_input(name: &str) -> Input {
    let library: MutexGuard<'_, DataLibrary> = LIBRARY.lock().unwrap();
    library.get(name).unwrap().clone()
}

pub fn store_ciphertext(name: &str, ciphertext: &str) {
    let mut library: MutexGuard<'_, DataLibrary> = LIBRARY.lock().unwrap();
    library.store_ciphertext(name, ciphertext);
}

pub fn get_ciphertext(name: &str) -> String {
    let library: MutexGuard<'_, DataLibrary> = LIBRARY.lock().unwrap();
    library.get_ciphertext(name).unwrap().clone()
}
