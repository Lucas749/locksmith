use lazy_static::lazy_static;

mod library;

pub use library::Input;
pub use library::DataLibrary;
pub use library::create_data_library;

lazy_static! {
    static ref LIBRARY: DataLibrary = create_data_library();
}

pub fn get_input(name: &str) -> &'static Input {
    LIBRARY.get(name).unwrap()
}
