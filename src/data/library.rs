pub struct Input {
    input_string: Vec<u8>,
    num_blocks: usize,
}

impl Input {
    pub fn from_file(input_string: &[u8], num_blocks: usize) -> Self {
        Input {
            input_string: input_string.to_vec(),
            num_blocks,
        }
    }
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("input_string", &String::from_utf8_lossy(&self.input_string))
            .field("num_blocks", &self.num_blocks)
            .finish()
    }
}

pub struct DataLibrary {
    inputs: std::collections::HashMap<String, Input>
}

impl DataLibrary {
    pub fn new() -> Self {
        DataLibrary { inputs: std::collections::HashMap::new() }
    }

    pub fn create(&mut self, name: &str, input: Input) {
        self.inputs.insert(name.to_string(), input);
    }

    pub fn get(&self, name: &str) -> Option<&Input> {
        self.inputs.get(name)
    }
}


pub fn pad_input_string(input_string: &[u8]) -> (Vec<u8>, usize) {
    let padding_len: usize = (16 - (input_string.len() % 16)) % 16;
    let padding: Vec<u8> = vec![0u8; padding_len];
    let input_string_padded: Vec<u8> = [input_string, &padding].concat();
    // Number of 16-byte blocks
    let num_blocks: usize = input_string_padded.len() / 16;
    (input_string_padded, num_blocks)
}

pub fn write_library_single(library: &mut DataLibrary, name: &str, filename: &str) {
    let input_string = std::fs::read(filename).expect("Failed to read file");
    let (padded_string, num_blocks) = pad_input_string(&input_string);
    library.create(name, Input::from_file(&padded_string, num_blocks));
}

pub fn create_data_library() -> DataLibrary {
    let mut library = DataLibrary { inputs: std::collections::HashMap::new() };

    write_library_single(&mut library, "short", "./src/data/sources/input-short.txt");
    write_library_single(&mut library, "long", "./src/data/sources/input-long.txt");

    library
}
