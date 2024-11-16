pub struct Input {
    input_string: Vec<u8>,
    num_blocks: usize,
}

impl Clone for Input {
    fn clone(&self) -> Self {
        Input {
            input_string: self.input_string.clone(),
            num_blocks: self.num_blocks,
        }
    }
}

impl Input {
    pub fn from_file(input_string: &[u8], num_blocks: usize) -> Self {
        Input {
            input_string: input_string.to_vec(),
            num_blocks,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.input_string.clone()
    }

    pub fn zero(num_blocks: usize) -> Self {
        Input {
            input_string: vec![0u8; num_blocks * 16],
            num_blocks,
        }
    }

    pub fn from_nonce(input: u128, blocks: usize) -> Self {
        Input {
            input_string: (0..blocks)
                .map(|i| (input.wrapping_add(i as u128)).to_be_bytes().to_vec())
                .flatten()
                .collect(),
            num_blocks: blocks,
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, u8> {
        self.input_string.iter()
    }

    pub fn num_blocks(&self) -> usize {
        self.num_blocks
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
    inputs: std::collections::HashMap<String, Input>,
    ciphertexts: std::collections::HashMap<String, String>,
}

impl DataLibrary {
    pub fn new() -> Self {
        DataLibrary { inputs: std::collections::HashMap::new(), ciphertexts: std::collections::HashMap::new() }
    }

    pub fn create(&mut self, name: &str, input: Input) {
        self.inputs.insert(name.to_string(), input);
    }

    pub fn get(&self, name: &str) -> Option<&Input> {
        self.inputs.get(name)
    }

    pub fn store_ciphertext(&mut self, name: &str, ciphertext: &str) {
        self.ciphertexts.insert(name.to_string(), ciphertext.to_string());
    }

    pub fn get_ciphertext(&self, name: &str) -> Option<&String> {
        self.ciphertexts.get(name)
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
    let mut library = DataLibrary::new();

    write_library_single(&mut library, "short", "./src/data/sources/input-short.txt");
    write_library_single(&mut library, "long", "./src/data/sources/input-long.txt");

    library.store_ciphertext("short-ecb", "da6340f38337f7f19f2c2a9bf151327e3165b40204a76a91f1f542a560713dc8945358493f31c3d45c967ad1e6404e58");
    library.store_ciphertext("short-ctr", "c1d466ec6e520f8a8ce1000f6680df7838ba90b15327c2033be52b65cd1ac076964e0e632a4fc3dc5607450c9d4c34fb");

    library
}
