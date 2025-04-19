use flate2::{Compression, write::GzEncoder, read::GzDecoder};
use std::io::{Write, Read};


pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("compression failed");
    encoder.finish().expect("compression error")
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).expect("decompression error");
    decompressed 
}