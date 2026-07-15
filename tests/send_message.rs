use varcpu::optical_adapter::OpticalFrameEncoder;

#[test]
fn simulate_sending_a_message() {
    println!("\n=======================================");
    println!("📧 PREPARING SECURE MESSAGE PAYLOAD...");
    println!("=======================================");
    
    // 1. Define your raw input text message
    let secret_message = b"CONFIDENTIAL: Sovereign multi-transport packet routed successfully.";
    println!("  ✔ Data payload loaded into native memory.");

    // 2. Match your exact 2-argument signature: (max_size, session_id)
    let session_id = 0x8767_u32;
    let encoder = match OpticalFrameEncoder::new(1024, session_id) {
        Ok(enc) => enc,
        Err(e) => {
            panic!("  ❌ Initialization failure: {:?}", e);
        }
    };

    // 3. Wrap your message payload directly into the visual frame layout
    match encoder.encode_frame(1, 1, secret_message) {
        Ok(frame_bytes) => {
            println!("\n🚀 --- OUTGOING TRANSMISSION BUFFER ---");
            println!("Visual Magic Header : {:?}", std::str::from_utf8(&frame_bytes[0..4]).unwrap_or("ERR"));
            println!("Raw Packet Length     : {} bytes", frame_bytes.len());
            println!("Hex Data Stream       : {:X?}", &frame_bytes[12..std::cmp::min(frame_bytes.len(), 44)]);
            println!("---------------------------------------\n");
            println!("🎉 Message packaged for transport layer. Success.");
        }
        Err(e) => {
            panic!("  ❌ Framing allocation boundary breach: {:?}", e);
        }
    }
}

