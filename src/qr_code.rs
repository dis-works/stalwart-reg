use qrcode::QrCode;
use qrcode::render::svg;

pub fn generate_qr_code(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Create a QrCode from the URL
    let code = QrCode::new(url)?;
    let svg = code.render::<svg::Color>().build();
    Ok(svg)
}
