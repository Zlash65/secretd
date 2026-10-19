use std::io::Cursor;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use png::{BitDepth, ColorType, Decoder, Transformations};
use tray_icon::Icon;

const TRAY_ICON_PNG: &str = include_str!("../assets/tray-light.png.base64");
const LOCKED_COLOR: [u8; 3] = [142, 142, 147];
const UNLOCKED_COLOR: [u8; 3] = [235, 235, 240];
// The locked icon is crossed out from top left to bottom right. Sizes are in pixels of the 44×44
// icon: the slash spans the logo, matches its stroke, and has a gap on each side to stand out.
const SLASH_INSET: f32 = 5.;
const SLASH_WIDTH: f32 = 3.;
const SLASH_GAP: f32 = 2.;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayStatus {
    Locked,
    Unlocked,
}

pub fn tray_icon(status: TrayStatus) -> Result<Icon, String> {
    let (rgba, width, height) = decode_tray_icon(status)?;
    Icon::from_rgba(rgba, width, height).map_err(|error| error.to_string())
}

fn decode_tray_icon(status: TrayStatus) -> Result<(Vec<u8>, u32, u32), String> {
    let encoded = STANDARD
        .decode(TRAY_ICON_PNG.trim())
        .map_err(|error| format!("invalid embedded tray icon: {error}"))?;
    let mut decoder = Decoder::new(Cursor::new(encoded));
    decoder.set_transformations(Transformations::EXPAND | Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|error| format!("could not read embedded tray icon: {error}"))?;
    let mut rgba = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or("embedded tray icon is too large")?
    ];
    let info = reader
        .next_frame(&mut rgba)
        .map_err(|error| format!("could not decode embedded tray icon: {error}"))?;
    if info.color_type != ColorType::Rgba || info.bit_depth != BitDepth::Eight {
        return Err("embedded tray icon must be an 8-bit RGBA PNG".to_owned());
    }
    rgba.truncate(info.buffer_size());
    let color = match status {
        TrayStatus::Locked => LOCKED_COLOR,
        TrayStatus::Unlocked => UNLOCKED_COLOR,
    };
    for pixel in rgba.as_chunks_mut::<4>().0 {
        if pixel[3] != 0 {
            pixel[..3].copy_from_slice(&color);
        }
    }
    if status == TrayStatus::Locked {
        draw_slash(&mut rgba, info.width as usize);
    }
    Ok((rgba, info.width, info.height))
}

fn draw_slash(rgba: &mut [u8], width: usize) {
    let end = width as f32 - SLASH_INSET;
    let radius = SLASH_WIDTH / 2.;
    for (index, pixel) in rgba.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        // Distance from the pixel's center to the slash. Edges fade over one pixel.
        let x = (index % width) as f32 + 0.5;
        let y = (index / width) as f32 + 0.5;
        let along = ((x + y) / 2.).clamp(SLASH_INSET, end);
        let distance = (x - along).hypot(y - along);
        let coverage = (radius + 0.5 - distance).clamp(0., 1.);
        if coverage > 0. {
            pixel[..3].copy_from_slice(&UNLOCKED_COLOR);
            pixel[3] = (coverage * 255.).round() as u8;
        } else {
            let kept = (distance - radius - SLASH_GAP + 0.5).clamp(0., 1.);
            pixel[3] = (f32::from(pixel[3]) * kept).round() as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TrayStatus, decode_tray_icon};

    fn pixel(rgba: &[u8], x: usize, y: usize) -> [u8; 4] {
        rgba.as_chunks::<4>().0[y * 44 + x]
    }

    #[test]
    fn embeds_the_original_typescript_tray_icon_shape() {
        let (rgba, width, height) =
            decode_tray_icon(TrayStatus::Locked).expect("tray icon should decode");

        assert_eq!((width, height), (44, 44));
        assert_eq!(rgba.len(), 44 * 44 * 4);
    }

    #[test]
    fn uses_gray_locked_and_light_unlocked_pixels() {
        let (locked, _, _) = decode_tray_icon(TrayStatus::Locked).unwrap();
        let (unlocked, _, _) = decode_tray_icon(TrayStatus::Unlocked).unwrap();

        // A pixel on the logo's top edge, away from the slash.
        assert_eq!(pixel(&locked, 22, 5), [142, 142, 147, 255]);
        assert_eq!(pixel(&unlocked, 22, 5), [235, 235, 240, 255]);
    }

    #[test]
    fn crosses_out_only_the_locked_icon() {
        let (locked, _, _) = decode_tray_icon(TrayStatus::Locked).unwrap();
        let (unlocked, _, _) = decode_tray_icon(TrayStatus::Unlocked).unwrap();

        // The slash crosses the empty space inside the logo in the unlocked color...
        assert_eq!(pixel(&unlocked, 14, 14)[3], 0);
        assert_eq!(pixel(&locked, 14, 14), [235, 235, 240, 255]);
        // ...and clears the keyhole beside it.
        assert_eq!(pixel(&unlocked, 19, 15)[3], 255);
        assert_eq!(pixel(&locked, 19, 15)[3], 0);
    }
}
