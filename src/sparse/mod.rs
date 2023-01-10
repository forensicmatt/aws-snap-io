#[cfg(any(target_os = "windows"))]
pub mod win;
#[cfg(any(target_os = "linux"))]
pub mod nix;