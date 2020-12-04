use crate::{constants::DEBUG_MODE, types::Result};

pub fn check_debug_mode() -> Result<()> {
    match DEBUG_MODE {
        true => {
            info!("✔ Application is in debug mode! Continuing...");
            Ok(())
        },
        false => Err("✘ Application NOT in debug mode - exiting!".into()),
    }
}
