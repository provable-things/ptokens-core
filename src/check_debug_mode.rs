use crate::{
    types::Result,
    errors::AppError,
    constants::DEBUG_MODE,
};

pub fn check_debug_mode() -> Result<()> {
    match DEBUG_MODE {
        true => {
            info!("✔ Application is in debug mode! Continuing...");
            Ok(())
        }
        false => {
            Err(AppError::Custom(
                "✘ Application NOT in debug mode - exiting!".to_string()
            ))
        }
    }
}
