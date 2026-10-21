use anyhow::Result;

use crate::os_detect;

pub fn run() -> Result<()> {
    let info = os_detect::detect()?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}
