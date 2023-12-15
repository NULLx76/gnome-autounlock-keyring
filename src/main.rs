use color_eyre::eyre::{bail, eyre, WrapErr};
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

fn get_control_socket() -> Option<PathBuf> {
    let gnome_var = env::var("GNOME_KEYRING_CONTROL")
        .ok()
        .map(|el| PathBuf::from(el).join("control"))
        .and_then(|el| el.exists().then_some(el));

    let xdg_var = env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|el| PathBuf::from(el).join("keyring").join("control"))
        .and_then(|el| el.exists().then_some(el));

    gnome_var.or(xdg_var)
}

enum ControlOp {
    Initialize = 0,
    Unlock = 1,
    Change = 2,
    Quit = 4,
}

impl ControlOp {
    fn to_bytes(self) -> [u8; 4] {
        (self as u32).to_be_bytes()
    }
}

#[derive(Debug)]
enum ControlResult {
    Ok = 0,
    Denied = 1,
    Failed = 2,
    NoDaemon = 3,
}

impl ControlResult {
    fn from_u32(n: u32) -> Option<ControlResult> {
        match n {
            0 => Some(ControlResult::Ok),
            1 => Some(ControlResult::Denied),
            2 => Some(ControlResult::Failed),
            3 => Some(ControlResult::NoDaemon),
            _ => None,
        }
    }
}

fn unlock_keyring(password: &str) -> color_eyre::Result<ControlResult> {
    let socket = get_control_socket()
        .ok_or_else(|| eyre!("Could not find gnome keyring control socket path"))?;
    let mut stream = UnixStream::connect(socket)
        .wrap_err("Could not connect to the gnome keyring unix socket")?;

    let ret = stream
        .write(&[0])
        .wrap_err("could not write credential byte")?;

    if ret != 1 {
        bail!("writing cred byte failed")
    }

    // oplen is
    // 8 = packet size + op code
    // 4 size of length of pw byte
    let oplen: u32 = 8 + 4 + password.len() as u32;

    // write length
    let ret = stream
        .write(&oplen.to_be_bytes())
        .wrap_err("could not write oplen")?;

    if ret != 4 {
        bail!("writing oplen failed")
    }

    // write unlock
    let ret = stream
        .write(&ControlOp::Unlock.to_bytes())
        .wrap_err("could not write unlock")?;

    if ret != 4 {
        bail!("writing unlock failed")
    }

    // write pw len
    let ret = stream
        .write(&(password.len() as u32).to_be_bytes())
        .wrap_err("could not write password length")?;

    if ret != 4 {
        bail!("writing pwlen failed")
    }

    let mut pw_buf = password.as_bytes();

    while !pw_buf.is_empty() {
        let ret = stream.write(pw_buf).wrap_err("writing password failed")?;
        pw_buf = &pw_buf[ret..]
    }

    let mut buf = [0; 4];
    let val = stream
        .read(&mut buf)
        .wrap_err("could not read response length")?;
    if val != 4 {
        bail!("invalid response length length")
    }

    let len = u32::from_be_bytes(buf);
    if len != 8 {
        bail!("invalid response length");
    }

    let val = stream.read(&mut buf).wrap_err("could not read response")?;
    if val != 4 {
        bail!("invalid response length (2)")
    }

    let resp = u32::from_be_bytes(buf);
    let code = ControlResult::from_u32(resp).ok_or_else(|| eyre!("invalid resp"))?;

    Ok(code)
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();

    let res = unlock_keyring("example")?;

    dbg!(res);

    Ok(())
}
