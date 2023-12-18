use clap::{Parser, Subcommand};
use clevis_pin_tpm2::tpm_objects::TPM2Config;
use color_eyre::eyre::{bail, eyre, WrapErr};
use std::env;
use std::fs::{read_to_string, File};
use std::io::{stdin, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::exit;

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

#[derive(Debug, PartialEq, Eq)]
enum ControlResult {
    Ok = 0,
    Denied = 1,
    Failed = 2,
    NoDaemon = 3,
}

impl ControlResult {
    fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        let num = u32::from_be_bytes(bytes);
        match num {
            0 => Some(Self::Ok),
            1 => Some(Self::Denied),
            3 => Some(Self::NoDaemon),
            _ => None,
        }
    }
}

fn unlock_keyring(password: &[u8]) -> color_eyre::Result<ControlResult> {
    let socket = get_control_socket()
        .ok_or_else(|| eyre!("Could not find gnome keyring control socket path"))?;
    let mut stream = UnixStream::connect(socket)
        .wrap_err("Could not connect to the gnome keyring unix socket")?;

    stream
        .write_all(&[0])
        .wrap_err("could not write credential byte")?;

    // oplen is
    // 8 = packet size + op code
    // 4 size of length of pw byte
    let oplen: u32 = 8 + 4 + password.len() as u32;

    // write length
    stream
        .write_all(&oplen.to_be_bytes())
        .wrap_err("could not write oplen")?;

    // write unlock
    stream
        .write_all(&ControlOp::Unlock.to_bytes())
        .wrap_err("could not write unlock")?;

    // write pw len
    stream
        .write_all(&(password.len() as u32).to_be_bytes())
        .wrap_err("could not write password length")?;

    stream.write_all(password).wrap_err("writing pass failed")?;

    let mut buf = [0; 4];
    stream
        .read_exact(&mut buf)
        .wrap_err("could not read response length")?;

    let len = u32::from_be_bytes(buf);
    if len != 8 {
        bail!("invalid response length");
    }

    stream
        .read_exact(&mut buf)
        .wrap_err("could not read response")?;

    let code = ControlResult::from_bytes(buf).ok_or_else(|| eyre!("invalid control result"))?;

    Ok(code)
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Unlock,
    Enroll,
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();
    let cli = Cli::parse();

    match cli.command {
        Commands::Unlock => {
            let file = PathBuf::from("/home/vivian/.config/gnome_password.token");
            if file.exists() {
                let token = read_to_string(file)?;
                let password = clevis_pin_tpm2::perform_decrypt(token.as_bytes())
                    .map_err(|err| eyre!("{err:?}"))?;
                let res = unlock_keyring(password.as_slice())?;
                if res != ControlResult::Ok {
                    eprintln!("Failed to unlock keyring: {res:?}");
                    exit(2);
                }
            } else {
                bail!("password token file not found")
            }
            println!("Unlocked keyring successfully")
        }
        Commands::Enroll => {
            let password = rpassword::prompt_password("Password: ")?;

            if unlock_keyring(password.as_bytes())? != ControlResult::Ok {
                eprintln!("invalid password");
                exit(3);
            }

            let token =
                clevis_pin_tpm2::perform_encrypt(TPM2Config::default(), password.as_bytes())
                    .map_err(|err| eyre!("{err:?}"))?;
            let mut file = File::create("/home/vivian/.config/gnome_password.token")?;
            file.write_all(token.as_bytes())?;
            println!("Password enrolled successfully")
        }
    }

    Ok(())
}
