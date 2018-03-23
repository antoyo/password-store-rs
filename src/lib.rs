/*
 * Copyright (c) 2016 Boucher, Antoni <bouanto@zoho.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#[macro_use]
extern crate json;

mod chomp;

use std::error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::str::{self, Utf8Error};
use std::string;

use json::JsonValue;

use Error::*;
use chomp::Chomp;

macro_rules! validate_path {
    ($path:expr) => {
        if $path.trim().is_empty() {
            return Err(InvalidInput);
        }
    };
}

const MSG_SIZE: usize = 4;

/// `Error` type that can be returned by the `PasswordStore` methods.
#[derive(Debug)]
pub enum Error {
    FromUtf8(string::FromUtf8Error),
    Json(json::Error),
    Io(io::Error),
    InvalidInput,
    InvalidOutput,
    Pass(String),
    Utf8(Utf8Error),
}

impl From<json::Error> for Error {
    fn from(error: json::Error) -> Self {
        Json(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Io(error)
    }
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Self {
        Utf8(error)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Self {
        FromUtf8(error)
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let string =
            match *self {
                FromUtf8(ref error) => error.to_string(),
                Json(ref error) => error.to_string(),
                Io(ref error) => error.to_string(),
                InvalidInput => "invalid input".to_string(),
                InvalidOutput => "invalid output".to_string(),
                Pass(ref error) => error.clone(),
                Utf8(ref error) => error.to_string(),
            };
        write!(formatter, "{}", string)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            FromUtf8(ref error) => error.description(),
            Json(ref error) => error.description(),
            Io(ref error) => error.description(),
            InvalidInput => "invalid input",
            InvalidOutput => "invalid output",
            Pass(ref error) => error,
            Utf8(ref error) => error.description(),
        }
    }
}

/// `Result` type returned by the `PasswordStore` methods.
pub type Result<T> = std::result::Result<T, Error>;

/// `Pass` process runner.
pub struct PasswordStore;

impl PasswordStore {
    /// Get the password a the specified `path`.
    pub fn get(path: &str) -> Result<String> {
        validate_path!(path);
        let mut response = gopass_ipc(object! {
            "type" => "getLogin",
            "entry" => path
        })?;
        if let Some(password) = response["password"].take_string() {
            Ok(password)
        }
        else {
            Err(InvalidOutput)
        }
    }

    /// Get the list of usernames at the specified `path`.
    pub fn get_usernames(path: &str) -> Result<Vec<String>> {
        validate_path!(path);
        let response = gopass_ipc(object! {
            "type" => "query",
            "query" => path
        })?;
        let mut result = vec![];
        match response {
            JsonValue::Array(usernames) => {
                for username in usernames {
                    let username =
                        match username.as_str() {
                            Some(username) => username,
                            None => return Err(InvalidOutput),
                        };
                    let index = username.rfind('/').map(|index| index + 1).unwrap_or(0);
                    result.push(username[index..].to_string());
                }
            },
            _ => return Err(InvalidOutput),
        }
        Ok(result)
    }

    /// Generate a password in the store.
    pub fn generate(path: &str, use_symbols: bool, length: i32) -> Result<()> {
        validate_path!(path);
        let response = gopass_ipc(object! {
            "type" => "create",
            "entry_name" => path,
            "password" => "",
            "generate" => true,
            "length" => length,
            "use_symbols" => use_symbols
        })?;
        if response["username"].as_str().is_none() {
            return Err(InvalidOutput);
        }
        Ok(())
    }

    /// Insert a password in the store.
    pub fn insert(path: &str, password: &str) -> Result<()> {
        validate_path!(path);
        let response = gopass_ipc(object! {
            "type" => "create",
            "entry_name" => path,
            "password" => password
        })?;
        if let Some(inserted_password) = response["password"].as_str() {
            if password != inserted_password {
                return Err(InvalidOutput);
            }
        }
        Ok(())
    }

    /// Remove a password from the store.
    pub fn remove(path: &str) -> Result<()> {
        validate_path!(path);
        exec_pass("rm", &["-f", path])?;
        Ok(())
    }
}

/// Exec the `gopass` process with the specified `command` and `args`.
fn exec_pass<S: AsRef<OsStr>>(command: &str, args: &[S]) -> Result<String> {
    let mut process = Command::new("gopass");
    if !command.trim().is_empty() {
        process.arg(command);
    }
    let child = process.args(args)
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;
    let mut stderr = String::from_utf8(output.stderr)?;
    if !stderr.is_empty() {
        stderr.chomp();
        Err(Pass(stderr))
    }
    else {
        Ok(String::from_utf8(output.stdout)?)
    }
}

/// Query the `gopass` process with a `json_query`.
fn gopass_ipc(json_query: JsonValue) -> Result<JsonValue> {
    let mut process = Command::new("gopass");
    let mut child = process.args(&["jsonapi", "listen"])
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        let json_string = json_query.dump();
        stdin.write_all(&i32_to_bytes(json_string.len() as i32))?;
        write!(stdin, "{}", json_string)?;
    }
    let output = child.wait_with_output()?;
    let mut stderr = String::from_utf8(output.stderr)?;
    if !stderr.is_empty() {
        stderr.chomp();
        Err(Pass(stderr))
    }
    else {
        json::parse(str::from_utf8(&output.stdout[MSG_SIZE..])?) // Skip the size of the json message.
            .map_err(Into::into)
    }
}

fn i32_to_bytes(num: i32) -> Vec<u8> {
    vec![
        (num & 0xFF) as u8,
        ((num >> 8) & 0xFF) as u8,
        ((num >> 16) & 0xFF) as u8,
        ((num >> 24) & 0xFF) as u8,
    ]
}
