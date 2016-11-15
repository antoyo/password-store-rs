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

extern crate chomp_nl;

use std::error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::string;

use chomp_nl::ChompInPlace;

use Error::*;

macro_rules! validate_path {
    ($path:expr) => {
        if $path.trim().is_empty() {
            return Err(InvalidInput);
        }
    };
}

/// `Error` type that can be returned by the `PasswordStore` methods.
#[derive(Debug)]
pub enum Error {
    FromUtf8(string::FromUtf8Error),
    Io(io::Error),
    InvalidInput,
    Pass(String),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Io(error)
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
                Io(ref error) => error.to_string(),
                InvalidInput => "invalid input".to_string(),
                Pass(ref error) => error.clone(),
            };
        write!(formatter, "{}", string)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            FromUtf8(ref error) => error.description(),
            Io(ref error) => error.description(),
            InvalidInput => "invalid input",
            Pass(ref error) => error,
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
        let mut password = exec_pass("", &[path], None)?;
        password.chomp();
        Ok(password)
    }

    /// Insert a password in the store.
    pub fn insert(path: &str, password: &str) -> Result<()> {
        validate_path!(path);
        exec_pass("insert", &["-m", path], Some(password))?;
        Ok(())
    }

    /// Remove a password from the store.
    pub fn remove(path: &str) -> Result<()> {
        validate_path!(path);
        exec_pass("rm", &["-f", path], None)?;
        Ok(())
    }
}

/// Exec the `pass` process with the specified `command` and `args`.
fn exec_pass<S: AsRef<OsStr>>(command: &str, args: &[S], input: Option<&str>) -> Result<String> {
    let mut process = Command::new("pass");
    if !command.trim().is_empty() {
        process.arg(command);
    }
    let mut child = process.args(args)
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let (Some(stdin), Some(input)) = (child.stdin.as_mut(), input) {
        write!(stdin, "{}\n", input)?;
    }
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
