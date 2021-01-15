/*
 * Copyright 2018-2021 Cargill Incorporated
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

//! Provides an API to retrieve private keys.
//!
//! Some tests in this module are run serially using the `serial_test` crate with the
//! `#[serial(env_var)]` annotation added to the individual tests. This is required because
//! multiple tests alter the same environment variables and may conflict with each other if
//! run in parallel.
//!
//! Cylinder key load is guarded by the feature "key-load".
//!
//! # Example
//!
//! ## Retrieving a private key from a given path
//!
//! ```
//! use std::path::Path;
//! use cylinder::{load_key, load_key_from_path};
//!
//! let private_key_path = Path::new("/etc/splinter/keys/private_key.priv");
//! let private_key = load_key_from_path(&private_key_path);
//! ```
//!
//! ## Load private key from `current_user_search_path()` and `current_user_key_name()`
//!
//! ```
//! use std::path::Path;
//! use cylinder::{load_key, load_key_from_path, current_user_key_name, current_user_search_path};
//!
//! let search_path = current_user_search_path();
//! let key_name = current_user_key_name();
//!
//! let private_key = cylinder::load_key(&key_name, &search_path);
//! ```
//!
//! ## Load private key from a given path and name
//!
//! ```
//! use std::path::{Path, PathBuf};
//! use cylinder::{load_key, load_key_from_path};
//!
//! let mut path = PathBuf::new();
//! path.push("/etc/splinter/keys");
//!
//! let search_path = vec![path];
//! let key_name = "splinterd";
//!
//! let private_key = cylinder::load_key(key_name, &search_path);
//!  ```

use std::env;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use crate::error::KeyLoadError;
use crate::PrivateKey;

/// Returns a list of possible paths to search for the private key file.
/// The value of the `CYLINDER_PATH` environment variable will returned if it exists
/// and is valid unicode. If the value of the `CYLINDER_PATH` environment variable
/// is not valid unicode or is not set, the default path will be returned.
pub fn current_user_search_path() -> Vec<PathBuf> {
    match env::var("CYLINDER_PATH") {
        Ok(value) => value
            .split(':')
            .map(|s| Path::new(s).to_path_buf())
            .collect(),
        Err(env::VarError::NotUnicode(_)) => {
            let mut dir = match dirs::home_dir() {
                Some(dir) => dir,
                None => Path::new(".").to_path_buf(),
            };
            dir.push(".cylinder");
            dir.push("keys");
            warn!(
                "Value for CYLINDER_PATH is not unicode, unable to parse path, using default {:?}",
                dir
            );
            vec![dir]
        }
        Err(env::VarError::NotPresent) => {
            let mut dir = match dirs::home_dir() {
                Some(dir) => dir,
                None => Path::new(".").to_path_buf(),
            };
            dir.push(".cylinder");
            dir.push("keys");
            vec![dir]
        }
    }
}

/// Returns the name of the current private key file. The value of the
/// `CYLINDER_KEY_NAME` environment variable will be returned if it exists and
/// is valid unicode. If the value of the `CYLINDER_KEY_NAME` environment variable
/// is not valid unicode or is not set, the default path will be returned.
pub fn current_user_key_name() -> String {
    match env::var("CYLINDER_KEY_NAME") {
        Ok(value) => value,
        Err(env::VarError::NotUnicode(_)) => {
            let key_name = whoami::username();
            warn!(
                "Value for CYLINDER_KEY_NAME is not unicode, using default {:?}",
                key_name
            );
            key_name
        }
        Err(env::VarError::NotPresent) => whoami::username(),
    }
}

/// Returns the private key from the given name and search path.
///
/// # Arguments
///
/// * `name` - The name of the private key file
/// * `search_path` - The private key file path
///
/// Returns an error in any of the following cases:
/// * The given file cannot be opened
/// * The key cannot be loaded from the given file
pub fn load_key(name: &str, search_path: &[PathBuf]) -> Result<Option<PrivateKey>, KeyLoadError> {
    match search_path.iter().find_map(|path| {
        let mut key_path = path.clone();
        key_path.push(name);
        key_path.set_extension("priv");

        if key_path.exists() && key_path.is_file() {
            match File::open(key_path) {
                Ok(f) => Some(Ok(f)),
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => None,
                    _ => Some(Err(e)),
                },
            }
        } else {
            None
        }
    }) {
        Some(Ok(file)) => match load_key_from_file(file) {
            Ok(key) => Ok(Some(key)),
            Err(e) => Err(e),
        },
        Some(Err(err)) => Err(KeyLoadError::with_source(
            Box::new(err),
            "Unable to retrieve key",
        )),
        None => Ok(None),
    }
}

/// Returns the private key from the given path.
///
/// # Arguments
///
/// * `path` - The full path of the private key file
///
/// Returns an error in any of the following cases:
/// * The given file cannot be opened
/// * `load_key_from_file` cannot retrieve the key from the file
pub fn load_key_from_path(path: &Path) -> Result<PrivateKey, KeyLoadError> {
    match File::open(&path) {
        Ok(f) => match load_key_from_file(f) {
            Ok(key) => Ok(key),
            Err(e) => Err(KeyLoadError::with_source(
                Box::new(e),
                &format!("Unable to load key from path: {:?}", path),
            )),
        },
        Err(err) => Err(KeyLoadError::with_source(
            Box::new(err),
            &format!("Unable to open key file: {:?}", path),
        )),
    }
}

/// Returns the private key from the given file.
///
/// # Arguments
///
/// * `file` - The open key file
///
/// Returns an error in any of the following cases:
/// * The given file cannot be read
/// * The file is empty
/// * The hex string read from the file cannot be converted into the private key
fn load_key_from_file(file: File) -> Result<PrivateKey, KeyLoadError> {
    let mut key_file = file;

    let mut buf = String::new();
    key_file
        .read_to_string(&mut buf)
        .map_err(|err| KeyLoadError::with_source(Box::new(err), "Unable to read key file"))?;
    let key = match buf.lines().next() {
        Some(k) => k.trim().to_string(),
        None => {
            return Err(KeyLoadError::new(&format!(
                "Empty key file: {:?}",
                key_file
            )));
        }
    };

    Ok(PrivateKey::new_from_hex(&key).map_err(|err| {
        KeyLoadError::with_source(Box::new(err), "unable to create private key from hex: {}")
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey;

    use serial_test::serial;
    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    /// Tests that when `load_key` is called with a valid key name and path it successfully returns the
    /// private key.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Call `load_key` with the private key file name and path
    /// 3. Ensure the private key is returned.
    #[test]
    fn load_key_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key("test_key", &[temp_dir.path().to_path_buf()])
            .expect("Unable retrieve key from file");

        assert_eq!(
            retrieved_private_key.unwrap().into_bytes(),
            private_key.into_bytes(),
        );
    }

    /// Tests that when the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables are set
    /// with the key name a path, `key_load` will successfully retrieve the private key if passed
    /// current_user_key_name() and current_user_search_path() as arguments.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Set the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables to the name and path
    ///    of the key file.
    /// 3. Ensure the environment variables were set correctly.
    /// 4. Call `load_key` with current_user_key_name() and current_user_search_path() as arguments.
    /// 5. Ensure the private key is returned.
    #[test]
    #[serial(env_var)]
    fn load_key_env_var_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let path_value = temp_dir.path().to_str().expect("failed to make path value");

        let env_key_name = "CYLINDER_KEY_NAME";
        let env_key_path = "CYLINDER_PATH";
        env::set_var(env_key_name, "test_key");
        env::set_var(env_key_path, path_value);
        assert_eq!(env::var("CYLINDER_KEY_NAME"), Ok("test_key".to_string()));
        assert_eq!(env::var("CYLINDER_PATH"), Ok(path_value.to_string()));

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key(&current_user_key_name(), &current_user_search_path())
            .expect("Unable retrieve key from file");

        assert_eq!(
            retrieved_private_key.unwrap().into_bytes(),
            private_key.into_bytes()
        );

        env::remove_var("CYLINDER_KEY_NAME");
        env::remove_var("CYLINDER_PATH");
        assert!(env::var("CYLINDER_KEY_NAME").is_err());
        assert!(env::var("CYLINDER_PATH").is_err());
    }

    /// Tests that when the CYLINDER_PATH environment variable is set with multiple paths,
    /// `key_load` will successfully retrieve the private key if passed
    /// current_user_key_name() and current_user_search_path() as arguments.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Set the CYLINDER_KEY_NAME env variable to the name of the private key file.
    /// 3. Set the CYLINDER_PATH env variable to be two different file paths, the second
    ///    being the correct path.
    /// 3. Ensure the environment variables were set correctly.
    /// 4. Call `load_key` with current_user_key_name() and current_user_search_path() as arguments.
    /// 5. Ensure the private key is returned.
    #[test]
    #[serial(env_var)]
    fn load_key_env_var_multiple_paths_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let path_value = temp_dir.path().to_str().expect("failed to make path value");

        let paths = format!("test_key/keys/:{}", path_value);

        let env_key_name = "CYLINDER_KEY_NAME";
        let env_key_path = "CYLINDER_PATH";
        env::set_var(env_key_name, "test_key");
        env::set_var(env_key_path, paths.clone());
        assert_eq!(env::var("CYLINDER_KEY_NAME"), Ok("test_key".to_string()));
        assert_eq!(env::var("CYLINDER_PATH"), Ok(paths.to_string()));

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key(&current_user_key_name(), &current_user_search_path())
            .expect("Unable retrieve key from file");

        assert_eq!(
            retrieved_private_key.unwrap().into_bytes(),
            private_key.into_bytes()
        );

        env::remove_var("CYLINDER_KEY_NAME");
        env::remove_var("CYLINDER_PATH");
        assert!(env::var("CYLINDER_KEY_NAME").is_err());
        assert!(env::var("CYLINDER_PATH").is_err());
    }

    /// Tests that when the CYLINDER_PATH environment variable is set with nonexisistant paths, and
    /// no key file exists in the default location `key_load` will return None when passed
    /// current_user_key_name() and current_user_search_path() as arguments.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Set the CYLINDER_KEY_NAME env variable to the name of the private key file.
    /// 3. Set the CYLINDER_PATH env variable to be two different incorrect file paths.
    /// 3. Ensure the environment variables were set correctly.
    /// 4. Call `load_key` with current_user_key_name() and current_user_search_path() as arguments.
    /// 5. Ensure None is returned.
    #[test]
    #[serial(env_var)]
    fn load_key_env_var_bad_paths_none() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let paths = "test_key/keys/:bad_path/keys";

        let env_key_name = "CYLINDER_KEY_NAME";
        let env_key_path = "CYLINDER_PATH";
        env::set_var(env_key_name, "test_key");
        env::set_var(env_key_path, paths.clone());
        assert_eq!(env::var("CYLINDER_KEY_NAME"), Ok("test_key".to_string()));
        assert_eq!(env::var("CYLINDER_PATH"), Ok(paths.to_string()));

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key(&current_user_key_name(), &current_user_search_path())
            .expect("Unable retrieve key from file");

        assert!(retrieved_private_key.is_none());

        env::remove_var("CYLINDER_KEY_NAME");
        env::remove_var("CYLINDER_PATH");
        assert!(env::var("CYLINDER_KEY_NAME").is_err());
        assert!(env::var("CYLINDER_PATH").is_err());
    }

    /// Tests that when the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables are not set
    /// and a private key file does not exist at the default location `key_load` will return None
    /// when passed current_user_key_name() and current_user_search_path() as arguments.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Remove the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables.
    /// 3. Ensure the environment variables don't exist.
    /// 4. Call `load_key` with current_user_key_name() and current_user_search_path() as arguments.
    /// 5. Ensure that None is returned.
    #[test]
    #[serial(env_var)]
    fn load_key_none_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        env::remove_var("CYLINDER_KEY_NAME");
        env::remove_var("CYLINDER_PATH");
        assert!(env::var("CYLINDER_KEY_NAME").is_err());
        assert!(env::var("CYLINDER_PATH").is_err());

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key(&current_user_key_name(), &current_user_search_path())
            .expect("Unable retrieve key from file");

        assert!(retrieved_private_key.is_none());
    }

    /// Tests that when the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables are not set
    /// and a private key file exists at the default location, `key_load` will successfully
    /// return the private key stored at the default location when passed current_user_key_name()
    /// and current_user_search_path() as arguments.
    ///
    /// 1. Create a temporary directory and set it to be the home directory.
    /// 2. Build the default private key file path `$HOME/.cylinder/keys/<username>.priv`.
    /// 3. Unset the CYLINDER_KEY_NAME and CYLINDER_PATH environment variables.
    /// 4. Ensure the environment variables are not set.
    /// 5. Call `load_key` with current_user_key_name() and current_user_search_path() as arguments.
    /// 6. Reset the home directory to its original value.
    /// 7. Ensure the private key is returned.
    #[test]
    #[serial(env_var)]
    fn load_key_default_path_success() {
        let original_home = std::env::var("HOME").expect("failed to get original home dir");

        let temp_home = TempDir::new("test_key_dir").expect("Failed to create temp dir");
        std::env::set_var("HOME", temp_home.path());

        let mut temp_path = temp_home.path().to_path_buf();

        temp_path.push(".cylinder");
        temp_path.push("keys");

        std::fs::create_dir_all(temp_path.clone()).expect("Unable to create key directory");

        let key_file = format!("{}.priv", whoami::username());

        env::remove_var("CYLINDER_KEY_NAME");
        env::remove_var("CYLINDER_PATH");
        assert!(env::var("CYLINDER_KEY_NAME").is_err());
        assert!(env::var("CYLINDER_PATH").is_err());

        env::set_current_dir(&temp_path).unwrap();

        let mut temp_file = File::create(key_file).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_key(&current_user_key_name(), &current_user_search_path())
            .expect("Unable retrieve key from file");

        std::env::set_var("HOME", original_home);

        assert_eq!(
            retrieved_private_key.unwrap().into_bytes(),
            private_key.into_bytes()
        );
    }

    /// Tests that `load_key_from_path` returns a private key when given the full path to the
    /// private key file.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Call `load_key_from_path` with the private key file path
    /// 3. Ensure the private key is returned.
    #[test]
    fn load_key_from_path_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key =
            load_key_from_path(&key_path).expect("Unable retrieve key from file");

        assert_eq!(retrieved_private_key.into_bytes(), private_key.into_bytes());
    }

    /// Tests that if the given key file is empty, load_key_from_path will fail.
    ///
    /// 1. Create an empty file in a temporary directory.
    /// 2. Call `load_key_from_path` with the file path
    /// 3. Ensure an error is returned.
    #[test]
    fn load_key_from_path_fail_empty_file() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        File::create(&key_path).expect("Unable to create temp private key file");

        assert!(load_key_from_path(&key_path).is_err());
    }

    /// Tests that if a bad file path is given, load_key_from_path will fail.
    ///
    /// 1. Create a private key file in a temporary directory and write a key to the file.
    /// 2. Call `load_key_from_path` with a bad file path
    /// 3. Ensure an error is returned.
    #[test]
    fn load_key_from_path_fail_bad_path() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";

        let key_path = temp_dir.path().join(key_name);

        let bad_path = Path::new("bad_path/keys/bad_file.priv");

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        assert!(load_key_from_path(&bad_path).is_err());
    }
}
