/*
 * Copyright 2018-2020 Cargill Incorporated
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

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::error::KeyLoadError;
use crate::PrivateKey;

// determines the key name and path of the private key file
pub fn load_user_key(
    key_name: Option<&str>,
    default_path: &str,
) -> Result<PrivateKey, KeyLoadError> {
    let name: String = match key_name {
        Some(name) => String::from(name),
        None => {
            if let Ok(user) = env::var("USER") {
                user
            } else {
                whoami::username()
            }
        }
    };

    // if the default path is an environment variable retrieve its value
    let key_path = match env::var(&default_path) {
        Ok(path) => path,
        Err(_) => default_path.to_string(),
    };

    // check if the key name is a path
    if name.contains('/') {
        Ok(load_key_file(None, &name)?)
    } else {
        // if the key name is not a path check to see if it is an environment variable
        let name = match env::var(&name) {
            Ok(val) => val,
            Err(_) => name,
        };
        // if key_path contains multiple paths check each path
        if key_path.contains(':') {
            let paths = key_path.split(':');
            for path in paths {
                match load_key_file(Some(name.clone()), &path) {
                    Ok(key) => return Ok(key),
                    Err(_) => continue,
                }
            }
            Err(KeyLoadError(format!(
                "Failed to find key file in {}",
                &key_path
            )))
        } else {
            Ok(load_key_file(Some(name), &key_path)?)
        }
    }
}

// constructs the full path of the private key file
fn load_key_file(key_name: Option<String>, key_path: &str) -> Result<PrivateKey, KeyLoadError> {
    let mut path = PathBuf::from(key_path);
    if let Some(key_name) = key_name {
        path.push(key_name);
    }
    if path.exists() {
        read_private_key(path)
    } else {
        path.set_extension("priv");
        if path.exists() {
            read_private_key(path)
        } else {
            Err(KeyLoadError(format!(
                "Failed to load key: could not be found {}",
                path.as_path().display()
            )))
        }
    }
}

// Reads a private key from the given path
fn read_private_key(path: PathBuf) -> Result<PrivateKey, KeyLoadError> {
    let mut file = File::open(&path).map_err(|err| {
        KeyLoadError(format!(
            "Unable to open key file '{}': {}",
            path.display(),
            err,
        ))
    })?;

    let mut buf = String::new();
    file.read_to_string(&mut buf).map_err(|err| {
        KeyLoadError(format!(
            "Unable to read key file '{}': {}",
            path.display(),
            err,
        ))
    })?;
    let key = match buf.lines().next() {
        Some(k) => k.trim().to_string(),
        None => {
            return Err(KeyLoadError(format!("Empty key file: {}", path.display())));
        }
    };

    Ok(PrivateKey::new_from_hex(&key)
        .map_err(|err| KeyLoadError(format!("unable to create private key from hex: {}", err)))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey;

    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    // tests that when an existing key name and default path are given load_user_key returns the
    // private key
    #[test]
    fn retrieve_key_success() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";
        let default_path = temp_dir
            .path()
            .to_str()
            .expect("Failed to get default path");

        let key_path = temp_dir
            .path()
            .join(key_name)
            .to_str()
            .expect("Failed to get path")
            .to_string();

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key =
            load_user_key(Some(key_name), default_path).expect("Unable retrieve key from file");

        assert_eq!(retrieved_private_key.into_bytes(), private_key.into_bytes(),);
    }

    // tests that when no key name is given and the USER environment variable is set the value of
    // the user environment variable will be used as the key_name and load_user_key returns the
    // private key successfully
    #[test]
    fn retrieve_key_success_no_keyname() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key = "USER";
        env::set_var(key, "test_user");
        assert_eq!(env::var("USER"), Ok("test_user".to_string()));

        let default_path = temp_dir
            .path()
            .to_str()
            .expect("Failed to get default path");

        let key_path = temp_dir
            .path()
            .join("test_user.priv")
            .to_str()
            .expect("Failed to get path")
            .to_string();

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key =
            load_user_key(None, default_path).expect("Unable retrieve key from file");

        assert_eq!(retrieved_private_key.into_bytes(), private_key.into_bytes(),);
    }

    // tests that when an environment variable is given as the default path load_user_key
    // successfully returns the private key
    #[test]
    fn retrieve_key_success_environment_var() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";
        let default_path = temp_dir
            .path()
            .to_str()
            .expect("Failed to get default path");

        let key_path = temp_dir
            .path()
            .join(key_name)
            .to_str()
            .expect("Failed to get path")
            .to_string();

        let key = "TEST_KEY_PATH";
        env::set_var(key, default_path);
        assert_eq!(env::var("TEST_KEY_PATH"), Ok(default_path.to_string()));

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key =
            load_user_key(Some(key_name), "TEST_KEY_PATH").expect("Unable retrieve key from file");

        assert_eq!(retrieved_private_key.into_bytes(), private_key.into_bytes(),);
    }

    // tests that when an environment variable is given as the default path and
    // it contains multiple paths load_user_key uses the correct path and successfully
    // returns the private key
    #[test]
    fn retrieve_key_success_environment_var2() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";
        let default_path = temp_dir
            .path()
            .to_str()
            .expect("Failed to get default path");

        let key_path = temp_dir
            .path()
            .join(key_name)
            .to_str()
            .expect("Failed to get path")
            .to_string();

        let paths = format!("test_key/keys:{}", default_path);
        let key = "TEST_PATH_MULTIPLE";
        env::set_var(key, paths.clone());
        assert_eq!(
            env::var("TEST_PATH_MULTIPLE"),
            Ok(paths.clone().to_string())
        );

        let mut temp_file =
            File::create(&key_path).expect("Unable to create temp private key file");

        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        writeln!(temp_file, "{}", private_key.as_hex())
            .expect("Unable to write private key to file");

        let retrieved_private_key = load_user_key(Some(key_name), "TEST_PATH_MULTIPLE")
            .expect("Unable retrieve key from file");

        assert_eq!(retrieved_private_key.into_bytes(), private_key.into_bytes(),);
    }

    // tests that if the given file with the given key name is empty load_user_key will fail
    #[test]
    fn retrieve_key_fail_empty_file() {
        let temp_dir = TempDir::new("test_key_dir").expect("Failed to create temp dir");

        let key_name = "test_key.priv";
        let default_path = temp_dir
            .path()
            .to_str()
            .expect("Failed to get default path");

        let key_path = temp_dir
            .path()
            .join(key_name)
            .to_str()
            .expect("Failed to get path")
            .to_string();

        File::create(&key_path).expect("Unable to create temp private key file");

        assert!(load_user_key(Some(key_name), default_path).is_err());
    }
}
