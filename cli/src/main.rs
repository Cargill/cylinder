/*
 * Copyright 2021 Cargill Incorporated
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

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

mod error;

use std::env;
use std::path::Path;

use cylinder::jwt::JsonWebTokenBuilder;
use cylinder::secp256k1::Secp256k1Context;
use cylinder::{
    current_user_key_name, current_user_search_path, load_key, load_key_from_path, Context,
    PrivateKey,
};
use flexi_logger::{LogSpecBuilder, Logger};

use error::CliError;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = clap_app!(myapp =>
        (name: APP_NAME)
        (version: VERSION)
        (author: "Cargill")
        (about: "Cylinder CLI")
        (@arg verbose: -v +multiple +global "Log verbosely")
        (@arg quiet: -q --quiet +global "Do not display output")
        (@setting SubcommandRequiredElseHelp)

        (@subcommand jwt =>
            (about: "Subcommands for generating and examining Cylinder JSON web tokens")
            (@setting SubcommandRequiredElseHelp)
            (@subcommand generate =>
            (about: "Generates a JWT for a given private key")
             (@arg private_key_file: -k --key +takes_value
                        "Name or path of private key")
            )
        )

    )
    .get_matches();

    // set default to info
    let log_level = if matches.is_present("quiet") {
        log::LevelFilter::Error
    } else {
        match matches.occurrences_of("verbose") {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    };

    let log_spec = LogSpecBuilder::new().default(log_level).build();

    match Logger::with(log_spec)
        .format(log_format)
        .log_to_stdout()
        .start()
    {
        Ok(_) => {}
        #[cfg(test)]
        // `FlexiLoggerError::Log` means the logger has already been initialized; this will happen
        // when `run` is called more than once in the tests.
        Err(flexi_logger::FlexiLoggerError::Log(_)) => {}
        Err(err) => panic!("Failed to start logger: {}", err),
    }

    let res = match matches.subcommand() {
        ("jwt", Some(matches)) => handle_jwt_subcommands(matches),
        // Clap will have caught any unrecognized subcommands
        (_, _) => unreachable!(),
    };

    if let Err(err) = res {
        error!("{}", err);
    }
}

fn handle_jwt_subcommands(matches: &clap::ArgMatches) -> Result<(), CliError> {
    match matches.subcommand() {
        ("generate", Some(matches)) => handle_jwt_generate(matches),
        // Clap will have caught any unrecognized subcommands
        (_, _) => unreachable!(),
    }
}

fn handle_jwt_generate(matches: &clap::ArgMatches) -> Result<(), CliError> {
    let key_name = matches.value_of("private_key_file");

    let private_key = load_private_key(key_name)?;

    let context = Secp256k1Context::new();
    let signer = context.new_signer(private_key);

    let encoded_token = JsonWebTokenBuilder::new().build(&*signer).map_err(|err| {
        CliError::from_source_with_message(Box::new(err), "failed to build json web token".into())
    })?;

    info!("{}", encoded_token);

    Ok(())
}

fn load_private_key(key_name: Option<&str>) -> Result<PrivateKey, CliError> {
    if let Some(key_name) = key_name {
        if key_name.contains('/') {
            return load_key_from_path(Path::new(key_name))
                .map_err(|err| CliError::from_source(Box::new(err)));
        }
    }

    load_key(
        &key_name
            .map(String::from)
            .unwrap_or_else(current_user_key_name),
        &current_user_search_path(),
    )
    .map_err(|err| CliError::from_source(Box::new(err)))?
    .ok_or_else(|| {
        CliError::with_message({
            format!(
                "No signing key found in {}. Specify a valid key with the --key argument",
                current_user_search_path()
                    .iter()
                    .map(|path| path.as_path().display().to_string())
                    .collect::<Vec<String>>()
                    .join(":")
            )
        })
    })
}

pub fn log_format(
    w: &mut dyn std::io::Write,
    _now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
) -> Result<(), std::io::Error> {
    write!(w, "{}", record.args(),)
}
