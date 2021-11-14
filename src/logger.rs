use log::LevelFilter;
use log4rs;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::env;

#[macro_export]
macro_rules! ferror{
    ($val:tt) => {
        log::error!( "{}", $val);
    };
    ($fmt:expr,$($val:expr),*) => {{
        log::error!( "{}", format!($fmt, $($val),*));
    }};
}

#[macro_export]
macro_rules! fwarn{
    ($val:tt) => {
        log::warn!("{}", $val);
    };
    ($fmt:expr,$($val:expr),*) => {{
        log::warn!( "{}", format!($fmt, $($val),*));
    }};
}

#[macro_export]
macro_rules! finfo{
    ($val:tt) => {
        log::info!( "{}", $val);
    };
    ($fmt:expr,$($val:expr),*) => {{
        log::info!("{}", format!($fmt, $($val),*));
    }};
}

#[macro_export]
macro_rules! fdebug {
    () => {
        log::debug!("arrived.");
    };
    ($val:tt) => {
        log::debug!("{}", $val);
    };
    ($fmt:expr,$($val:expr),*) => {{
        log::debug!( "{}", format!($fmt, $($val),*));
    }};
}

pub fn js_logger_init(logf: Option<&str>, level: LevelFilter, detail: bool) {
    if let Some(f) = logf {
        let filelog = match detail {
            true => FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("[{l}] <{t}> {f}:{L}: {m}{n}")))
            .build(f)
            .unwrap(),

            false => FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("[{l}] {m}{n}")))
            .build(f)
            .unwrap(),
        };

        let config = Config::builder()
            .appender(Appender::builder().build("filelog", Box::new(filelog)))
            .build(Root::builder().appender("filelog").build(level))
            .unwrap();

        log4rs::init_config(config).unwrap();

        return;
    } else if let Ok(a) = env::var("LOG4RS_CONFIG") {
        log4rs::init_file(a, Default::default()).unwrap_or(())
    } else {
        let consolelog = match detail {
            true => ConsoleAppender::builder()
                .target(log4rs::append::console::Target::Stderr)
                .encoder(Box::new(PatternEncoder::new("[{l}] <{t}> {f}:{L}: {m}{n}")))
                .build(),

            false => ConsoleAppender::builder()
                .target(log4rs::append::console::Target::Stderr)
                .encoder(Box::new(PatternEncoder::new("[{l}]: {m}{n}")))
                .build(),
        };

        let config = Config::builder()
            .appender(Appender::builder().build("stderr", Box::new(consolelog)))
            .build(Root::builder().appender("stderr").build(level))
            .unwrap();

        log4rs::init_config(config).unwrap();
    }
}
