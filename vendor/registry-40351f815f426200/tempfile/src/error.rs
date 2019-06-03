use std::path::PathBuf;
use std::{error, fmt, io};

#[derive(Debug)]
struct PathError {
    path: PathBuf,
    err: io::Error,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} at path {:?}", self.err, self.path)
    }
}

impl error::Error for PathError {
    fn description(&self) -> &str {
        self.err.description()
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&error::Error> {
        self.err.cause()
    }
}

pub(crate) trait IoResultExt<T> {
    fn with_err_path<F, P>(self, path: F) -> Self
    where
        F: FnOnce() -> P,
        P: Into<PathBuf>;
}

impl<T> IoResultExt<T> for Result<T, io::Error> {
    fn with_err_path<F, P>(self, path: F) -> Self
    where
        F: FnOnce() -> P,
        P: Into<PathBuf>,
    {
        self.map_err(|e| {
            io::Error::new(
                e.kind(),
                PathError {
                    path: path().into(),
                    err: e,
                },
            )
        })
    }
}
