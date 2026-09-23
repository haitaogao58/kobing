#[macro_export]
macro_rules! err {
    { $($arg:tt)+ } => {
        format!("{}:{} {}", file!(), line!(), format_args!($($arg)+))
    };
    {} => {
        format!("{}:{}", file!(), line!())
    };
}

#[macro_export]
macro_rules! root_path {
    () => {
        "/data/surprise/waste"
    };
    ($leaf:literal) => {
        concat!("/data/surprise/waste/", $leaf)
    };
}
