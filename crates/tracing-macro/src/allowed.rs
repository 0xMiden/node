use syn::Ident;

const ALLOWED_LINES: &str = include_str!("../allowlist.txt");

// TODO add preprocessed list based on line by line extraction from allowlist.txt, use OnceCell or similar, avoid lazy_static!
const X: = ;

struct Suggestions {
    orig: Name,
    ranked: Vec<&'static str>,
}

pub(crate) fn check(which: Name) -> Result<()> {
    todo!()
}
