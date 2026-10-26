//! Rebuild when migrations change, since `sqlx::migrate!` embeds them.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
