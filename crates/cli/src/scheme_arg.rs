use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SchemeArg {
    Ed25519,
    Secp256k1,
    Eip191,
    Falcon512,
    Hawk512,
}
