//! Search for an Ed25519 `OpenPGP` v4 key whose fingerprint starts with
//! chosen hex digits, then print the finished certificate.
//!
//! Every candidate key is fresh randomness from Sequoia's CSPRNG. The search
//! only varies the key creation timestamp, which changes the fingerprint
//! without making the key weaker or predictable.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::packet::key::{Key4, PrimaryRole, SecretParts, SubordinateRole};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{Key, Signature, UserID};
use openpgp::serialize::Serialize;
use openpgp::types::{
    Curve,
    Features,
    HashAlgorithm,
    KeyFlags,
    ReasonForRevocation,
    SignatureType,
    SymmetricAlgorithm,
};
use openpgp::{Packet, Result, armor};
use sequoia_openpgp as openpgp;
use sha1::digest::generic_array::GenericArray;

const USAGE: &str = "usage: pgp-vanity <hex-prefix> <user-id> <revocation-file> [days]\n\
    Prints the secret certificate to stdout; pipe it into `gpg --import`.";

const SHA1_IV: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];
const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
/// Public-key packet body: version, timestamp, algorithm, OID, 2-byte MPI
/// length, and the 33-byte point (0x40 prefix + 32 bytes).
const BODY_LEN: u8 = 51;

/// Hex digits the fingerprint must start with, as per-word masks.
struct Prefix {
    mask: [u32; 5],
    value: [u32; 5],
    digits: u32,
}

impl Prefix {
    fn parse(hex: &str) -> Option<Self> {
        if hex.is_empty() || hex.len() > 40 {
            return None;
        }
        let (mut mask, mut value) = ([0; 5], [0; 5]);
        for (i, c) in hex.chars().enumerate() {
            let digit = c.to_digit(16)?;
            let shift = 28 - 4 * (i % 8);
            mask[i / 8] |= 0xF << shift;
            value[i / 8] |= digit << shift;
        }
        Some(Self {
            mask,
            value,
            digits: u32::try_from(hex.len()).ok()?,
        })
    }

    fn matches(&self, words: &[u32; 5]) -> bool {
        words
            .iter()
            .zip(self.mask)
            .zip(self.value)
            .all(|((w, m), v)| w & m == v)
    }
}

/// The single SHA-1 block a v4 fingerprint hashes: 0x99, the body length,
/// then the body (RFC 9580 section 5.5.4). Bytes 4..8 hold the timestamp.
fn fingerprint_block(point: &[u8]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..4].copy_from_slice(&[0x99, 0, BODY_LEN, 4]);
    block[8] = 22; // legacy EdDSA, the Ed25519 form GnuPG 2.4 reads
    block[9] = 9;
    block[10..19].copy_from_slice(&ED25519_OID);
    block[19..21].copy_from_slice(&263u16.to_be_bytes());
    block[21..54].copy_from_slice(point);
    block[54] = 0x80;
    block[56..].copy_from_slice(&(54u64 * 8).to_be_bytes());
    block
}

fn fingerprint_words(block: &[u8; 64]) -> [u32; 5] {
    let mut state = SHA1_IV;
    sha1::compress(&mut state, &[*GenericArray::from_slice(block)]);
    state
}

fn eddsa_point<R: openpgp::packet::key::KeyRole>(key: &Key4<SecretParts, R>) -> Result<Vec<u8>> {
    match key.mpis() {
        mpi::PublicKey::EdDSA { q, .. } if q.value().len() == 33 => Ok(q.value().to_vec()),
        other => bail!("expected a legacy EdDSA point, got {other:?}"),
    }
}

fn import_primary(seed: &[u8; 32], created: u32) -> Result<Key4<SecretParts, PrimaryRole>> {
    let time = UNIX_EPOCH + Duration::from_secs(created.into());
    Key4::import_secret_ed25519(seed, time)
}

fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    openpgp::crypto::random(&mut seed)?;
    Ok(seed)
}

/// Check the hand-built fingerprint against Sequoia's before searching.
fn self_test() -> Result<()> {
    let created = 1_700_000_000;
    let key = import_primary(&random_seed()?, created)?;
    let mut block = fingerprint_block(&eddsa_point(&key)?);
    block[4..8].copy_from_slice(&created.to_be_bytes());
    let ours: Vec<u8> = fingerprint_words(&block)
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    ensure!(
        ours == key.fingerprint().as_bytes(),
        "fingerprint computation disagrees with Sequoia"
    );
    Ok(())
}

struct Search<'a> {
    prefix: &'a Prefix,
    newest: u32,
    window: u32,
    found: &'a AtomicBool,
    tries: &'a AtomicU64,
}

impl Search<'_> {
    fn run(&self, tx: &mpsc::Sender<Result<([u8; 32], u32)>>) {
        while !self.found.load(Ordering::Relaxed) {
            match self.one_key() {
                Ok(Some(hit)) => {
                    self.found.store(true, Ordering::Relaxed);
                    let _ = tx.send(Ok(hit));
                }
                Ok(None) => {}
                Err(e) => {
                    self.found.store(true, Ordering::Relaxed);
                    let _ = tx.send(Err(e));
                }
            }
        }
    }

    /// Try every timestamp in the window for one fresh key.
    fn one_key(&self) -> Result<Option<([u8; 32], u32)>> {
        let seed = random_seed()?;
        let mut block = fingerprint_block(&eddsa_point(&import_primary(&seed, self.newest)?)?);
        let mut checked = 0u64;
        for ts in (self.newest - self.window..=self.newest).rev() {
            block[4..8].copy_from_slice(&ts.to_be_bytes());
            if self.prefix.matches(&fingerprint_words(&block)) {
                return Ok(Some((seed, ts)));
            }
            checked += 1;
            if checked.is_multiple_of(1 << 20) {
                self.tries.fetch_add(1 << 20, Ordering::Relaxed);
                if self.found.load(Ordering::Relaxed) {
                    return Ok(None);
                }
            }
        }
        self.tries.fetch_add(checked % (1 << 20), Ordering::Relaxed);
        Ok(None)
    }
}

/// Primary Ed25519 (certify + sign), one Cv25519 encryption subkey, one
/// User ID, plus a revocation certificate for safekeeping.
fn build_cert(seed: &[u8; 32], created: u32, user_id: &str) -> Result<(Cert, Signature)> {
    let now = SystemTime::now();
    let primary: Key<SecretParts, PrimaryRole> = import_primary(seed, created)?.into();
    let mut signer = primary.clone().into_keypair()?;
    let cert = Cert::try_from(vec![Packet::from(primary)])?;

    let uid = UserID::from(user_id);
    let uid_sig = uid.bind(
        &mut signer,
        &cert,
        SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_signature_creation_time(now)?
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
            .set_primary_userid(true)?
            // SEIPDv1 only: GnuPG 2.4 cannot decrypt SEIPDv2 messages.
            .set_features(Features::empty().set_seipdv1())?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?,
    )?;

    let mut sub: Key<SecretParts, SubordinateRole> =
        Key4::generate_ecc(false, Curve::Cv25519)?.into();
    sub.set_creation_time(UNIX_EPOCH + Duration::from_secs(created.into()))?;
    let sub_sig = sub.bind(
        &mut signer,
        &cert,
        SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(now)?
            .set_key_flags(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
            )?,
    )?;

    let (cert, _) = cert.insert_packets(vec![
        Packet::from(uid),
        uid_sig.into(),
        sub.into(),
        sub_sig.into(),
    ])?;
    let revocation = cert.revoke(&mut signer, ReasonForRevocation::Unspecified, b"")?;
    Ok((cert, revocation))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [prefix_hex, user_id, revocation_path, rest @ ..] = args.as_slice() else {
        bail!(USAGE);
    };
    let prefix = Prefix::parse(prefix_hex).context("prefix must be 1-40 hex digits")?;
    let days: u32 = rest
        .first()
        .map_or(Ok(30), |d| d.parse())
        .context("days must be a number")?;

    self_test()?;

    let newest = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let window = days * 86_400;
    let found = AtomicBool::new(false);
    let tries = AtomicU64::new(0);
    let search = Search {
        prefix: &prefix,
        newest,
        window,
        found: &found,
        tries: &tries,
    };
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let expected = 16f64.powi(i32::try_from(prefix.digits)?);
    eprintln!("searching {threads} threads for {prefix_hex}..., ~{expected:.2e} tries expected");

    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    let (seed, created) = std::thread::scope(|scope| {
        for _ in 0..threads {
            let tx = tx.clone();
            let search = &search;
            scope.spawn(move || search.run(&tx));
        }
        loop {
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(hit) => break hit,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    #[allow(clippy::cast_precision_loss)]
                    let done = tries.load(Ordering::Relaxed) as f64;
                    let rate = done / start.elapsed().as_secs_f64();
                    eprintln!(
                        "{:.1e} tries, {:.0} M/s, {:.0}% of expected",
                        done,
                        rate / 1e6,
                        100.0 * done / expected
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(anyhow::anyhow!("all workers stopped"));
                }
            }
        }
    })?;
    eprintln!("found after {:.0?}", start.elapsed());

    let (cert, revocation) = build_cert(&seed, created, user_id)?;
    ensure!(
        prefix.matches(&{
            let fp = cert.fingerprint();
            let b = fp.as_bytes();
            std::array::from_fn(|i| {
                u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
            })
        }),
        "built certificate does not carry the searched fingerprint"
    );

    let mut rev_out = armor::Writer::new(
        std::fs::File::create(revocation_path)?,
        armor::Kind::PublicKey,
    )?;
    Packet::from(revocation).serialize(&mut rev_out)?;
    rev_out.finalize()?;

    cert.as_tsk()
        .armored()
        .serialize(&mut std::io::stdout().lock())?;
    eprintln!("fingerprint {}", cert.fingerprint().to_spaced_hex());
    Ok(())
}
