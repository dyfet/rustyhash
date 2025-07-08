use digest::Digest;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::convert::TryInto;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// Supported hash algorithms
pub enum Algo {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
}

/// Runtime hash wrapper
pub struct Hash {
    algo: Algo,
}

impl Hash {
    pub fn new(algo: Algo) -> Self {
        Self { algo }
    }

    fn compute(&self, input: &str) -> Vec<u8> {
        match self.algo {
            Algo::Sha256 => Sha256::digest(input.as_bytes()).to_vec(),
            Algo::Sha512 => Sha512::digest(input.as_bytes()).to_vec(),
            Algo::Sha3_256 => Sha3_256::digest(input.as_bytes()).to_vec(),
            Algo::Sha3_512 => Sha3_512::digest(input.as_bytes()).to_vec(),
        }
    }

    pub fn to_u64(&self, input: &str) -> u64 {
        let digest = self.compute(input);
        let bytes: [u8; 8] = digest[..8].try_into().expect("Digest too short");
        u64::from_be_bytes(bytes)
    }

    pub fn to_u32(&self, input: &str) -> u32 {
        (self.to_u64(input) & 0xFFFF_FFFF) as u32
    }

    pub fn to_bits(&self, input: &str, bits: u8) -> u64 {
        assert!((1..=64).contains(&bits), "Bits must be 1..=64");
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        self.to_u64(input) & mask
    }
}

/// Distributed ring of dynamic targets that may be added or removed
pub struct Ring64 {
    ring: Arc<RwLock<BTreeMap<u64, String>>>,
    vnodes: u32,
    hasher: Hash,
    size: AtomicUsize,
}

impl Ring64 {
    pub fn new(algo: Algo, vnodes: Option<u32>) -> Self {
        Self {
            ring: Arc::new(RwLock::new(BTreeMap::new())),
            vnodes: vnodes.unwrap_or(100),
            hasher: Hash::new(algo),
            size: AtomicUsize::new(0),
        }
    }

    pub fn size(&self) -> usize {
        self.size.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let ring = self.ring.read().unwrap();
        let hash = self.hasher.to_u64(&key.to_string());
        let mut it = ring.range(hash..).next();
        if it.is_none() {
            it = ring.iter().next();
        }

        it.map(|(_, v)| v.clone())
    }

    pub fn insert(&self, node: &str) -> bool {
        let mut inserted = false;
        let mut ring = self.ring.write().unwrap();
        for i in 0..self.vnodes {
            let vnode = format!("{node}#{i}");
            let index = self.hasher.to_u64(&vnode);
            let success = ring.insert(index, node.to_string()).is_none();
            if success {
                inserted = true;
            }
        }

        if inserted {
            self.size.fetch_add(1, Ordering::Relaxed);
        }
        inserted
    }

    pub fn remove(&self, node: &str) -> bool {
        let mut removed = false;
        let mut ring = self.ring.write().unwrap();
        for i in 0..self.vnodes {
            let vnode = format!("{node}#{i}");
            let index = self.hasher.to_u64(&vnode);
            if let Some(existing) = ring.get(&index) {
                if existing == node {
                    ring.remove(&index);
                    removed = true;
                }
            }
        }

        if removed {
            self.size.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_test() {
        let hasher = Hash::new(Algo::Sha256);
        let h1 = hasher.to_u64("alpha");
        let h2 = hasher.to_u64("beta");
        let h3 = hasher.to_u64("alpha");
        assert_eq!(h1, h3);
        assert_ne!(h1, h2);
    }
}
