use core::cmp::Ordering;

use crate::{Digest, EmbeddedError, hash_parts};

const EMPTY_TREE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-EMPTY-v1\0";
const LEAF_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-LEAF-v1\0";
const NODE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-NODE-v1\0";
const ODD_NODE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-ODD-v1\0";
const ROOT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-ROOT-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MeasurementKind {
    Firmware = 1,
    Configuration = 2,
    BootState = 3,
    ApplicationData = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub component_id: Digest,
    pub kind: MeasurementKind,
    pub content_digest: Digest,
    pub metadata_digest: Digest,
}

impl Measurement {
    pub const fn new(
        component_id: Digest,
        kind: MeasurementKind,
        content_digest: Digest,
        metadata_digest: Digest,
    ) -> Self {
        Self {
            component_id,
            kind,
            content_digest,
            metadata_digest,
        }
    }

    pub fn leaf_digest(&self) -> Digest {
        hash_parts(&[
            LEAF_DOMAIN,
            &self.component_id,
            &[self.kind as u8],
            &self.content_digest,
            &self.metadata_digest,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementSet<const CAPACITY: usize> {
    entries: [Option<Measurement>; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> Default for MeasurementSet<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> MeasurementSet<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn entries(&self) -> impl Iterator<Item = &Measurement> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }

    pub fn get(&self, component_id: &Digest) -> Option<&Measurement> {
        self.find(component_id)
            .ok()
            .and_then(|index| self.entries[index].as_ref())
    }

    pub fn upsert(
        &mut self,
        measurement: Measurement,
    ) -> Result<Option<Measurement>, EmbeddedError> {
        match self.find(&measurement.component_id) {
            Ok(index) => Ok(self.entries[index].replace(measurement)),
            Err(index) => {
                if self.len == CAPACITY {
                    return Err(EmbeddedError::CapacityExceeded);
                }
                for position in (index..self.len).rev() {
                    self.entries[position + 1] = self.entries[position];
                }
                self.entries[index] = Some(measurement);
                self.len += 1;
                Ok(None)
            }
        }
    }

    pub fn remove(&mut self, component_id: &Digest) -> Result<Measurement, EmbeddedError> {
        let index = self
            .find(component_id)
            .map_err(|_| EmbeddedError::MeasurementNotFound)?;
        let removed = self.entries[index]
            .take()
            .ok_or(EmbeddedError::MeasurementNotFound)?;
        for position in index..self.len - 1 {
            self.entries[position] = self.entries[position + 1];
        }
        self.len -= 1;
        self.entries[self.len] = None;
        Ok(removed)
    }

    pub fn root(&self) -> Digest {
        if self.is_empty() {
            return hash_parts(&[EMPTY_TREE_DOMAIN]);
        }

        let mut layer = [[0u8; 32]; CAPACITY];
        for (index, measurement) in self.entries().enumerate() {
            layer[index] = measurement.leaf_digest();
        }

        let mut width = self.len;
        while width > 1 {
            let mut read = 0;
            let mut write = 0;
            while read < width {
                layer[write] = if read + 1 < width {
                    hash_parts(&[NODE_DOMAIN, &layer[read], &layer[read + 1]])
                } else {
                    hash_parts(&[ODD_NODE_DOMAIN, &layer[read]])
                };
                read += 2;
                write += 1;
            }
            width = write;
        }

        hash_parts(&[ROOT_DOMAIN, &(self.len as u64).to_be_bytes(), &layer[0]])
    }

    fn find(&self, component_id: &Digest) -> Result<usize, usize> {
        let mut left = 0;
        let mut right = self.len;
        while left < right {
            let middle = left + (right - left) / 2;
            let Some(current) = self.entries[middle].as_ref() else {
                return Err(middle);
            };
            match current.component_id.cmp(component_id) {
                Ordering::Less => left = middle + 1,
                Ordering::Greater => right = middle,
                Ordering::Equal => return Ok(middle),
            }
        }
        Err(left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(id: u8, content: u8) -> Measurement {
        Measurement::new([id; 32], MeasurementKind::Firmware, [content; 32], [9; 32])
    }

    #[test]
    fn root_is_order_independent_and_updates_deterministically() {
        let mut first = MeasurementSet::<2>::new();
        first.upsert(measurement(2, 20)).unwrap();
        first.upsert(measurement(1, 10)).unwrap();

        let mut second = MeasurementSet::<2>::new();
        second.upsert(measurement(1, 10)).unwrap();
        second.upsert(measurement(2, 20)).unwrap();
        assert_eq!(first.root(), second.root());

        second.upsert(measurement(1, 11)).unwrap();
        assert_ne!(first.root(), second.root());
    }

    #[test]
    fn capacity_and_removal_fail_closed() {
        let mut set = MeasurementSet::<1>::new();
        set.upsert(measurement(1, 10)).unwrap();
        assert_eq!(
            set.upsert(measurement(2, 20)),
            Err(EmbeddedError::CapacityExceeded)
        );
        assert_eq!(
            set.remove(&[2; 32]),
            Err(EmbeddedError::MeasurementNotFound)
        );
        assert_eq!(set.remove(&[1; 32]).unwrap(), measurement(1, 10));
        assert!(set.is_empty());
    }
}
