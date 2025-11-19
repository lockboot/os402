use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;
use thiserror::Error;
use crate::sha256;

#[derive(Debug, Clone, Error)]
pub enum SluiceError {
    #[error("Buffer overflow: attempted to write {attempted} bytes, but only {available} bytes available (capacity: {capacity})")]
    BufferOverflow {
        attempted: usize,
        available: usize,
        capacity: usize,
    },
}

/// A fixed-size buffer for byte streams (stdout/stderr)
/// When the buffer fills up, further writes will fail with BufferOverflow error
#[derive(Debug, Clone)]
pub struct Sluice {
    buffer: Vec<u8>,
    capacity: usize,
}

impl Sluice {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Append bytes to the buffer
    /// Returns an error if the buffer would exceed capacity
    pub fn append(&mut self, data: &[u8]) -> Result<(), SluiceError> {
        let available = self.capacity.saturating_sub(self.buffer.len());
        if data.len() > available {
            return Err(SluiceError::BufferOverflow {
                attempted: data.len(),
                available,
                capacity: self.capacity,
            });
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Get the current contents as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the current contents as a UTF-8 string (lossy conversion)
    pub fn as_string(&self) -> String {
        String::from_utf8_lossy(&self.buffer).to_string()
    }

    /// Get the SHA256 hash of the buffer contents as a 0x-prefixed hex string
    pub fn sha256_hex(&self) -> String {
        format!("0x{}", hex::encode(self.sha256()))
    }

    /// Get the SHA256 hash of the buffer contents as raw bytes
    pub fn sha256(&self) -> Vec<u8> {
        sha256!(&self.buffer).finalize().to_vec()
    }
}

impl Serialize for Sluice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Sluice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = s.as_bytes();
        // Use a default capacity of 1MB for deserialized buffers
        let capacity = bytes.len().max(1024 * 1024);
        let mut buffer = Self::new(capacity);
        buffer.append(bytes)
            .map_err(|e| serde::de::Error::custom(format!("Failed to deserialize Sluice: {}", e)))?;
        Ok(buffer)
    }
}
