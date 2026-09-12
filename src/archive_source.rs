//! SPEC-054 CON-006: owned chat/source reception, without capture authority.
//! Selection and the joined room are facts supplied by the current connection.
use cbcl_archive_core::source_delivery::{self, Delivery, MAX_DELIVERY, MAX_FRAME};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReceiveError {
    #[error("malformed ordinary legacy frame")]
    LegacyFrame,
    #[error("archive source data exceeds the receive bound")]
    Bound,
    #[error("archive source format was not selected on this connection")]
    Unselected,
    #[error("invalid archive source frame")]
    Invalid,
    #[error("archive source belongs to another room")]
    Room,
    #[error("repeated connection bootstrap")]
    Bootstrap,
}

/// Keeps original bytes and source coordinates together until processing ends.
/// Recognition grants no permission to archive or trust an MLS sender.
pub(crate) struct ReceivedFrame {
    bytes: Vec<u8>,
    source: Option<Delivery>,
}

impl ReceivedFrame {
    pub(crate) fn read(
        bytes: impl AsRef<[u8]>,
        selected: bool,
        channel: &str,
    ) -> Result<Self, ReceiveError> {
        let bytes = bytes.as_ref();
        let legacy = !selected && !bytes.starts_with(b"CSD1");
        if bytes.len() > MAX_DELIVERY {
            return Err(if legacy {
                ReceiveError::LegacyFrame
            } else {
                ReceiveError::Bound
            });
        }
        let source = if bytes.starts_with(b"CSD1") {
            if !selected {
                return Err(ReceiveError::Unselected);
            }
            let delivery = source_delivery::read(bytes).map_err(|_| ReceiveError::Invalid)?;
            if delivery.channel != channel {
                return Err(ReceiveError::Room);
            }
            Some(delivery)
        } else {
            None
        };
        let value = Self {
            bytes: bytes.to_vec(),
            source,
        };
        let frame = value.frame();
        if frame.len() > MAX_FRAME {
            return Err(if legacy {
                ReceiveError::LegacyFrame
            } else {
                ReceiveError::Bound
            });
        }
        if frame.len() < 68
            || u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize != frame.len() - 68
            || std::str::from_utf8(&frame[4..frame.len() - 64]).is_err()
        {
            return Err(if legacy {
                ReceiveError::LegacyFrame
            } else {
                ReceiveError::Invalid
            });
        }
        if source_delivery::read_bootstrap(frame).is_ok() {
            return Err(ReceiveError::Bootstrap);
        }
        Ok(value)
    }

    pub(crate) fn frame(&self) -> &[u8] {
        self.source
            .as_ref()
            .map_or(&self.bytes, |source| &source.frame)
    }

    pub(crate) fn text(&self) -> &str {
        let frame = self.frame();
        // Complete length and UTF-8 recognition precede construction.
        std::str::from_utf8(&frame[4..frame.len() - 64]).unwrap()
    }

    #[cfg(test)]
    fn source(&self) -> Option<&Delivery> {
        self.source.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_archive_core::source_delivery::{Policy, Source};
    use sha2::{Digest, Sha256};

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&[7; 64]);
        bytes
    }

    fn delivery() -> Delivery {
        let payload = b"(tell @test \"saved message\" :from @alice)";
        Delivery {
            channel: "room:test".into(),
            admission_seq: 9,
            admission_ts: 11,
            digest: Sha256::digest(payload).into(),
            source: Some(Source { seq: 3, ts: 5 }),
            policy: Policy::Persistent,
            frame: frame(payload),
        }
    }

    #[test]
    fn selected_delivery_preserves_original_frame_and_canonical_coordinates() {
        let expected = delivery();
        let bytes = source_delivery::encode(&expected).unwrap();
        let mut caller = bytes.clone();
        let received = ReceivedFrame::read(&caller, true, "room:test").unwrap();
        caller.fill(0);
        assert_eq!(received.bytes, bytes);
        assert_eq!(received.frame(), expected.frame);
        assert_eq!(received.source(), Some(&expected));
        assert_eq!(
            received.text(),
            "(tell @test \"saved message\" :from @alice)"
        );
        assert_eq!(&received.frame()[received.frame().len() - 64..], &[7; 64]);
    }

    #[test]
    fn repeated_admissions_preserve_one_source_identity() {
        let first = delivery();
        let mut repeated = first.clone();
        repeated.admission_seq = 100;
        repeated.admission_ts = 200;
        for value in [first.clone(), repeated] {
            let received =
                ReceivedFrame::read(source_delivery::encode(&value).unwrap(), true, "room:test")
                    .unwrap();
            assert_eq!(received.source().unwrap().source, first.source);
            assert_eq!(received.source().unwrap().digest, first.digest);
            assert_eq!(
                received.source().unwrap().admission_seq,
                value.admission_seq
            );
        }
    }

    #[test]
    fn connection_selection_and_room_are_required_before_source_use() {
        let bytes = source_delivery::encode(&delivery()).unwrap();
        assert!(matches!(
            ReceivedFrame::read(bytes.clone(), false, "room:test"),
            Err(ReceiveError::Unselected)
        ));
        assert!(matches!(
            ReceivedFrame::read(bytes, true, "room:foreign"),
            Err(ReceiveError::Room)
        ));
        let ordinary =
            ReceivedFrame::read(frame(b"(tell @test \"legacy\")"), false, "room:test").unwrap();
        assert!(ordinary.source().is_none());
    }

    #[test]
    fn rejects_corruption_and_never_repairs_utf8_or_framing() {
        let bytes = source_delivery::encode(&delivery()).unwrap();
        for end in 0..bytes.len() {
            assert!(ReceivedFrame::read(bytes[..end].to_vec(), true, "room:test").is_err());
        }
        let mut corrupt = bytes.clone();
        let at = corrupt
            .windows(13)
            .position(|part| part == b"saved message")
            .unwrap();
        corrupt[at] ^= 1;
        assert!(ReceivedFrame::read(corrupt, true, "room:test").is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(ReceivedFrame::read(trailing, true, "room:test").is_err());
        assert!(ReceivedFrame::read(frame(&[0xff]), false, "room:test").is_err());
        assert!(ReceivedFrame::read(vec![0; MAX_DELIVERY + 1], true, "room:test").is_err());
        let mut ordinary = frame(b"(tell @test \"legacy\")");
        ordinary.push(0);
        assert!(ReceivedFrame::read(ordinary, false, "room:test").is_err());
    }

    #[test]
    fn a_later_bootstrap_cannot_replace_connection_state() {
        let payload = b"(tell @client \"conn-nonce\" :from @cbcl-chat :nonce \"BwcHBwcHBwcHBwcHBwcHBw==\" :hub \"cbcl-chat\")";
        let mut bytes = frame(payload);
        let end = bytes.len();
        bytes[end - 64..].fill(0);
        assert!(matches!(
            ReceivedFrame::read(bytes, false, "room:test"),
            Err(ReceiveError::Bootstrap)
        ));
    }
}
