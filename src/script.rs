use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHDATA1};
use bitcoin::opcodes::{OP_0, OP_TRUE};

use bitcoin::script::PushBytes;

pub trait ScriptFragment {
    const STATIC_LEN: Option<usize>;

    fn encoded_len(&self) -> Option<usize> { Self::LEN }

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error>;
}

pub trait ToScriptFragment {
    type Fragment: ScriptFragment;

    fn to_fragment(&self) -> Self::Fragment;
}

impl<T: ToScriptFragment> ScriptFragment for T {
    const STATIC_LEN: Option<usize> = T::Fragment::STATIC_LEN;

    fn encoded_len(&self) -> Option<usize> { self.to_fragment().encoded_len() }

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        self.to_fragment().encode(encoder)
    }
}

pub trait OutputScriptPubkey: ScriptFragment { }

impl ScriptFragment for Opcode {
    const STATIC_LEN: Option<usize> = Some(1);

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.push_opcode(self)?;

        Ok(())
    }
}

/// Represents a Pay to Taproot output with a given output public key
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToTaproot(bitcoin::key::TweakedPublicKey);

impl PayToTaproot {
    pub fn new_p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);

        Self::new_p2tr_tweaked(output_key)
    }

    pub fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        Self(output_key)
    }
}

const WITNESS_V1_LEN: u8 = 1;
const WITNESS_V1: u8 = OP_PUSHNUM_1.to_u8();
const PUSHBYTES_32_LEN: u8 = 1;
const TAPROOT_SCRIPT_PUBKEY_LEN: u8 = WITNESS_V1_LEN + PUSHBYTES_32_LEN + SCHNORR_PUBLIC_KEY_SIZE as u8;

pub trait ScriptEncoder {
    type Error;

    fn push_opcode(&mut self, opcode: Opcode) -> Result<usize, Self::Error>;

    fn push_int(mut self, value: i64) -> Result<Self, Self::Error> {
        if value == -1 || ((1 <= value && value <= 16)) {
            let opcode = Opcode::from((value - 1 + OP_TRUE.to_u8() as i64) as u8);
            self.push_opcode(opcode)
        } else if value == 0 {
            self.push_opcode(OP_0)
        } else {
            let mut int_bytes = [0u8; 8];
            let mut len = 0;
            let negative = value < 0;

            let magnitude = value.unsigned_abs();
            
            while magnitude > 0xFF {
                int_bytes[len] = magnitude as u8;
                len += 1;
                magnitude = magnitude >> 8;
            }

            if abs & 0x80 != 0 {
                int_bytes[len] = abs as u8;
                len += 1;
                int_bytes[len] = if negative { 0x80 } else { 0 };
            } else {
                if negative {
                    int_bytes[len] = magnitude as u8 | 0x80;
                } else {
                    int_bytes[len] = magnitude as u8 | 0x00;
                }
            }
        }
    }

    fn push_slice(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum PushSliceError<E> {
    Error(E),
    InvalidSliceLength(usize),
}

pub struct ScriptWrite<W> {
    writer: W,
    committed_length: usize,
    current_length: usize,
}

impl<W> for ScriptWrite<W> {
    fn new(writer: W, committed_length: usize) -> Self {
        Self {
            writer,
            committed_length,
            current_length: 0,
        }
    }

    fn write_opcode(&mut self, opcode: Opcode) -> Result<usize, bitcoin::io::Error> {
        self.writer.write(&[opcode.to_u8()])
    }
}

impl<W: bitcoin::io::Write> ScriptEncoder for ScriptWrite<W> {
    type Error = bitcoin::io::Error;

    fn push_opcode(mut self, opcode: Opcode) -> Result<Self, Self::Error> {
        self.current_length += self.writer.write(&[opcode.to_u8()])?;

        Ok(self)
    }

    fn push_slice(mut self, bytes: &[u8]) -> Result<Self, Self::Error> {
        match data.len() as u64 {
            n if n < OP_PUSHDATA1 as u64 => {
                self.current_length += self.writer.write(&[n as u8])?;
            }
            n if n < 0x100 => {
                self.current_length += self.write_opcode(OP_PUSHDATA1)?;
                self.current_length += self.writer.write(&[n as u8])?;
            }
            n if n < 0x10000 => {
                self.current_length += self.write_opcode(OP_PUSHDATA2)?;
                self.current_length += self.writer.write(&n.to_le_bytes()[..2])?;
            }
            n if n < 0x100000000 => {
                self.current_length += self.write_opcode(OP_PUSHDATA4)?;
                self.current_length += self.writer.write(&n.to_le_bytes()[..4])?;
            }
            n => { return Err(ScriptWriteError::PushSliceLength(n)); }
        }

        self.current_length += self.writer.write(data)?;

        Ok(self)
    }
}

// FIXME: name
pub enum BuildScriptBufError {
    PushLengthError(PushBytesError),
}

impl ScriptEncoder for ScriptBuf {
    type Error = BuildScriptBufError;

    fn push_opcode(mut self, opcode: Opcode) -> Result<Self, Self::Error> {
        ScriptBuf::push_opcode(&mut self, opcode);

        Ok(self)
    }

    fn push_slice(mut self, bytes: &[u8]) -> Result<Self, Self::Error> {
        let push_bytes = PushBytes::try_from(bytes)
            .map_err(|e| BuildScriptBufError::PushLengthError(bytes.len()))?;

        ScriptBuf::push_slice(&mut self, push_bytes);

        Ok(self)
    }
}

// XXX: Maybe ScriptBuilder should be ScriptSink or something

impl Encodable for PayToTaproot {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        const TAPROOT_SCRIPT_PREFIX: [u8; 3] = [
            TAPROOT_SCRIPT_PUBKEY_LEN,
            WITNESS_V1,
            OP_PUSHBYTES_32.to_u8(),
        ];

        let mut len = 0;

        len += writer.write(&TAPROOT_SCRIPT_PREFIX)?;
        len += writer.write(&self.0.serialize())?;

        Ok(len)
    }
}

impl From<PayToTaproot> for ScriptBuf {
    fn from(p2tr: PayToTaproot) -> Self {
        ScriptBuf::new_p2tr_tweaked(p2tr.0)
    }
}

macro_rules! impl_tuple_fragment {
    ($($name:ident : $idx:tt),+ $(,)?) => {
        impl<$($name),+> ScriptFragment for ($($name,)+)
        where
            $($name: ScriptFragment),+
        {
            const STATIC_LEN: Option<usize> = {
                let len = Some(0);
                $(
                    let len = match (len, $name::STATIC_LEN) {
                        (Some(len), Some(extra_len)) => Some(len + extra_len),
                        _ => None,
                    };
                )+
                len
            };

            fn encoded_len(&self) -> Option<usize> {
                let len = 0;

                $(
                    let len = len.checked_add(self.$idx.encoded_len()?)?;
                )+

                Some(len)
            }

            fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
                $(
                    self.$idx.encode(encoder)?;
                )+

                Ok(())
            }
        }
    };
}

