use bitcoin::consensus::Encodable;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Opcode, TapLeafHash, TapNodeHash, ScriptBuf, VarInt};
use bitcoin::key::{TweakedPublicKey, TapTweak};
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use bitcoin::opcodes::{OP_0, OP_TRUE};

use bitcoin::script::PushBytes;
use bitcoin::io::{Error, Write};
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use bitcoin::hashes::Hash;

pub trait ScriptFragment {
    const STATIC_LEN: Option<usize>;

    fn encoded_len(&self) -> Option<usize> { Self::STATIC_LEN }

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error>;

    fn to_scriptbuf(&self) -> ScriptBuf {
        let mut buf = Vec::with_capacity(self.encoded_len().unwrap_or(0));

        self.encode(&mut buf)
            .expect("write to Vec buffer won't fail");

        ScriptBuf::from_bytes(buf)
    }
}

pub trait ScriptPubkey: ScriptFragment { }
pub trait ScriptSig: ScriptFragment { }

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

impl ScriptFragment for () {
    const STATIC_LEN: Option<usize> = Some(0);

    fn encode<E: ScriptEncoder>(&self, _encoder: &mut E) -> Result<(), E::Error> {
        Ok(())
    }
}

impl ScriptSig for () { }

pub trait OutputScriptPubkey: ScriptFragment { }

impl ScriptFragment for Opcode {
    const STATIC_LEN: Option<usize> = Some(1);

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.push_opcode(*self)?;

        Ok(())
    }
}

pub trait ScriptEncoder {
    type Error;

    fn push_opcode(&mut self, opcode: Opcode) -> Result<(), Self::Error>;
    fn push_slice<T: AsRef<PushBytes>>(&mut self, data: T) -> Result<(), Self::Error>;

    fn push_int(&mut self, value: i64) -> Result<(), Self::Error> {
        if value == -1 || ((1 <= value && value <= 16)) {
            let opcode = Opcode::from((value - 1 + OP_TRUE.to_u8() as i64) as u8);
            self.push_opcode(opcode)?;
        } else if value == 0 {
            self.push_opcode(OP_0)?;
        } else {
            let mut int_bytes = [0u8; 8];
            let mut len = 0;
            let negative = value < 0;

            let mut magnitude = value.unsigned_abs();
            
            while magnitude > 0xFF {
                int_bytes[len] = magnitude as u8;
                len += 1;
                magnitude = magnitude >> 8;
            }

            if (magnitude & 0x80) != 0 {
                int_bytes[len] = magnitude as u8;
                len += 1;
                int_bytes[len] = if negative { 0x80 } else { 0 };
            } else {
                if negative {
                    int_bytes[len] = magnitude as u8 | 0x80;
                } else {
                    int_bytes[len] = magnitude as u8 | 0x00;
                }
            }

            self.push_slice(&<&PushBytes>::from(&int_bytes)[..len])?;
        }

        Ok(())
    }
}

impl<W: Write> ScriptEncoder for W {
    type Error = Error;

    fn push_opcode(&mut self, opcode: Opcode) -> Result<(), Self::Error> {
        self.write(&[opcode.to_u8()])?;

        Ok(())
    }

    fn push_slice<T: AsRef<PushBytes>>(&mut self, data: T) -> Result<(), Self::Error> {
        match data.as_ref().len() as u64 {
            n if n < OP_PUSHDATA1.to_u8() as u64 => {
                self.write(&[n as u8])?;
            }
            n if n < 0x100 => {
                self.write(&[OP_PUSHDATA1.to_u8()])?;
                self.write(&[n as u8])?;
            }
            n if n < 0x10000 => {
                self.write(&[OP_PUSHDATA2.to_u8()])?;
                self.write(&n.to_le_bytes()[..2])?;
            }
            n if n < 0x100000000 => {
                self.write(&[OP_PUSHDATA4.to_u8()])?;
                self.write(&n.to_le_bytes()[..4])?;
            }
            _ => panic!("oversized push (over 4 Billion Bytes)"),
        }

        self.write(data.as_ref().as_bytes())?;

        Ok(())
    }
}

pub struct PushXOnlyPublicKey(pub XOnlyPublicKey);

impl ScriptFragment for PushXOnlyPublicKey {
    const STATIC_LEN: Option<usize> = Some(33);

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.push_slice(self.0.serialize())
    }
}

pub struct PushHash<H>(pub H);

impl<H: Hash<Bytes = [u8; 32]>> ScriptFragment for PushHash<H> {
    const STATIC_LEN: Option<usize> = Some(33);

    fn encode<E: ScriptEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.push_slice(&self.0.to_byte_array())
    }
}

impl ToScriptFragment for PayToTaproot {
    type Fragment = (Opcode, PushXOnlyPublicKey);

    fn to_fragment(&self) -> Self::Fragment {
        (OP_PUSHNUM_1, PushXOnlyPublicKey(self.0.to_x_only_public_key()))
    }
}

impl ScriptPubkey for PayToTaproot { }

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
                let len = 0usize;

                $(
                    let len = len + self.$idx.encoded_len()?;
                )+

                Some(len)
            }

            fn encode<Encoder: ScriptEncoder>(&self, encoder: &mut Encoder) -> Result<(), Encoder::Error> {
                $(
                    self.$idx.encode(encoder)?;
                )+

                Ok(())
            }
        }
    };
}

fn write_fragment<W: Write, F: ScriptFragment>(writer: &mut W, fragment: &F) -> Result<(), Error> {
    const EXPECT_SCRIPT_LEN: &str = "script length fits in u64";
    if let Some(len) = fragment.encoded_len() {
        let len: u64 = len.try_into()
            .expect(EXPECT_SCRIPT_LEN);
        let len = VarInt(len);

        len.consensus_encode(writer)?;

        fragment.encode(writer)
    } else {
        let mut buf: Vec<u8> = Vec::new();

        fragment.encode(&mut buf)?;

        let len: u64 = buf.len().try_into()
            .expect(EXPECT_SCRIPT_LEN);

        let len = VarInt(len);

        len.consensus_encode(writer)?;

        writer.write(buf.as_ref())?;

        Ok(())
    }
}

pub trait TapScript {
    fn to_tapleaf(&self, leaf_version: LeafVersion) -> TapLeafHash;
}

impl<F: ScriptFragment> TapScript for F {
    fn to_tapleaf(&self, leaf_version: LeafVersion) -> TapLeafHash
    {
        let mut engine = TapLeafHash::engine();

        leaf_version
            .to_consensus()
            .consensus_encode(&mut engine)
            .expect("hash engines don't error");

        write_fragment(&mut engine, self)
            .expect("script write wrapping hash engines don't error");

        TapLeafHash::from_engine(engine)
    }
}

/// Store information about taproot leaf node.
#[derive(Debug, Clone, Hash)]
pub struct LeafNode<M> {
    leaf: TapLeafHash,

    metadata: M,
    /// The merkle proof (hashing partners) to get this node.
    merkle_branch: Vec<TapNodeHash>,
}

impl<M> PartialEq for LeafNode<M> {
    fn eq(&self, other: &Self) -> bool {
        self.leaf.eq(&other.leaf)
    }
}

impl<M> Eq for LeafNode<M> { }

impl<M> PartialOrd for LeafNode<M> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl<M> Ord for LeafNode<M> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.leaf.cmp(&other.leaf)
    }
}

#[derive(Debug, Clone, PartialOrd, Ord)]
struct NodeInfo<M> {
    hash: TapNodeHash,

    leaves: Vec<LeafNode<M>>,
}

/// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
/// weights of satisfaction for that script.
///
/// The weights represent the probability of each branch being taken. If probabilities/weights
/// for each condition are known, constructing the tree as a Huffman Tree is the optimal way to
/// minimize average case satisfaction cost. This function takes as input an iterator of
/// `tuple(u32, ScriptBuf)` where `u32` represents the satisfaction weights of the branch. For
/// example, [(3, S1), (2, S2), (5, S3)] would construct a [`TapTree`] that has optimal
/// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%.
///
/// # Errors:
///
/// - When the optimal Huffman Tree has a depth more than 128.
/// - If the provided list of script weights is empty.
///
/// # Edge Cases:
///
/// If the script weight calculations overflow, a sub-optimal tree may be generated. This should
/// not happen unless you are dealing with billions of branches with weights close to 2^32.
///
/// [`TapTree`]: crate::taproot::TapTree
pub fn with_huffman_tree<I, M, S>(script_weights: I) -> Result<Self, TaprootBuilderError>
where
    I: IntoIterator<Item = (u32, M, S)>,
{
    let mut node_weights = BinaryHeap::<(Reverse<u32>, NodeInfo)>::new();
    for (p, leaf) in script_weights {
        node_weights
            .push((Reverse(p), NodeInfo::new_leaf_with_ver(leaf, LeafVersion::TapScript)));
    }
    if node_weights.is_empty() {
        return Err(TaprootBuilderError::EmptyTree);
    }
    while node_weights.len() > 1 {
        // Combine the last two elements and insert a new node
        let (p1, s1) = node_weights.pop().expect("len must be at least two");
        let (p2, s2) = node_weights.pop().expect("len must be at least two");
        // Insert the sum of first two in the tree as a new node
        // N.B.: p1 + p2 can not practically saturate as you would need to have 2**32 max u32s
        // from the input to overflow. However, saturating is a reasonable behavior here as
        // huffman tree construction would treat all such elements as "very likely".
        let p = Reverse(p1.0.saturating_add(p2.0));
        node_weights.push((p, NodeInfo::combine(s1, s2)?));
    }
    // Every iteration of the loop reduces the node_weights.len() by exactly 1
    // Therefore, the loop will eventually terminate with exactly 1 element
    debug_assert_eq!(node_weights.len(), 1);
    let node = node_weights.pop().expect("huffman tree algorithm is broken").1;
    Ok(TaprootBuilder { branch: vec![Some(node)] })
}

impl_tuple_fragment!(A: 0);
impl_tuple_fragment!(A: 0, B: 1);
impl_tuple_fragment!(A: 0, B: 1, C: 2);
impl_tuple_fragment!(A: 0, B: 1, C: 2, D: 3);
impl_tuple_fragment!(A: 0, B: 1, C: 2, D: 3, E: 4);
impl_tuple_fragment!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
impl_tuple_fragment!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
impl_tuple_fragment!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);
