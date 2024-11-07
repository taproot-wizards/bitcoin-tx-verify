use bitcoin::consensus::Encodable;
use bitcoin::{OutPoint, Transaction, TxOut};
use libc::c_uint;
use std::collections::HashMap;
use thiserror::Error;

mod ffi {
    use libc::{c_uchar, c_uint};

    #[repr(C)]
    pub(super) struct VerifyScriptResult {
        pub success: bool,
        pub err_msg: *const libc::c_char,
    }

    // Implement a Drop trait to ensure the C++ side frees allocated resources
    impl Drop for VerifyScriptResult {
        fn drop(&mut self) {
            unsafe {
                free_verify_script_result(self);
            }
        }
    }

    impl From<&VerifyScriptResult> for Result<(), String> {
        fn from(res: &VerifyScriptResult) -> Self {
            if res.success {
                Ok(())
            } else {
                let err_c_str =
                    unsafe { std::ffi::CStr::from_ptr(res.err_msg) };
                Err(err_c_str.to_str().unwrap().to_owned())
            }
        }
    }

    #[link(name = "bitcoin-script.a", kind = "static")]
    extern "C" {
        #[allow(dead_code)]
        pub fn mandatory_script_verify_flags() -> u32;

        #[allow(dead_code)]
        pub fn standard_script_verify_flags() -> u32;

        pub fn op_cat_verify_flag() -> u32;

        pub fn verify_script(
            scriptPubKey: *const c_uchar,
            scriptPubKeyLen: c_uint,
            txTo: *const c_uchar,
            txToLen: c_uint,
            nIn: c_uint,
            flags: c_uint,
            amount: i64,
        ) -> *mut VerifyScriptResult;

        pub fn verify_tapscript(
            txTo: *const c_uchar,
            txToLen: c_uint,
            prev_outs: *const *const c_uchar,
            prev_outs_lens: *const c_uint,
            prev_outs_count: c_uint,
            nIn: c_uint,
            flags: c_uint,
            amount: i64,
        ) -> *mut VerifyScriptResult;

        /// MUST be called when VerifyScriptResult is dropped
        pub(super) fn free_verify_script_result(
            result: *mut VerifyScriptResult,
        );
    }
}

#[allow(dead_code)]
pub fn mandatory_script_verify_flags() -> u32 {
    unsafe { ffi::mandatory_script_verify_flags() }
}

#[allow(dead_code)]
pub fn standard_script_verify_flags() -> u32 {
    unsafe { ffi::standard_script_verify_flags() }
}

pub fn op_cat_verify_flag() -> u32 {
    unsafe { ffi::op_cat_verify_flag() }
}

pub fn verify_tapscript(
    tx_to: &[u8],
    n_in: u32,
    prev_outs: &[Vec<u8>],
    flags: u32,
    amount: i64,
) -> Result<(), String> {
    // Create arrays of pointers and lengths
    let ptrs: Vec<*const u8> = prev_outs.iter().map(|s| s.as_ptr()).collect();
    let lengths: Vec<u32> = prev_outs.iter().map(|s| s.len() as u32).collect();

    unsafe {
        &*ffi::verify_tapscript(
            tx_to.as_ptr(),
            tx_to.len() as c_uint,
            ptrs.as_ptr(),
            lengths.as_ptr(),
            prev_outs.len() as c_uint,
            n_in as c_uint,
            flags as c_uint,
            amount,
        )
    }
    .into()
}

pub fn verify(
    script_pub_key: &[u8],
    tx_to: &[u8],
    n_in: u32,
    flags: u32,
    amount: i64,
) -> Result<(), String> {
    unsafe {
        &*ffi::verify_script(
            script_pub_key.as_ptr(),
            script_pub_key.len() as c_uint,
            tx_to.as_ptr(),
            tx_to.len() as c_uint,
            n_in as c_uint,
            flags as c_uint,
            amount,
        )
    }
    .into()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("Error verifying input {input_idx}: {err_msg}")]
pub struct VerifyTxError {
    /// Index of the input that failed verification
    pub input_idx: usize,
    /// Source error message
    pub err_msg: String,
}

/// Verifies the transaction input's tapscript, this does not validate the control block
/// and assumes there is no annex.
pub fn verify_tx_input_tapscript(
    tx: &Transaction,
    spent_outputs: &HashMap<OutPoint, TxOut>,
    input_idx: usize,
    flags: u32,
) -> Result<(), VerifyTxError> {
    if tx.input[input_idx].witness.tapscript().is_none() {
        return Err(VerifyTxError {
            input_idx,
            err_msg: "Not a taproot script spend input".to_string(),
        })
    }

    let tx_encoded = bitcoin::consensus::serialize(tx);
    let prevouts: Vec<&TxOut> = tx
        .input
        .iter()
        .enumerate()
        .map(|(idx, i)| {
            spent_outputs.get(&i.previous_output).ok_or(VerifyTxError {
                input_idx: idx,
                err_msg: "Missing previous output".to_string(),
            })
        })
        .collect::<Result<_, _>>()?;

    let prevouts_encoded = prevouts
        .iter()
        .map(|o| {
            let mut bytes = Vec::new();
            o.value
                .consensus_encode(&mut bytes)
                .expect("serialization failed");
            bytes.extend_from_slice(o.script_pubkey.as_bytes());
            bytes
        })
        .collect::<Vec<Vec<u8>>>();

    if let Err(err_msg) = verify_tapscript(
        &tx_encoded,
        input_idx as u32,
        &prevouts_encoded,
        flags,
        prevouts[input_idx].value.to_sat() as i64,
    ) {
        Err(VerifyTxError { input_idx, err_msg })
    } else {
        Ok(())
    }
}

/// Verify tx
pub fn verify_tx(
    tx: &Transaction,
    spent_outputs: &HashMap<OutPoint, TxOut>,
    flags: u32,
) -> Result<(), VerifyTxError> {
    let tx_encoded = bitcoin::consensus::serialize(tx);
    for (input_idx, input) in tx.input.iter().enumerate() {
        let spent_output = &spent_outputs[&input.previous_output];
        let spk_encoded = &spent_output.script_pubkey.to_bytes();
        if let Err(err_msg) = verify(
            spk_encoded,
            &tx_encoded,
            input_idx as u32,
            flags,
            spent_output.value.to_sat() as i64,
        ) {
            return Err(VerifyTxError { input_idx, err_msg });
        } else {
            continue;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use bitcoin::consensus::Decodable;
    use bitcoin::io::Cursor;
    use bitcoin::{
        absolute::LockTime,
        ecdsa::Signature,
        hex::FromHex,
        opcodes::all::{OP_CAT, OP_EQUAL},
        secp256k1::{rand::rngs::OsRng, Secp256k1},
        sighash::SighashCache,
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
        Amount, EcdsaSighashType, PublicKey, ScriptBuf, TxIn, Witness,
    };

    /// Generate a tx with 0 inputs and 1 output,
    /// with the specified scriptpubkey.
    fn tx_0_in_1_out(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
        let txout = TxOut {
            value,
            script_pubkey,
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1).unwrap(),
            input: Vec::new(),
            output: vec![txout],
        }
    }

    /// Generate a tx with 1 input and 1 output,
    /// with the specified scriptpubkey and value.
    /// The tx input does not include a script sig or witness.
    fn tx_1_in_1_out(
        previous_output: OutPoint,
        script_pubkey: ScriptBuf,
        value: Amount,
    ) -> Transaction {
        let txin = TxIn {
            previous_output,
            ..Default::default()
        };
        let txout = TxOut {
            value,
            script_pubkey,
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1).unwrap(),
            input: vec![txin],
            output: vec![txout],
        }
    }

    #[test]
    fn verify_1_in_1_out() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let wpkh = pk.wpubkey_hash()?;
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let previous_output = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let tx = { tx_1_in_1_out(previous_output, spk.clone(), value) };
        let mut sighash_cache = SighashCache::new(tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            0,
            &spk,
            sighash_cache.transaction().output[0].value,
            EcdsaSighashType::All,
        )?;
        let mut sig = Secp256k1::new().sign_ecdsa_low_r(&sighash.into(), &sk);
        sig.normalize_s();
        let wit = Witness::p2wpkh(&Signature::sighash_all(sig), &pk.inner);
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<OutPoint, TxOut> = HashMap::from_iter([(
            previous_output,
            source_tx.output[0].clone(),
        )]);
        // sanity checks that tx is valid
        {
            tx.verify(|outpoint| {
                let tx_out = spent_outputs.get(outpoint)?;
                Some(tx_out.clone())
            })?;
        }

        // verify tx
        assert!(verify_tx(&tx, &spent_outputs, op_cat_verify_flag()).is_ok());
        Ok(())
    }

    // OP_CAT on an empty stack should fail if OP_CAT is enabled,
    // and succeed if disabled
    #[test]
    fn verify_op_cat_empty_stack() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder().push_opcode(OP_CAT).into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let previous_output = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let tx = { tx_1_in_1_out(previous_output, spk.clone(), value) };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<OutPoint, TxOut> = HashMap::from_iter([(
            previous_output,
            source_tx.output[0].clone(),
        )]);
        // verify tx without OP_CAT enabled should work
        let res = verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(res, Ok(()));
        // verify tx with OP_CAT enabled should fail
        assert!(
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags())
                .is_err()
        );
        Ok(())
    }

    // OP_CAT on a stack with two elements should succeed if OP_CAT is enabled
    #[test]
    fn verify_op_cat_two_elements() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder().push_opcode(OP_CAT).into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let previous_output = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let tx = { tx_1_in_1_out(previous_output, spk.clone(), value) };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push([0xaa]);
        wit.push([0xbb]);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<OutPoint, TxOut> = HashMap::from_iter([(
            previous_output,
            source_tx.output[0].clone(),
        )]);
        // verify tx with OP_CAT enabled should succeed
        let res = verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(res, Ok(()));
        Ok(())
    }

    // OP_CAT on a stack with two elements, compared with their concatenation,
    // should succeed if OP_CAT is enabled
    #[test]
    fn verify_op_cat_two_elements_eq() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder()
            .push_opcode(OP_CAT)
            .push_opcode(OP_EQUAL)
            .into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let previous_output = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let tx = { tx_1_in_1_out(previous_output, spk.clone(), value) };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(Vec::<u8>::from_hex("78a11a1260c1101260")?);
        wit.push(Vec::<u8>::from_hex("78a11a1260")?);
        wit.push(Vec::<u8>::from_hex("c1101260")?);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<OutPoint, TxOut> = HashMap::from_iter([(
            previous_output,
            source_tx.output[0].clone(),
        )]);
        // verify tx with OP_CAT enabled should succeed
        let res = verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(res, Ok(()));
        Ok(())
    }

    // OP_CAT on a stack with two elements, compared with something other than
    // their concatenation, should fail if OP_CAT is enabled, and succeed
    // if OP_CAT is not enabled
    #[test]
    fn verify_op_cat_two_elements_neq() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder()
            .push_opcode(OP_CAT)
            .push_opcode(OP_EQUAL)
            .into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let previous_output = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let tx = { tx_1_in_1_out(previous_output, spk.clone(), value) };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(Vec::<u8>::from_hex("")?);
        wit.push(Vec::<u8>::from_hex("78a11a1260")?);
        wit.push(Vec::<u8>::from_hex("c1101260")?);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<OutPoint, TxOut> = HashMap::from_iter([(
            previous_output,
            source_tx.output[0].clone(),
        )]);
        // verify tx with OP_CAT disabled should succeed
        let res = verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(res, Ok(()));
        // verify tx with OP_CAT enabled should fail
        let res =
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags());
        assert_ne!(res, Ok(()));

        Ok(())
    }

    #[test]
    fn test_run_tapscript() -> anyhow::Result<()> {
        let tx_bytes: Vec<u8> = FromHex::from_hex("02000000000101b125029710f2ba7fe064292418d2e833bae2897f7bf6e2f1a2242c87635dfc2e0100000000ffffffff01905f010000000000160014cea9d080198881e00baead0521d5be4e660693771001000100040200000004bb00000020f92434758cd2d2eaa58881b31cdfd3c3515448f80e1b51ac32d77c6ec65f1dce20184c0ede118ec8cd31f699524bae48a81ed01ded5f8d08f2f4ff4286b33b027020d0c8f23f944956475f4ef6823c171a46f2f39123fb8e62c3255087e4d68e366c20ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e01020400000000209d9f03916f15de9baac8de5a785e8f3c401d85a49f476a14de38ad0dcea4d3db010004ffffffff3f79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ef3d745bcf6458f86768ae8adba97ac0a1702cd9cebb786f8665c5a84d87d8ae6b7e7e7e7e201f8f848c1c8015fba58504000a171722182cb30ac3716afa9ecb8d398ab039847c7e7e7e7e7e7e7e7e7e0a54617053696768617368a8767b7e7ea811424950303334302f6368616c6c656e6765a8767b2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179876766b7b7e7e7e7ea86c7c7e6c7601007e7b88517e2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0bb000000").unwrap();
        let mut tx_cursor = Cursor::new(tx_bytes);
        let tx: Transaction = Transaction::consensus_decode(&mut tx_cursor)?;

        let prevout: TxOut = TxOut {
            value: Amount::from_btc(0.00100000).unwrap(),
            script_pubkey: ScriptBuf::from_hex(
                "5120c6ee2efbb6a663bd2d9996e2e7cf5d2a27cb4375879fe3b6beb669dcce6505cd",
            )?,
        };

        let prevouts =
            HashMap::from_iter([(tx.input[0].previous_output, prevout)]);

        let result = verify_tx_input_tapscript(
            &tx,
            &prevouts,
            0,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(result, Ok(()));

        Ok(())
    }

    #[test]
    fn test_multi_input_tx() -> anyhow::Result<()> {
        let tx_bytes: Vec<u8> = FromHex::from_hex("02000000000103f5054de658ce910c95f79e83284d2eb584d093b5772a09eebe8825adab203be70000000000ffffffff732f571f2fdfb45a463c15d5b31300ffb22a35ca18fd021cc28b373d39d2d9060000000000ffffffffd90a4581ec95e8551fb7af1ea1510a71da94c95925b3adb03b7f73bb91a5ca2a0200000000ffffffff037a040000000000001976a914cbd0e959eff7b08d59f93bf1605f5a5b5239649b88acc045040000000000225120f9414c8366098d8ebaadd5190f375b316ebf13b068083d3ef6822d2741fe2d8cd4883e0000000000225120dfe4d8dfb3f7fff0ba7706ad1f5a79099da5eb0252ce9e72af81930bbbcb9df001405f87b743508953b77bf07482433301e56956a341b025e3ec3e0ea0e8026e17e6997946fd52a19e4dc8a965d3c19ffe9c861ea4be7ffc50d5ff53328a821908750141d2a67fc10087c98446bfff0af818bde789546cdcd833604909a40680d3543b1fd64281e83bb007cc450bfc7f9f7c91102647a9839065a9d517448b0a6885afba83014032a0fa9508d34356bad3726648f00e6bda4740064d63578af0c073ee46e310a5ec9b911d5afab43164a23863ef1015784fb84c86c587da116f648ff5186ee43400000000").unwrap();
        let mut tx_cursor = Cursor::new(tx_bytes);
        let tx: Transaction = Transaction::consensus_decode(&mut tx_cursor)?;

        let prevout0: TxOut = TxOut {
            value: Amount::from_sat(600),
            script_pubkey: ScriptBuf::from_hex(
                "5120dfe4d8dfb3f7fff0ba7706ad1f5a79099da5eb0252ce9e72af81930bbbcb9df0",
            )?
        };

        let prevout1: TxOut = TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::from_hex(
                "5120f9414c8366098d8ebaadd5190f375b316ebf13b068083d3ef6822d2741fe2d8c",
            )?
        };

        let prevout2: TxOut = TxOut {
            value: Amount::from_sat(4383797),
            script_pubkey: ScriptBuf::from_hex(
                "5120dfe4d8dfb3f7fff0ba7706ad1f5a79099da5eb0252ce9e72af81930bbbcb9df0",
            )?
        };

        let prevouts = HashMap::from_iter([
            (tx.input[0].previous_output, prevout0),
            (tx.input[1].previous_output, prevout1),
            (tx.input[2].previous_output, prevout2),
        ]);

        let result = verify_tx(
            &tx,
            &prevouts,
            standard_script_verify_flags() & op_cat_verify_flag(),
        );
        assert_eq!(result, Ok(()));

        Ok(())
    }
}
