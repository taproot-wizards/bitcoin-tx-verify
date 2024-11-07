#include <vector>

#include <policy/policy.h>
#include <primitives/transaction.h>
#include <node/protocol_version.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>

typedef std::vector<unsigned char> valtype;

// no exported so just copy pasted from interpreter.cpp
bool xCastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

extern "C" {
    unsigned int mandatory_script_verify_flags() {
        return MANDATORY_SCRIPT_VERIFY_FLAGS;
    }

    unsigned int standard_script_verify_flags() {
        return STANDARD_SCRIPT_VERIFY_FLAGS;
    }

    unsigned int op_cat_verify_flag() {
        return SCRIPT_VERIFY_OP_CAT;
    }

    struct VerifyScriptResult {
        bool success;
        char* err_msg;

        VerifyScriptResult(bool success, const std::string& err_msg)
        : success(success), err_msg(nullptr) {
            if (!err_msg.empty()) {
                this->err_msg = strdup(err_msg.c_str());  // Duplicate the string
            }
        }

        // Destructor to free the allocated memory
        ~VerifyScriptResult() {
            if (this->err_msg != nullptr) {
                free(this->err_msg);
            }
        }
    };

    VerifyScriptResult* verify_script(const uint8_t* scriptPubKey, uint32_t scriptPubKeyLen,
                       const uint8_t* txTo, uint32_t txToLen,
                       unsigned int nIn, unsigned int flags,
                       int64_t amount_in) {
        // Convert inputs to appropriate types
        std::vector<uint8_t> vscriptPubKey(scriptPubKey, scriptPubKey + scriptPubKeyLen);
        std::vector<uint8_t> vtxTo(txTo, txTo + txToLen);

        // Parse the transaction
        DataStream stream(vtxTo);
        const CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        // Verify the script
        ScriptError scriptErr;
        bool success = VerifyScript(
            tx.vin[nIn].scriptSig, CScript(vscriptPubKey.begin(), vscriptPubKey.end()),
            &tx.vin[nIn].scriptWitness, flags,
            TransactionSignatureChecker(&tx, nIn, amount_in, MissingDataBehavior::FAIL),
            &scriptErr
        );
        if (success) {
            return new VerifyScriptResult(success, "");
        } else {
            std::string err_msg = ScriptErrorString(scriptErr);
            return new VerifyScriptResult(success, err_msg);
        }
    }

    VerifyScriptResult* verify_tapscript(
                       const uint8_t* txTo, uint32_t txToLen,
                        // Array of pointers to byte arrays
                       const uint8_t* const* prev_outs,
                        // Array of lengths corresponding to each byte array
                       const uint32_t* prev_out_lengths,
                       uint32_t prev_out_counts,
                       unsigned int nIn, unsigned int flags,
                       int64_t amount_in) {
        // Convert inputs to appropriate types
        std::vector<uint8_t> vtxTo(txTo, txTo + txToLen);

        // Parse the transaction
        DataStream stream(vtxTo);
        const CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        std::vector<CTxOut> txouts;
        txouts.reserve(prev_out_counts);

        for (uint32_t i = 0; i < prev_out_counts; i++) {
            const uint8_t* data = prev_outs[i];
            uint32_t len = prev_out_lengths[i];

            // First 8 bytes are value (amount)
            if (len < 8) {
                return new VerifyScriptResult(false, "TxOut data too short for value");
            }

            // Parse value (amount) - assuming little endian
            CAmount value;
            std::memcpy(&value, data, sizeof(value));

            // Remaining bytes are scriptPubKey
            CScript script(data + 8, data + len);


            CTxOut txout(value, script);
            txouts.emplace_back(txout);
        }

//        std::ostringstream debug;
//        // Then where you want to print TxOut info:
//        for (size_t i = 0; i < txouts.size(); i++) {
//            const auto& txout = txouts[i];
//            debug << "TxOut " << i << ":\n";
//            debug << "  Value: " << txout.nValue << "\n";
//            debug << "  Script size: " << txout.scriptPubKey.size() << "\n";
//            debug << "  Script (hex): ";
//
//            // Simpler hex encoding
//            const uint8_t* data = txout.scriptPubKey.data();
//            for (size_t j = 0; j < txout.scriptPubKey.size(); j++) {
//                char hex[3];
//                sprintf(hex, "%02x", data[j]);
//                debug << hex;
//            }
//            debug << "\n";
//        }

        // Script path spending (stack size is >1 after removing optional annex)
        Span stack_span{tx.vin[nIn].scriptWitness.stack};
        const valtype& control = SpanPopBack(stack_span);
        const valtype& script = SpanPopBack(stack_span);

        // setup execution data
        ScriptExecutionData execdata;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        execdata.m_tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script);
        execdata.m_tapleaf_hash_init = true;
        execdata.m_validation_weight_left = ::GetSerializeSize(tx.vin[nIn].scriptWitness.stack) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;

        // sig checker
        PrecomputedTransactionData txdata(tx);
        txdata.Init(tx, std::move(txouts), false);
        TransactionSignatureChecker checker = TransactionSignatureChecker(&tx, nIn, amount_in, txdata, MissingDataBehavior::FAIL);

        // Verify the script
        ScriptError scriptErr;
        std::vector<valtype> stack{stack_span.begin(), stack_span.end()};
        CScript exec_script = CScript(script.begin(), script.end());
        bool success = EvalScript(stack, exec_script, flags, checker, SigVersion::TAPSCRIPT, execdata, &scriptErr);

        if (success) {
            // Scripts inside witness implicitly require cleanstack behaviour
            if (stack.size() != 1) return new VerifyScriptResult(false, "Stack size must be exactly one after execution");
            if (!xCastToBool(stack.back())) return new VerifyScriptResult(false, "Script evaluated without error but finished with a false/empty top stack element");

            return new VerifyScriptResult(success, "");
        } else {
            std::string err_msg = ScriptErrorString(scriptErr);
            return new VerifyScriptResult(success, err_msg);
//            return new VerifyScriptResult(success, strdup(debug.str().c_str()));
        }
    }

    /// MUST call when dropping VerifyScriptResult
    void free_verify_script_result(VerifyScriptResult* result) {
        delete result;
    }
}
