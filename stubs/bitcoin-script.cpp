#include <vector>

#include <policy/policy.h>
#include <primitives/transaction.h>
#include <node/protocol_version.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>

typedef std::vector<unsigned char> valtype;

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

    VerifyScriptResult* verify_tapscript(const uint8_t* scriptPubKey, uint32_t scriptPubKeyLen,
                       const uint8_t* txTo, uint32_t txToLen,
                       unsigned int nIn, unsigned int flags,
                       int64_t amount_in) {
        // Convert inputs to appropriate types
        std::vector<uint8_t> vscriptPubKey(scriptPubKey, scriptPubKey + scriptPubKeyLen);
        std::vector<uint8_t> vtxTo(txTo, txTo + txToLen);

        // Parse the transaction
        DataStream stream(vtxTo);
        const CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        // Script path spending (stack size is >1 after removing optional annex)
        Span stack_span{tx.vin[nIn].scriptWitness.stack};
        const valtype& control = SpanPopBack(stack_span);
        const valtype& script = SpanPopBack(stack_span);
        ScriptExecutionData execdata;

        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        execdata.m_tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script);
        execdata.m_tapleaf_hash_init = true;
        execdata.m_validation_weight_left = ::GetSerializeSize(tx.vin[nIn].scriptWitness.stack) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;

        // Verify the script
        ScriptError scriptErr;
        std::vector<valtype> stack{stack_span.begin(), stack_span.end()};
        CScript exec_script = CScript(script.begin(), script.end());
        bool success = EvalScript(stack, exec_script, flags, TransactionSignatureChecker(&tx, nIn, amount_in, MissingDataBehavior::FAIL), SigVersion::TAPSCRIPT, execdata, &scriptErr);

        if (success) {
            return new VerifyScriptResult(success, "");
        } else {
            std::string err_msg = ScriptErrorString(scriptErr);
            return new VerifyScriptResult(success, err_msg);
        }
    }

    /// MUST call when dropping VerifyScriptResult
    void free_verify_script_result(VerifyScriptResult* result) {
        delete result;
    }
}
