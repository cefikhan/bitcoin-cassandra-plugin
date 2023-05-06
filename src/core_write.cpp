// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/standard.h>
#include <serialize.h>
#include <streams.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/system.h>
#include<rpc/util.h>
#include <map>
#include <string>
#include <vector>

UniValue ValueFromAmount(const CAmount amount)
{
    static_assert(COIN > 1);
    int64_t quotient = amount / COIN;
    int64_t remainder = amount % COIN;
    if (amount < 0) {
        quotient = -quotient;
        remainder = -remainder;
    }
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", amount < 0 ? "-" : "", quotient, remainder));
}

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp(it, op, vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_NOP10) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(std::vector<uint8_t>(it2, it - vch.size())),
                                               HexStr(std::vector<uint8_t>(it - vch.size(), it)));
            } else {
                ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, it)));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, script.end())));
        break;
    }
    return ret.substr(0, ret.empty() ? ret.npos : ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};

std::string SighashToStr(unsigned char sighash_type)
{
    const auto& it = mapSigHashTypes.find(sighash_type);
    if (it == mapSigHashTypes.end()) return "";
    return it->second;
}

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        const auto it = mapSigHashTypes.find(chSigHashType);
                        if (it != mapSigHashTypes.end()) {
                            strSigHashDecode = "[" + it->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction& tx, const int serializeFlags)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | serializeFlags);
    ssTx << tx;
    return HexStr(ssTx);
}

void ScriptToUniv(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    CTxDestination address;

    out.pushKV("asm", ScriptToAsmStr(script));
    if (include_address) {
        out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
    }
    if (include_hex) {
        out.pushKV("hex", HexStr(script));
    }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
        out.pushKV("address", EncodeDestination(address));
    }
    out.pushKV("type", GetTxnOutputType(type));
}

void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, int serialize_flags, const CTxUndo* txundo, TxVerbosity verbosity)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);

    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("hash", tx.GetWitnessHash().GetHex());
    // Transaction version is actually unsigned in consensus checks, just signed in memory,
    // so cast to unsigned before giving it to the user.
    entry.pushKV("version", static_cast<int64_t>(static_cast<uint32_t>(tx.nVersion)));
    entry.pushKV("size", (int)::GetSerializeSize(tx, PROTOCOL_VERSION));
    entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    entry.pushKV("weight", GetTransactionWeight(tx));
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin{UniValue::VARR};

    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        } else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig));


            in.pushKV("scriptSig", o);
        }
        if (!tx.vin[i].scriptWitness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : tx.vin[i].scriptWitness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("txinwitness", txinwitness);
        }
        if (have_undo) {
            const Coin& prev_coin = txundo->vprevout[i];
            const CTxOut& prev_txout = prev_coin.out;

            amt_total_in += prev_txout.nValue;

            if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
                UniValue o_script_pub_key(UniValue::VOBJ);
                ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

                UniValue p(UniValue::VOBJ);
                p.pushKV("generated", bool(prev_coin.fCoinBase));
                p.pushKV("height", uint64_t(prev_coin.nHeight));
                p.pushKV("value", ValueFromAmount(prev_txout.nValue));
                p.pushKV("scriptPubKey", o_script_pub_key);
                in.pushKV("prevout", p);
            }
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);

        if (have_undo) {
            amt_total_out += txout.nValue;
        }
    }
    entry.pushKV("vout", vout);

    if (have_undo) {
        const CAmount fee = amt_total_in - amt_total_out;
        CHECK_NONFATAL(MoneyRange(fee));
        entry.pushKV("fee", ValueFromAmount(fee));
    }

    if (!block_hash.IsNull()) {
        entry.pushKV("blockhash", block_hash.GetHex());
    }

    if (include_hex) {
        entry.pushKV("hex", EncodeHexTx(tx, serialize_flags)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    }
}




//CUSTOMIZED CODE
std::string TxToUnivAF(const CTransaction& tx,uint32_t nx ,const uint256& block_hash, UniValue& entry, bool include_hex, int serialize_flags, const CTxUndo* txundo, TxVerbosity verbosity)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    std::string addresxxAF ;

    // for (i=0;i<2;i++) {
    //  cass_collection_append_string(senderCollection, "huehf4829cjdsk");
    // }




    // entry.pushKV("txid", tx.GetHash().GetHex());
    // entry.pushKV("hash", tx.GetWitnessHash().GetHex());

    // Transaction version is actually unsigned in consensus checks, just signed in memory,
    // so cast to unsigned before giving it to the user.

//Customised Logic
    // entry.pushKV("version", static_cast<int64_t>(static_cast<uint32_t>(tx.nVersion)));
    // entry.pushKV("size", (int)::GetSerializeSize(tx, PROTOCOL_VERSION));
    // entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    // entry.pushKV("weight", GetTransactionWeight(tx));
    // entry.pushKV("locktime", (int64_t)tx.nLockTime);
//till


    UniValue vin{UniValue::VARR};

    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;

    // for (unsigned int i = 0; i < tx.vin.size(); i++) {
    //     const CTxIn& txin = tx.vin[i];
    //     UniValue in(UniValue::VOBJ);
    //     if (tx.IsCoinBase()) {
    //         in.pushKV("coinbase", HexStr(txin.scriptSig));
    //     } else {
    //         in.pushKV("txid", txin.prevout.hash.GetHex());
    //         in.pushKV("vout", (int64_t)txin.prevout.n);
    //         UniValue o(UniValue::VOBJ);
    //         o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
    //         o.pushKV("hex", HexStr(txin.scriptSig));
    //         in.pushKV("scriptSig", o);
    //     }
    //     if (!tx.vin[i].scriptWitness.IsNull()) {
    //         UniValue txinwitness(UniValue::VARR);
    //         for (const auto& item : tx.vin[i].scriptWitness.stack) {
    //             txinwitness.push_back(HexStr(item));
    //         }
    //         in.pushKV("txinwitness", txinwitness);
    //     }
    //     if (have_undo) {
    //         const Coin& prev_coin = txundo->vprevout[i];
    //         const CTxOut& prev_txout = prev_coin.out;

    //         amt_total_in += prev_txout.nValue;

    //         if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
    //             UniValue o_script_pub_key(UniValue::VOBJ);
    //             ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

    //             UniValue p(UniValue::VOBJ);
    //             p.pushKV("generated", bool(prev_coin.fCoinBase));
    //             p.pushKV("height", uint64_t(prev_coin.nHeight));
    //             p.pushKV("value", ValueFromAmount(prev_txout.nValue));
    //             p.pushKV("scriptPubKey", o_script_pub_key);
    //             in.pushKV("prevout", p);
    //         }
    //     }
    //     in.pushKV("sequence", (int64_t)txin.nSequence);
    //     vin.push_back(in);
    // }
    // entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        if(i==nx){
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        // out.pushKV("value", ValueFromAmount(txout.nValue));
        // out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        addresxxAF =  ScriptToUnivAF(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("Sender Address", o);
        vout.push_back(out);
        }

    }
    entry.pushKV("vout", vout);
    return addresxxAF;

    // if (have_undo) {
    //     const CAmount fee = amt_total_in - amt_total_out;
    //     CHECK_NONFATAL(MoneyRange(fee));
    //     entry.pushKV("fee", ValueFromAmount(fee));
    // }

    // if (!block_hash.IsNull()) {
    //     entry.pushKV("blockhash", block_hash.GetHex());
    // }

    // if (include_hex) {
    //     entry.pushKV("hex", EncodeHexTx(tx, serialize_flags)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    // }
}





//CUSTOMIZED CODE
struct collectionsStruct TxToUnivXX(CassUserType* ScriptSigSimple_type ,CassUserType* vinTypeSimple_type , CassUserType* scriptpubkey_type, CassUserType* voutTypeSimple_type , const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, int serialize_flags, const CTxUndo* txundo, TxVerbosity verbosity)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);

    struct collectionsStruct s1;

    UniValue myUniValue(UniValue::VOBJ);
    //std::string jsonOutput 
    //int lastIndex


    entry.pushKV("txid", tx.GetHash().GetHex());
    //Cassandra pushing values into struct
    myUniValue.pushKV("",tx.GetHash().GetHex());
    std::string jsonOutput = myUniValue.write(0);
    int lastIndex = jsonOutput.size()-7;
    s1.id = jsonOutput.substr(5,lastIndex);
    //5+2
    // start
    //{"":"2b8d7a7ee7999b6df861fc1f398b31006eb36d89359fd347bf598979899f234c"}




    entry.pushKV("hash", tx.GetWitnessHash().GetHex());
    // Transaction version is actually unsigned in consensus checks, just signed in memory,
    // so cast to unsigned before giving it to the user.


    entry.pushKV("version", static_cast<int64_t>(static_cast<uint32_t>(tx.nVersion)));
    //Cassandra 
    myUniValue.pushKV("",static_cast<int64_t>(static_cast<uint32_t>(tx.nVersion)));
    jsonOutput = myUniValue.write(0);
    lastIndex = jsonOutput.size()-5;
    s1.version = jsonOutput.substr(4,lastIndex);
    //4+1
    //{"":1}




    entry.pushKV("size", (int)::GetSerializeSize(tx, PROTOCOL_VERSION));
    //Cassandra 
    myUniValue.pushKV("",(int)::GetSerializeSize(tx, PROTOCOL_VERSION));
    jsonOutput = myUniValue.write(0);
    lastIndex = jsonOutput.size()-5;
    s1.size = jsonOutput.substr(4,lastIndex);







    
    entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    //Cassandra
    myUniValue.pushKV("",(GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    jsonOutput = myUniValue.write(0);
    lastIndex = jsonOutput.size()-5;
    s1.vsize = jsonOutput.substr(4,lastIndex);


   
    entry.pushKV("weight", GetTransactionWeight(tx));
    //Cassandra
    myUniValue.pushKV("",GetTransactionWeight(tx));
    jsonOutput = myUniValue.write(0);
    lastIndex = jsonOutput.size()-5;
    s1.weight = jsonOutput.substr(4,lastIndex);

    entry.pushKV("locktime", (int64_t)tx.nLockTime);
   //Cassandra
    myUniValue.pushKV("",(int64_t)tx.nLockTime);
    jsonOutput = myUniValue.write(0);
    lastIndex = jsonOutput.size()-5;
    s1.locktime = jsonOutput.substr(4,lastIndex);


    UniValue vin{UniValue::VARR};
    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;


    //CASSANDRA CODE 
    CassCollection* vinCollection = NULL;
    vinCollection = cass_collection_new(CASS_COLLECTION_TYPE_LIST,4);
    // for(i=0;i<2;i++){
    //   cass_collection_append_user_type(vinCollection,vinTypeSimple_type);
    // }


    //making array of voutTypeSimple for vout
    CassCollection* collection = NULL;
    collection = cass_collection_new(CASS_COLLECTION_TYPE_LIST, 3);
    //   for (i = 0; i<2; i++) {
    //         cass_collection_append_user_type(collection, voutTypeSimple_type);
    //  }





    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        } else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            //Cassandra
            myUniValue.pushKV("", txin.prevout.hash.GetHex());
            jsonOutput = myUniValue.write(0);
            lastIndex = jsonOutput.size()-7;
            std::string txidvin = jsonOutput.substr(5,lastIndex);
            // {"":"654b0a695cb0926bd15b967e4825dbb268a8ab831457a55e009509f85fae9617"}

            in.pushKV("vout", (int64_t)txin.prevout.n);
            //Cassandra
            myUniValue.pushKV("", (int64_t)txin.prevout.n);
            jsonOutput = myUniValue.write(0);
            lastIndex = jsonOutput.size()-5;
            std::string voutin = jsonOutput.substr(4,lastIndex);
            //{"":0}
            
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            //Cassandra
            myUniValue.pushKV("",ScriptToAsmStr(txin.scriptSig, true));
            jsonOutput = myUniValue.write(0);
            lastIndex = jsonOutput.size()-7;
            std::string asmvin = jsonOutput.substr(5,lastIndex);
            // {"":"3045022016c645930581b7f56bdec567eaa59432f2d84219de6feb55b0660d7e8a1994a9022100f1a401030e1b05e011bc86baa86d27d13572ceec53fc41203f809bbef662706e[ALL] 040d0350822e59c96139822b360b3a305a0942e3450cc35857e39c51c8982ce4b315671e3d20333fed23c18da5b1afd37b6e64f3fa2ca8a36e837df5c91251df90"}



            o.pushKV("hex", HexStr(txin.scriptSig));
            //Cassandra
            myUniValue.pushKV("",HexStr(txin.scriptSig));
            jsonOutput = myUniValue.write(0);
            std::cout<<"Hex ---->>>>>>Cxxxx "<<std::endl;
            std::cout<<jsonOutput<<std::endl;
            lastIndex = jsonOutput.size()-7;
            std::string HexIn = jsonOutput.substr(5,lastIndex);
            //{"":"483045022100828d4169ac0ab22d4af292cd391ee626cc90a9f7adf90f8dc715d42e4c3811fe02205526274bdd94b6649f06bee7e61348e2f3b023f1ba38b94bfea4464468bf3a3a014104a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5"}


            //Add logic to
            std::cout<<"LOGGING ScriptSig Public Key ID NOWWW --->>>"<<std::endl;
            //Setting values of scriptSigSimple
            cass_user_type_set_string_by_name(ScriptSigSimple_type,"asm",asmvin.c_str());
            cass_user_type_set_string_by_name(ScriptSigSimple_type,"hex",HexIn.c_str());

            //setting values of vinTypeSimple
            cass_user_type_set_string_by_name(vinTypeSimple_type,"txid",txidvin.c_str());
            cass_user_type_set_string_by_name(vinTypeSimple_type,"vout",voutin.c_str());
            cass_user_type_set_user_type_by_name(vinTypeSimple_type, "scriptsig", ScriptSigSimple_type);


            in.pushKV("scriptSig", o);
            // in.pushKV("scriptSigXXX", o_script_SIG_key);
        }
        if (!tx.vin[i].scriptWitness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : tx.vin[i].scriptWitness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("txinwitness", txinwitness);
        }
        if (have_undo) {
            const Coin& prev_coin = txundo->vprevout[i];
            const CTxOut& prev_txout = prev_coin.out;

            amt_total_in += prev_txout.nValue;

            if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
                UniValue o_script_pub_key(UniValue::VOBJ);
                ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

                UniValue p(UniValue::VOBJ);
                p.pushKV("generated", bool(prev_coin.fCoinBase));
                p.pushKV("height", uint64_t(prev_coin.nHeight));
                p.pushKV("value", ValueFromAmount(prev_txout.nValue));
                p.pushKV("scriptPubKey", o_script_pub_key);
                in.pushKV("prevout", p);
            }
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);

        //Cassandra
        myUniValue.pushKV("",  (int64_t)txin.nSequence);
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-5;
        std::string sequnceIN = jsonOutput.substr(4,lastIndex);
        cass_user_type_set_string_by_name(vinTypeSimple_type,"sequence",sequnceIN.c_str());

        vin.push_back(in);
        //Cassandra Code
        //in is object
        //we will return vinCollection
        cass_collection_append_user_type(vinCollection,vinTypeSimple_type);

    }
    entry.pushKV("vin", vin);



    //PREPERATION FOR VOUT

    cass_user_type_set_user_type_by_name(voutTypeSimple_type, "scriptpubkey", scriptpubkey_type);


    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));

        //Cassandra
        myUniValue.pushKV("",ValueFromAmount(txout.nValue));
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-5;
        std::string ValueX = jsonOutput.substr(4,lastIndex);

        out.pushKV("n", (int64_t)i);
        //Cassandra
        myUniValue.pushKV("", (int64_t)i);
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-5;
        std::string nx = jsonOutput.substr(4,lastIndex);



        UniValue o(UniValue::VOBJ);          
        // ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        struct retScriptUnivXX s2x= ScriptToUnivXX(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("scriptPubKey", o);

        //CASSANDRA CODE --- >>>>
        cass_user_type_set_string_by_name(scriptpubkey_type,"asm",s2x.asmS.c_str());
        cass_user_type_set_string_by_name(scriptpubkey_type,"des",s2x.descS.c_str());
        cass_user_type_set_string_by_name(scriptpubkey_type,"hex",s2x.hexS.c_str());
        cass_user_type_set_string_by_name(scriptpubkey_type,"address",s2x.addressS.c_str());
        cass_user_type_set_string_by_name(scriptpubkey_type,"type",s2x.typeS.c_str());
        //CASSANDRA CODE -----xxxx
        cass_user_type_set_string_by_name(voutTypeSimple_type, "value", ValueX.c_str());
        cass_user_type_set_string_by_name(voutTypeSimple_type, "n", nx.c_str());
        cass_user_type_set_user_type_by_name(voutTypeSimple_type, "scriptpubkey", scriptpubkey_type);
        cass_collection_append_user_type(collection, voutTypeSimple_type);


        vout.push_back(out);

        if (have_undo) {
            amt_total_out += txout.nValue;
        }
    }
    entry.pushKV("vout", vout);

    if (have_undo) {
        const CAmount fee = amt_total_in - amt_total_out;
        CHECK_NONFATAL(MoneyRange(fee));
        entry.pushKV("fee", ValueFromAmount(fee));
    }

    if (!block_hash.IsNull()) {
        entry.pushKV("blockhash", block_hash.GetHex());
    }

    if (include_hex) {
        entry.pushKV("hex", EncodeHexTx(tx, serialize_flags)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    }
    
    s1.collection=collection;
    s1.vinCollection=vinCollection;

    return s1;

}


//Customised ScriptToUniv
std::string ScriptToUnivAF(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    CTxDestination address;
std::string addrexx;
    // out.pushKV("asm", ScriptToAsmStr(script));
    // if (include_address) {
    //     out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
    // }
    // if (include_hex) {
    //     out.pushKV("hex", HexStr(script));
    // }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    // if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
    //     out.pushKV("address", EncodeDestination(address));
    // }

    if (include_address && ExtractDestination(script, address)) {
        out.pushKV("address", EncodeDestination(address));

            //Cassandra
            UniValue myUniValue(UniValue::VOBJ);

            myUniValue.pushKV("",EncodeDestination(address));
            std::string jsonOutput = myUniValue.write(0);
            int lastIndex = jsonOutput.size()-7;
            std::string addrexx = jsonOutput.substr(5,lastIndex);




    }
    return addrexx;
    // out.pushKV("type", GetTxnOutputType(type));
}



//it worked !
struct retScriptUnivXX ScriptToUnivXX(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    CTxDestination address;

    struct retScriptUnivXX s2x;

    out.pushKV("asm", ScriptToAsmStr(script));



    
    
    UniValue myUniValue(UniValue::VOBJ);


    //Cassandra
    myUniValue.pushKV("",ScriptToAsmStr(script));
    std::string jsonOutput = myUniValue.write(0);
    int lastIndex = jsonOutput.size()-7;
    std::string asmvo = jsonOutput.substr(5,lastIndex);
    s2x.asmS=asmvo;




    if (include_address) {
        out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
        
        //Cassandra
        myUniValue.pushKV("", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-7;
        std::string descX = jsonOutput.substr(5,lastIndex);
        s2x.descS=descX;


    }
    if (include_hex) {
        out.pushKV("hex", HexStr(script));
        
        //Cassandra
        myUniValue.pushKV("",HexStr(script));
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-7;
        std::string hexX = jsonOutput.substr(5,lastIndex);
        s2x.hexS=hexX;
    }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    // if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
    //     out.pushKV("address", EncodeDestination(address));
    // }

    //Customised Logic
    if (include_address && ExtractDestination(script, address)) {
        std::cout<<"Entered ExtractDestination "<<std::endl;
        out.pushKV("address", EncodeDestination(address));
        //Cassandra
        myUniValue.pushKV("",EncodeDestination(address));
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-7;
        std::string hexX = jsonOutput.substr(5,lastIndex);
        s2x.addressS=hexX;
    }
    out.pushKV("type", GetTxnOutputType(type));
        
        //Cassandra
        myUniValue.pushKV("",GetTxnOutputType(type));
        jsonOutput = myUniValue.write(0);
        lastIndex = jsonOutput.size()-7;
        std::string typeVo = jsonOutput.substr(5,lastIndex);
        s2x.typeS=typeVo;
        return s2x;
}