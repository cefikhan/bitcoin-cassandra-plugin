// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CORE_IO_H
#define BITCOIN_CORE_IO_H

#include <consensus/amount.h>

#include <string>
#include <vector>
#include "cassandra.h"


class CBlock;
class CBlockHeader;
class CScript;
class CTransaction;
struct CMutableTransaction;
class SigningProvider;
class uint256;
class UniValue;
class CTxUndo;




struct collectionsStruct{
        CassCollection* collection ;
        CassCollection* vinCollection ;
        std::string id;
        std::string size;
        std::string version;
        std::string vsize;
        std::string weight;
        std::string locktime;
        std::string hex;
};

/**
 * Verbose level for block's transaction
 */
enum class TxVerbosity {
    SHOW_TXID,                //!< Only TXID for each block's transaction
    SHOW_DETAILS,             //!< Include TXID, inputs, outputs, and other common block's transaction information
    SHOW_DETAILS_AND_PREVOUT  //!< The same as previous option with information about prevouts if available
};

// core_read.cpp
CScript ParseScript(const std::string& s);
std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode = false);
[[nodiscard]] bool DecodeHexTx(CMutableTransaction& tx, const std::string& hex_tx, bool try_no_witness = false, bool try_witness = true);
[[nodiscard]] bool DecodeHexBlk(CBlock&, const std::string& strHexBlk);
bool DecodeHexBlockHeader(CBlockHeader&, const std::string& hex_header);

/**
 * Parse a hex string into 256 bits
 * @param[in] strHex a hex-formatted, 64-character string
 * @param[out] result the result of the parsing
 * @returns true if successful, false if not
 *
 * @see ParseHashV for an RPC-oriented version of this
 */
bool ParseHashStr(const std::string& strHex, uint256& result);
std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName);
int ParseSighashString(const UniValue& sighash);

// core_write.cpp
UniValue ValueFromAmount(const CAmount amount);
std::string FormatScript(const CScript& script);
std::string EncodeHexTx(const CTransaction& tx, const int serializeFlags = 0);
std::string SighashToStr(unsigned char sighash_type);
void ScriptToUniv(const CScript& script, UniValue& out, bool include_hex = true, bool include_address = false, const SigningProvider* provider = nullptr);
void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex = true, int serialize_flags = 0, const CTxUndo* txundo = nullptr, TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS);
collectionsStruct TxToUnivXX(CassUserType* ScriptSigSimple_type ,CassUserType* vinTypeSimple_type ,const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex = true, int serialize_flags = 0, const CTxUndo* txundo = nullptr, TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS);
void TxToUnivAF(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex = true, int serialize_flags = 0, const CTxUndo* txundo = nullptr, TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS);
void ScriptToUnivAF(const CScript& script, UniValue& out, bool include_hex = true, bool include_address = false, const SigningProvider* provider = nullptr);
void ScriptToUnivXX(const CScript& script, UniValue& out, bool include_hex = true, bool include_address = false, const SigningProvider* provider = nullptr);

#endif // BITCOIN_CORE_IO_H
