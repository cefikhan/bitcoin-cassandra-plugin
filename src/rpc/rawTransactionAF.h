// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <uint256.h>
#include <undo.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <numeric>
#include <stdint.h>

#include <univalue.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;
using node::ReadBlockFromDisk;
using node::UndoReadFromDisk;



static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, RPCSerializationFlags(), txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            } else
                entry.pushKV("confirmations", 0);
        }
    }
}



static void TxToJSONAF(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUnivAF(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, RPCSerializationFlags(), txundo, verbosity);

    // if (!hashBlock.IsNull()) {
    //     LOCK(cs_main);

    //     entry.pushKV("blockhash", hashBlock.GetHex());
    //     const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
    //     if (pindex) {
    //         if (active_chainstate.m_chain.Contains(pindex)) {
    //             entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
    //             entry.pushKV("time", pindex->GetBlockTime());
    //             entry.pushKV("blocktime", pindex->GetBlockTime());
    //         } else
    //             entry.pushKV("confirmations", 0);
    //     }
    // }
}







auto AFreadTransaction(uint256 AFhashx,ChainstateManager& chainman, const CTxMemPool* const mempool ){



            // const NodeContext& node = EnsureAnyNodeContext(request.context);
            // ChainstateManager& chainman = EnsureChainman(node);
            // uint256 hash = ParseHashV(request.params[0], "parameter 1");
            uint256 hash = AFhashx;
            const CBlockIndex* blockindex = nullptr;

            if (hash == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
                // Special exception for the genesis block coinbase transaction
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
            }

            // Accept either a bool (true) or a num (>=0) to indicate verbosity.
            int verbosity{0};
            // if (!request.params[1].isNull()) {
            //     if (request.params[1].isBool()) {
            //         verbosity = request.params[1].get_bool();
            //     } else {
            //         verbosity = request.params[1].getInt<int>();
            //     }
            // }

            verbosity = 1;
            

            // if (!request.params[2].isNull()) {
            //     LOCK(cs_main);

            //     uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
            //     blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
            //     if (!blockindex) {
            //         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
            //     }
            // }

            bool f_txindex_ready = false;
            if (g_txindex && !blockindex) {
                // f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();

            }

            uint256 hash_block;
            
            // const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), hash, chainman.GetConsensus(), hash_block);
            
            const CTransactionRef tx = GetTransaction(blockindex, mempool, hash, chainman.GetConsensus(), hash_block);

            if (!tx) {
                std::string errmsg;
                if (blockindex) {
                    const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
                    if (!block_has_data) {
                        throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
                    }
                    errmsg = "No such transaction found in the provided block";
                } else if (!g_txindex) {
                    errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
                } else if (!f_txindex_ready) {
                    errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
                } else {
                    errmsg = "No such mempool or blockchain transaction";
                }
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
            }

            // if (verbosity <= 0) {
            //     return EncodeHexTx(*tx, RPCSerializationFlags());
            // }

            UniValue result(UniValue::VOBJ);
            if (blockindex) {
                LOCK(cs_main);
                result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex));
            }
            // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
            // if (request.params[2].isNull()) {
            bool noBlockGiven = true;
            if(noBlockGiven){
                LOCK(cs_main);
                blockindex = chainman.m_blockman.LookupBlockIndex(hash_block);
            }
            if (verbosity == 1) {


                // UniValue entry(UniValue::VOBJ);
                // // TxToUniv(tx, /*block_hash=*/uint256(), entry);
                // TxToUnivXX(tx, /*block_hash=*/uint256(), entry);
                // std::string jsonOutput = entry.write(4);
                // tfm::format(std::cout, "%s\n", jsonOutput);

                TxToJSONAF(*tx, hash_block, result, chainman.ActiveChainstate());
                std::string jsonOutput = result.write(4);
                tfm::format(std::cout, "%s\n", jsonOutput);
                // return result;
            std::cout<<"returned after formating anything "<<std::endl;

                return;
            }

            // CBlockUndo blockUndo;
            // CBlock block;
            // const bool is_block_pruned{WITH_LOCK(cs_main, return chainman.m_blockman.IsBlockPruned(blockindex))};

            // if (tx->IsCoinBase() ||
            //     !blockindex || is_block_pruned ||
            //     !(UndoReadFromDisk(blockUndo, blockindex) && ReadBlockFromDisk(block, blockindex, Params().GetConsensus()))) {
            //     TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
            //     return result;
            // }

            // CTxUndo* undoTX{nullptr};
            // auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t) { return *t == *tx; });
            // if (it != block.vtx.end()) {
            //     // -1 as blockundo does not have coinbase tx
            //     undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
            // }
            // TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
            // return result;
            std::cout<<"returned without anything "<<std::endl;

}


