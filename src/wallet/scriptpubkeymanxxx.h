// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_SCRIPTPUBKEYMAN_H

#include <psbt.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <util/error.h>
#include <util/message.h>
#include <util/result.h>
#include <util/time.h>
#include <wallet/crypter.h>
#include <wallet/ismine.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/signals2/signal.hpp>

#include <optional>
#include <unordered_map>


#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>

#include <optional>

enum class OutputType;
struct bilingual_str;
#include <optional>





bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return SolverXXX(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}


#endif // BITCOIN_WALLET_SCRIPTPUBKEYMAN_H