
#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <clientversion.h>
#include <coins.h>
#include <compat/compat.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <key_io.h>
#include <fs.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/translation.h>

#include <cstdio>
#include <functional>
#include <memory>

void OutputTxJSONx(const CTransaction& tx)
{
    std::cout<<"OUTPUTTXJSON CALLED FROM INSIDE "<<std::endl;
    UniValue entry(UniValue::VOBJ);
    // TxToUniv(tx, /*block_hash=*/uint256(), entry);
    TxToUnivXX(tx, /*block_hash=*/uint256(), entry);


    std::string jsonOutput = entry.write(4);
    tfm::format(std::cout, "%s\n", jsonOutput);
}