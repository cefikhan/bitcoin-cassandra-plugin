
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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cassandra.h"






 
void OutputTxJSONx(const CTransaction& tx,CassUserType* ScriptSigSimple_type ,CassUserType* vinTypeSimple_type  )
{
    std::cout<<"OUTPUTTXJSON CALLED FROM INSIDE "<<std::endl;
    UniValue entry(UniValue::VOBJ);
    TxToUnivXX(ScriptSigSimple_type, vinTypeSimple_type, tx, /*block_hash=*/uint256(), entry);


    std::string jsonOutput = entry.write(0);
    tfm::format(std::cout, "%s\n", jsonOutput);
}