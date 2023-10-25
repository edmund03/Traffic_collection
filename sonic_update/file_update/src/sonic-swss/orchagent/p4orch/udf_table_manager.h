#pragma once

#include <map>
#include <string>
#include <vector>

#include "copporch.h"
#include "orch.h"
#include "p4orch/acl_util.h"
#include "p4orch/object_manager_interface.h"
#include "p4orch/p4oidmapper.h"
#include "p4orch/p4orch_util.h"
#include "response_publisher_interface.h"
#include "return_code.h"
#include "vrforch.h"

extern "C"
{
#include "sai.h"
}

#define MatchLengthField "length"
#define UdfTablePriority "priority"
#define ServerAddr "tcp://127.0.0.1:9669"

#define P4RT_USER_TABLE_ADD "add"
#define P4RT_USER_TABLE_MOD "mod"
#define P4RT_USER_TABLE_GET "get"
#define P4RT_USER_TABLE_DEL "del"

#define P4RT_USER_TABLE_BATCH_ADD "batch_add"
#define P4RT_USER_TABLE_BATCH_MOD "batch_mod"
#define P4RT_USER_TABLE_BATCH_GET "batch_get"
#define P4RT_USER_TABLE_BATCH_DEL "batch_del"

#define APP_P4RT_UDF_PORTCLASSIFICATION_NAME  "FIXED_ACL"
#define APP_P4RT_UDF_PAYLOADCLASSIFICATION_NAME  "FIXED_PAYLOAD_CLASSIFICATION"

namespace p4orch
{
// namespace test
// {
// class UdfManagerTest;
// } // namespace test

class UdfTableManager : public ObjectManagerInterface
{
  public:
    virtual ~UdfTableManager() = default;
    explicit UdfTableManager(P4OidMapper *p4oidMapper, VRFOrch *vrfOrch, CoppOrch *coppOrch,
                        ResponsePublisherInterface *publisher);

    void enqueue(const swss::KeyOpFieldsValuesTuple &entry) override;
    void drain() override;

    // Update counters stats for every rule in each ACL table in COUNTERS_DB, if
    // counters are enabled in rules.
    void doUdfCounterStatsTask();
    void init_port_classification_table();
    void init_paylod_classification_table();

  private:
    // Deserializes an entry in a UDF table.
    ReturnCodeOr<P4UdfTableAppDbEntry> deserializeUdfTableAppDbEntry(
        const std::string &udf_table_name, const std::string &key,
        const std::vector<swss::FieldValueTuple> &attributes);

    // Validate a UDF rule APP_DB entry.
    ReturnCode validateUdfTableAppDbEntry(const P4UdfTableAppDbEntry &app_db_entry);

    // Processes add operation for a UDF rule.
    ReturnCode processAddRuleRequest(const std::string &udf_rule_key, const P4UdfTableAppDbEntry &app_db_entry);

    // Processes delete operation for a UDF rule.
    ReturnCode processDeleteRuleRequest(const std::string &udf_table_name, const std::string &udf_rule_key);

    // Processes update operation for a UDF rule.
    ReturnCode processUpdateRuleRequest(const P4UdfTableAppDbEntry &app_db_entry,const P4UdfRule &old_udf_rule);

    // Create a UDF rule.
    ReturnCode createUdfRule(P4UdfRule &udf_rule,std::string command);

    // Update UDF rule.
    ReturnCode updateUdfRule(P4UdfRule &udf_rule, std::string command);

    P4UdfRule *getUdfRule(const std::string &udf_table_name, const std::string &udf_rule_key);

    // Remove the ACL rule by key in the given ACL table.
    ReturnCode removeUdfRule(const std::string &udf_table_name,const std::string &udf_rule_key);

    // Validate and set all match attributes in an ACL rule.
    ReturnCode setAllMatchFieldValues(const P4UdfTableAppDbEntry &app_db_entry, P4UdfRule &udf_rule);

    // Validate and set all action attributes in an ACL rule.
    ReturnCode setAllActionFieldValues(const P4UdfTableAppDbEntry &app_db_entry,P4UdfRule &udf_rule);

    // Validate and set a match attribute in an ACL rule.
    ReturnCode setMatchValue(const std::string& attr_name,const std::string &attr_value, const UdfMatchField *udf_field, 
                                            P4UdfRule *udf_rule);

    ReturnCode waitResponse(void *m_socket, std::string& key, std::string& command, std::vector<uint8_t>& m_buffer);

    ReturnCode zmqSendRequest(const std::string& msg, std::string key, std::string command);

    // Validate and set an action attribute in an ACL rule.
    ReturnCode setActionValue(const std::string attr_name, const std::string &attr_value,Format_UDF format,
                                           uint32_t bitwidth,P4UdfRule *udf_rule);

    P4OidMapper *m_p4OidMapper;
    ResponsePublisherInterface *m_publisher;
    P4UdfTableDefinitions m_udftables; // check table definition
    P4UdfRuleTables m_udfRuleTables; //storage for udf entries.
  
    VRFOrch *m_vrfOrch;
    CoppOrch *m_coppOrch;

    std::deque<swss::KeyOpFieldsValuesTuple> m_entries;

    // friend class p4orch::test::UdfManagerTest;
};

} // namespace p4orch
