#include "p4orch/udf_table_manager.h"

#include <endian.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <zmq.h>

#include "converter.h"
#include "crmorch.h"
#include "json.hpp"
#include "logger.h"
#include "orch.h"
#include "p4orch.h"
#include "p4orch/p4orch_util.h"
#include "portsorch.h"
#include "sai_serialize.h"
#include "tokenize.h"

#define ZMQ_RESPONSE_UDF_BUFFER_SIZE (4*1024*1024)

extern "C"
{
#include "sai.h"
}

extern sai_object_id_t gSwitchId;
// extern sai_acl_api_t *sai_acl_api;
// extern sai_policer_api_t *sai_policer_api;
// extern sai_hostif_api_t *sai_hostif_api;
extern CrmOrch *gCrmOrch;
extern PortsOrch *gPortsOrch;
extern P4Orch *gP4Orch;

namespace p4orch
{
namespace
{

const std::string concatTableNameAndRuleKey(const std::string &table_name, const std::string &rule_key)
{
    return table_name + kTableKeyDelimiter + rule_key;
}

std::string NetworkOrderTransToLittleEndian(uint32_t *value, int size)
{
    std::string S_value;
        //to host byte order

    for(int i = 0 ; i < size; i++) {
        std::ostringstream s_value_u32;
        value[i] = ntohl(value[i]);
        value[i] = htole32(value[i]);
        s_value_u32 << std::hex << std::setw(8)<<std::setfill('0')<<value[i];
        S_value.append(s_value_u32.str());
    }

    return S_value;
}

std::string U16NetworkOrderTransToLittleEndian(uint16_t *value, int size)
{
    std::string S_value;
        //to host byte order

    for(int i = 0 ; i < size; i++) {
        std::ostringstream s_value_u16;
        value[i] = ntohs(value[i]);
        value[i] = htole16(value[i]);
        s_value_u16 << std::hex << std::setw(4)<<std::setfill('0')<<value[i];
        S_value.append(s_value_u16.str());
    }

    return S_value;
}

void InitUdfTableMatchElement(P4UdfTableDefinition &udf,std::string match_name, uint32_t bitwidth, 
                              Format_UDF matchformat, Match_Type_UDF match_type)
{
    udf.udf_match_field_lookup[match_name].bitwidth = bitwidth;
    udf.udf_match_field_lookup[match_name].format = matchformat;
    udf.udf_match_field_lookup[match_name].match_type = match_type;
}

void InitUdfTableActionElement(P4UdfTableDefinition &udf,std::string action_name,std::string param_name,
                               std::string param_value,uint32_t bitwidth, Format_UDF actionformat)
{
    UdfActionWithParam param;
    param.action = action_name;
    param.param_name = param_name;
    param.param_value = param_value;
    param.bitwidth = bitwidth;
    param.format = actionformat;
    udf.rule_action_field_lookup[action_name].push_back(param);
}


// bool isUdfDiffActionFieldValue(const std::string value,const std::string old_value)
// {
//     return value != old_value;
// }

} // namespace

UdfTableManager::UdfTableManager(P4OidMapper *p4oidMapper, VRFOrch *vrfOrch, CoppOrch *coppOrch,
                        ResponsePublisherInterface *publisher)
    : m_p4OidMapper(p4oidMapper), m_vrfOrch(vrfOrch), m_publisher(publisher), m_coppOrch(coppOrch)
        // m_countersDb(std::make_unique<swss::DBConnector>("COUNTERS_DB", 0)),
        // m_countersTable(std::make_unique<swss::Table>(
        //     m_countersDb.get(), std::string(COUNTERS_TABLE) + DEFAULT_KEY_SEPARATOR + APP_P4RT_TABLE_NAME))
{
    SWSS_LOG_ENTER();
    assert(m_p4OidMapper != nullptr);
    SWSS_LOG_NOTICE("UdfTableManager create\n");
    /*init table definition*/
    init_port_classification_table();
    init_paylod_classification_table();
    SWSS_LOG_NOTICE("init udf table definition success\n");
}

void UdfTableManager::init_port_classification_table()
{
    P4UdfTableDefinition port_classification_table;
    /*init port collection table*/
    port_classification_table.udf_table_name = APP_P4RT_UDF_PORTCLASSIFICATION_NAME;
    port_classification_table.priority = 0; //means not set;
    port_classification_table.size = 0; //means not set;

    /*init match filed*/
    InitUdfTableMatchElement(port_classification_table,"is_ip",1,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::IGNORE_UDF);
    InitUdfTableMatchElement(port_classification_table,"is_ipv4",1,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::IGNORE_UDF);
    InitUdfTableMatchElement(port_classification_table,"is_ipv6",1,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::IGNORE_UDF);
    InitUdfTableMatchElement(port_classification_table,"mac_type",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"mac_src_addr",48,Format_UDF::MAC_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"mac_dst_addr",48,Format_UDF::MAC_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_src_addr_v4",32,Format_UDF::IPV4_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_dst_addr_v4",32,Format_UDF::IPV4_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_src_addr_v6",128,Format_UDF::IPV6_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_dst_addr_v6",128,Format_UDF::IPV6_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_ttl",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_tos",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_proto",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ip_frag",2,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"l4_dst_port",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"is_vlan",1,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"tcp_flags",8,Format_UDF::IPV4_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"l4_src_port",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"l4_src_port_label",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"l4_dst_port_label",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"ingress_port",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"bd_label",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"is_QinQ",1,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"vlan_id",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(port_classification_table,"QinQ_vlan_id",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);

    /*init action field*/
    InitUdfTableActionElement(port_classification_table,"NoAction","","",0,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(port_classification_table,"port_collection","meter_index","0",32,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(port_classification_table,"port_collection","session_id","0",32,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(port_classification_table,"port_collection","app_id","0",12,Format_UDF::HEX_STRING_UDF);

    m_udftables[port_classification_table.udf_table_name] = port_classification_table;
}

void UdfTableManager::init_paylod_classification_table()
{
    P4UdfTableDefinition payload_classification_table;
    /*init payload classification_table*/
    payload_classification_table.udf_table_name = APP_P4RT_UDF_PAYLOADCLASSIFICATION_NAME;
    payload_classification_table.priority = 0;
    payload_classification_table.size = 0;


    InitUdfTableMatchElement(payload_classification_table,"l4_src_port",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"l4_dst_port",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"tcp_or_udp",8,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"payload32_0",32,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"payload32_1",32,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"payload32_2",32,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"payload32_3",32,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::TERNARY_UDF);
    InitUdfTableMatchElement(payload_classification_table,"payload_length",16,Format_UDF::HEX_STRING_UDF,Match_Type_UDF::RANGE_UDF);

    InitUdfTableActionElement(payload_classification_table,"payload_port_collection","meter_index","0",8,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(payload_classification_table,"payload_port_collection","session_id","0",10,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(payload_classification_table,"payload_port_collection","app_id","0",12,Format_UDF::HEX_STRING_UDF);
    InitUdfTableActionElement(payload_classification_table,"payload_port_snort3","","",0,Format_UDF::HEX_STRING_UDF);

    m_udftables[payload_classification_table.udf_table_name] = payload_classification_table;

}


void UdfTableManager::enqueue(const swss::KeyOpFieldsValuesTuple &entry)
{
    SWSS_LOG_ENTER();
    SWSS_LOG_NOTICE("%s:%d enqueue",__func__,__LINE__);
    m_entries.push_back(entry);
    SWSS_LOG_NOTICE("%s:%d enqueue",__func__,__LINE__);
}

void UdfTableManager::drain()
{
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("%s:%d drain",__func__,__LINE__);
    for (const auto &key_op_fvs_tuple : m_entries)
    {   /*get every entry in m_entries to process...*/
        std::string table_name;
        std::string db_key;

        parseP4RTKey(kfvKey(key_op_fvs_tuple), &table_name, &db_key);
        const auto &op = kfvOp(key_op_fvs_tuple);
        const std::vector<swss::FieldValueTuple> &attributes = kfvFieldsValues(key_op_fvs_tuple);
        /*get kvopvaluetuple */

        SWSS_LOG_NOTICE("OP: %s, RULE_KEY: %s", op.c_str(), QuotedVar(db_key).c_str());


        SWSS_LOG_NOTICE("%s:%d OP: %s, RULE_KEY: %s",__func__,__LINE__,op.c_str(), QuotedVar(db_key).c_str());
        ReturnCode status;
        auto app_db_entry_or = deserializeUdfTableAppDbEntry(table_name, db_key, attributes);
        if (!app_db_entry_or.ok())
        {
            status = app_db_entry_or.status();
            SWSS_LOG_ERROR("Unable to deserialize APP DB entry with key %s: %s",
                           QuotedVar(table_name + ":" + db_key).c_str(), status.message().c_str());
            m_publisher->publish(APP_P4RT_TABLE_NAME, kfvKey(key_op_fvs_tuple), kfvFieldsValues(key_op_fvs_tuple),
                                 status,
                                 /*replace=*/true);
            continue;
        }
        auto &app_db_entry = *app_db_entry_or;
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        status = validateUdfTableAppDbEntry(app_db_entry);
        if (!status.ok())
        {
            SWSS_LOG_ERROR("Validation failed for ACL rule APP DB entry with key %s: %s",
                           QuotedVar(table_name + ":" + db_key).c_str(), status.message().c_str());
            m_publisher->publish(APP_P4RT_TABLE_NAME, kfvKey(key_op_fvs_tuple), kfvFieldsValues(key_op_fvs_tuple),
                                 status,
                                 /*replace=*/true);
            continue;
        }
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        const auto &udf_table_name = app_db_entry.udf_table_name;
        //create key for storage
        const auto &udf_rule_key =
            KeyGenerator::generateAclRuleKey(app_db_entry.match_fvs, std::to_string(app_db_entry.priority)); 
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        const auto &operation = kfvOp(key_op_fvs_tuple);
        if (operation == SET_COMMAND)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            auto *udf_rule = getUdfRule(udf_table_name, udf_rule_key);
            if (udf_rule == nullptr)
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                status = processAddRuleRequest(udf_rule_key, app_db_entry);
            }
            else
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                //if we find the same key, sure it is an upate operation
                status = processUpdateRuleRequest(app_db_entry, *udf_rule);
            }
        }
        else if (operation == DEL_COMMAND)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            status = processDeleteRuleRequest(udf_table_name, udf_rule_key);
        }
        else
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            status = ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "Unknown operation type " << operation;
            SWSS_LOG_ERROR("%s", status.message().c_str());
        }
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        m_publisher->publish(APP_P4RT_TABLE_NAME, kfvKey(key_op_fvs_tuple), kfvFieldsValues(key_op_fvs_tuple), status,
                             /*replace=*/true);
    }
    m_entries.clear();
}

ReturnCodeOr<P4UdfTableAppDbEntry> UdfTableManager::deserializeUdfTableAppDbEntry(
    const std::string &udf_table_name, const std::string &key, const std::vector<swss::FieldValueTuple> &attributes)
{
    SWSS_LOG_ENTER();
    P4UdfTableAppDbEntry app_db_entry = {};
    app_db_entry.udf_table_name = udf_table_name;
    app_db_entry.db_key = concatTableNameAndRuleKey(udf_table_name, key);
    // Parse rule key : match fields and priority
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    try
    {
        const auto &rule_key_json = nlohmann::json::parse(key);
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        if (!rule_key_json.is_object())
        {
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "Invalid ACL rule key: should be a JSON object.";
        }
        for (auto rule_key_it = rule_key_json.begin(); rule_key_it != rule_key_json.end(); ++rule_key_it)
        {
            if (rule_key_it.key() == kPriority)
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                if (!rule_key_it.value().is_number_unsigned())
                {
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "Invalid ACL rule priority type: should be uint32_t";
                }
                app_db_entry.priority = rule_key_it.value();
                continue;
            }
            else
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                const auto &tokenized_match_field = tokenize(rule_key_it.key(), kFieldDelimiter);
                if (tokenized_match_field.size() <= 1 || tokenized_match_field[0] != kMatchPrefix)
                {
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "Unknown Udf match field string " << QuotedVar(rule_key_it.key());
                }
                app_db_entry.match_fvs[tokenized_match_field[1]] = rule_key_it.value();
            }
        }
    }
    catch (std::exception &e)
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "Failed to deserialize UDF rule match key";
    }

    for (const auto &it : attributes)
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        const auto &field = fvField(it);
        const auto &value = fvValue(it);

        SWSS_LOG_NOTICE("%s:%d GET FILED:%s VALLUE:%s",__func__,__LINE__,field.c_str(),value.c_str());
        if (field == kControllerMetadata)
            continue;
        if (field == kAction)
        {
            app_db_entry.action = value;
            continue;
        }

        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        const auto &tokenized_field = tokenize(field, kFieldDelimiter);
        if (tokenized_field.size() <= 1)
        {
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "Unknown UDF rule field " << QuotedVar(field);
        }

        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        const auto &prefix = tokenized_field[0];
        if (prefix == kActionParamPrefix)
        {
            const auto &param_name = tokenized_field[1];
            app_db_entry.action_param_fvs[param_name] = value;
            SWSS_LOG_NOTICE("%s:%d WRITE FILED:%s VALLUE:%s",__func__,__LINE__,param_name.c_str(),value.c_str());
        }
        else if (prefix == kMeterPrefix)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "meter field not support " << QuotedVar(field);
        }
        else
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM) << "Unknown UDF rule field " << QuotedVar(field);
        }
    }
    return app_db_entry;
}

ReturnCode UdfTableManager::validateUdfTableAppDbEntry(const P4UdfTableAppDbEntry &app_db_entry)
{
    SWSS_LOG_ENTER();
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    if (app_db_entry.priority == 0)
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
               << "Udf rule in table " << QuotedVar(app_db_entry.udf_table_name) << " is missing priority";
    }
    return ReturnCode();
}

P4UdfRule *UdfTableManager::getUdfRule(const std::string &udf_table_name, const std::string &udf_rule_key)
{
    SWSS_LOG_ENTER();
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    if (m_udfRuleTables[udf_table_name].find(udf_rule_key) == m_udfRuleTables[udf_table_name].end())
    {
        return nullptr;
    }
    return &m_udfRuleTables[udf_table_name][udf_rule_key];
}

ReturnCode UdfTableManager::setMatchValue(const std::string& attr_name,const std::string &attr_value, const UdfMatchField *udf_field, 
                                            P4UdfRule *udf_rule)
{
      SWSS_LOG_ENTER();
      SWSS_LOG_NOTICE("%s:%d match attr_name:%s attr_value:%s",__func__,__LINE__,attr_name.c_str(), attr_value.c_str());
      if(udf_field->match_type == Match_Type_UDF::IGNORE_UDF)
            return ReturnCode();
    try
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        switch (udf_field->format)
        {
        case Format_UDF::HEX_STRING_UDF: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            const std::vector<std::string> &value_and_mask = tokenize(attr_value, kDataMaskDelimiter);
            if(udf_field->match_type == Match_Type_UDF::LPM_UDF || udf_field->match_type == Match_Type_UDF::TERNARY_UDF || udf_field->match_type == Match_Type_UDF::RANGE_UDF){
                if (value_and_mask.size() > 1)
                {
                    udf_rule->match_fvs[attr_name] = std::string(trim(value_and_mask[0])+"&"+trim(value_and_mask[1]));
                }else{
                    std::ostringstream ss;
                    uint32_t mask = (1 << udf_field->bitwidth) - 1; 
                    ss << std::hex << mask;
                    std::string result = ss.str();
                    udf_rule->match_fvs[attr_name] = std::string(trim(value_and_mask[0])+"&"+result);//if dont set mask, we set biggest mask.
                }
            } else {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                udf_rule->match_fvs[attr_name] = std::string(trim(value_and_mask[0]));
            }
            break;
        }
        case Format_UDF::IPV4_UDF: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            const auto &tokenized_ip = tokenize(attr_value, kDataMaskDelimiter); // take ipv4 . need to process it to byte stream.
            uint32_t ipaddr = 0;
            uint32_t ipmask = 0;
            if (tokenized_ip.size() == 2)
            {
                // data & mask
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                swss::IpAddress ip_data(trim(tokenized_ip[0]));
                if (!ip_data.isV4())
                {
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP data type should be v4 type: " << QuotedVar(attr_value);
                }
                swss::IpAddress ip_mask(trim(tokenized_ip[1]));
                if (!ip_mask.isV4())
                {
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP mask type should be v4 type: " << QuotedVar(attr_value);
                }
                ipaddr = ip_data.getV4Addr();
                ipmask = ip_mask.getV4Addr();
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            }
            else
            {
                // LPM annotated value
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                swss::IpPrefix ip_prefix(trim(attr_value));
                if (!ip_prefix.isV4())
                {
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP type should be v6 type: " << QuotedVar(attr_value);
                }
                ipaddr = ip_prefix.getIp().getV4Addr();
                ipmask = ip_prefix.getMask().getV4Addr();
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            }
            //need to get to little endian byte.
            ipaddr = ntohl(ipaddr);
            ipmask = ntohl(ipmask);
            //to little endian
            ipaddr = htole32(ipaddr);
            ipmask = htole32(ipmask);

            std::ostringstream s_ip;
            s_ip << std::hex << std::setw(8)<<std::setfill('0')<< ipaddr;
            
            std::string S_ip = std::string("00000000"+s_ip.str()+"0000000000000000");
            

            std::ostringstream s_ipmask;
            s_ipmask << std::hex <<std::setw(8)<<std::setfill('0')<< ipmask;
            std::string S_ipmask = std::string("00000000"+s_ipmask.str()+"0000000000000000");

            if(attr_name.find("ip_src_addr") != std::string::npos)
                udf_rule->match_fvs["ip_src_addr"] = std::string("0x"+S_ip + "&" + "0x" +S_ipmask);
            else if(attr_name.find("ip_dst_addr") != std::string::npos)
                udf_rule->match_fvs["ip_dst_addr"] = std::string("0x"+S_ip + "&" + "0x" +S_ipmask);
            else 
                udf_rule->match_fvs[attr_name] = std::string("0x"+S_ip + "&" + "0x" +S_ipmask);

            SWSS_LOG_NOTICE("%s:%d ip match attr_value:%s attr_mask:%s",__func__,__LINE__,S_ip.c_str(), S_ipmask.c_str());
            break;
        }
        case Format_UDF::IPV6_UDF: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            const auto &tokenized_ip = tokenize(attr_value, kDataMaskDelimiter);
            uint32_t *ipaddr = (uint32_t *)malloc(sizeof(uint32_t) * 4);
            uint32_t *ipmask = (uint32_t *)malloc(sizeof(uint32_t) * 4);
            if(!ipaddr || !ipmask) {
                return ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                        << "malloc function return NULL pointer,cannot insert:" <<QuotedVar(attr_value);
            }
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            memset(ipaddr, 0 ,sizeof(uint32_t) * 4);
            memset(ipmask, 0 ,sizeof(uint32_t) * 4);

            if (tokenized_ip.size() == 2)
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                // data & mask
                swss::IpAddress ip_data(trim(tokenized_ip[0]));
                if (ip_data.isV4())
                {
                    free(ipaddr);
                    free(ipmask);
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP data type should be v6 type: " << QuotedVar(attr_value);
                }
                swss::IpAddress ip_mask(trim(tokenized_ip[1]));
                if (ip_mask.isV4())
                {
                    free(ipaddr);
                    free(ipmask);
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP mask type should be v6 type: " << QuotedVar(attr_value);
                }
                memcpy(ipaddr, ip_data.getV6Addr(), sizeof(sai_ip6_t));
                memcpy(ipmask, ip_mask.getV6Addr(), sizeof(sai_ip6_t));
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            }
            else
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                // LPM annotated value
                swss::IpPrefix ip_prefix(trim(attr_value));
                if (ip_prefix.isV4())
                {
                    free(ipaddr);
                    free(ipmask);
                    return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                           << "IP type should be v6 type: " << QuotedVar(attr_value);
                }
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                memcpy(ipaddr, ip_prefix.getIp().getV6Addr(), sizeof(sai_ip6_t));
                memcpy(ipmask, ip_prefix.getMask().getV6Addr(), sizeof(sai_ip6_t));
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            }

            std::string S_ipV6;
            std::string S_ipV6Mask;
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            S_ipV6 = NetworkOrderTransToLittleEndian(ipaddr,4);
            S_ipV6Mask = NetworkOrderTransToLittleEndian(ipmask,4);
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            if(attr_name.find("ip_dst_addr") != std::string::npos)
                udf_rule->match_fvs["ip_dst_addr"] = std::string("0x"+S_ipV6 + "&" + "0x" + S_ipV6Mask);
            else if(attr_name.find("ip_src_addr") != std::string::npos)
                udf_rule->match_fvs["ip_src_addr"] = std::string("0x"+S_ipV6 + "&" + "0x" + S_ipV6Mask);
            else
                udf_rule->match_fvs[attr_name] = std::string("0x"+S_ipV6 + "&" + "0x" + S_ipV6Mask);
    
            free(ipaddr);
            free(ipmask);
           SWSS_LOG_NOTICE("%s:%d ipv6 match attr_value:%s attr_mask:%s",__func__,__LINE__,S_ipV6.c_str(), S_ipV6Mask.c_str());
            break;
        }
        case Format_UDF::MAC_UDF: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            const std::vector<std::string> mask_and_value = tokenize(attr_value, kDataMaskDelimiter);
            swss::MacAddress mac(trim(mask_and_value[0]));
            uint16_t *mac_address = (uint16_t *)malloc(sizeof(uint16_t) * 3);
            uint16_t *mac_Mask = (uint16_t *)malloc(sizeof(uint16_t) * 3);

            if(!mac_address || !mac_Mask){
                return ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                        << "malloc function return NULL pointer,cannot insert:" <<QuotedVar(attr_value);
            }
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            memset(mac_address, 0 ,sizeof(uint16_t) * 3);
            memset(mac_Mask, 0 ,sizeof(uint16_t) * 3);
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            memcpy(mac_address, mac.getMac(), sizeof(sai_mac_t));
            if (mask_and_value.size() > 1)
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                swss::MacAddress mask(trim(mask_and_value[1]));
                memcpy(mac_Mask, mask.getMac(), sizeof(sai_mac_t));
            }
            else
            {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                const sai_mac_t mac_mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                memcpy(mac_Mask, mac_mask, sizeof(sai_mac_t));
            }

            std::string S_macaddr;
            std::string S_macaddrMask;

            S_macaddr = U16NetworkOrderTransToLittleEndian(mac_address,3);
            S_macaddrMask = U16NetworkOrderTransToLittleEndian(mac_Mask,3);

            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            udf_rule->match_fvs[attr_name] = std::string("0x"+S_macaddr + "&" +"0x"+S_macaddrMask);
            free(mac_address);
            free(mac_Mask);
            break;
        }
        case Format_UDF::STRING_UDF: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
             udf_rule->match_fvs[attr_name] = std::string(trim(attr_value));
            break;
        }
        case Format_UDF::PORT_STRING_UDF:{
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            //const auto &ports = tokenize(attr_value, kPortsDelimiter);
            //TODO support later if we need this.
             return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "UDF match field " << attr_name << " is not supported.";
        }
        default: {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "UDF match field " << attr_name << " is not supported.";
        }
        }
    }
    catch (std::exception &e)
    {
        return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
               << "Failed to parse match attribute " << attr_name << " value: " << QuotedVar(attr_value);
    }
    
    return ReturnCode();
}

ReturnCode UdfTableManager::setAllMatchFieldValues(const P4UdfTableAppDbEntry &app_db_entry, P4UdfRule &udf_rule)
{
    SWSS_LOG_ENTER();
    auto udf_table_it = m_udftables.find(app_db_entry.udf_table_name);

    for (const auto &match_fv : app_db_entry.match_fvs)
    {
        const auto &match_field = fvField(match_fv);
        const auto &match_value = fvValue(match_fv);
        ReturnCode set_match_rc;    
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);

        /*process match field*/
        auto match_field_it = udf_table_it->second.udf_match_field_lookup.find(match_field);
        if(match_field_it != udf_table_it->second.udf_match_field_lookup.end())
        {
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                auto & udf_field= match_field_it->second;
                SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
                set_match_rc = setMatchValue(match_field,match_value,&udf_field,&udf_rule);
                if (!set_match_rc.ok())
                {
                    set_match_rc.prepend("Invalid UDF rule match field " + QuotedVar(match_field) + ": " +
                                         QuotedVar(match_value) + " to add: ");
                    return set_match_rc;
                }
            
        }

    }
   
    return ReturnCode();
}

ReturnCode UdfTableManager::setAllActionFieldValues(const P4UdfTableAppDbEntry &app_db_entry,P4UdfRule &udf_rule)
{
    SWSS_LOG_ENTER();
    auto udf_table_it = m_udftables.find(app_db_entry.udf_table_name);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    const auto &action_param_list_it = udf_table_it->second.rule_action_field_lookup.find(app_db_entry.action);
    if (action_param_list_it == udf_table_it->second.rule_action_field_lookup.end())
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                            << "Invalid P4 ACL action " << QuotedVar(app_db_entry.action);
        return status;
    }

    UdfActionWithParam udf_action_param;
    for (const auto &action_param : action_param_list_it->second)
    {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        udf_action_param.action = action_param.action;
        udf_action_param.param_name = action_param.param_name;
        udf_action_param.param_value = action_param.param_value;
        udf_action_param.bitwidth = action_param.bitwidth;
        udf_action_param.format = action_param.format;
        if (!action_param.param_name.empty())
        {
            const auto &param_value_it = app_db_entry.action_param_fvs.find(action_param.param_name);
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            if (param_value_it == app_db_entry.action_param_fvs.end())
            {
                ReturnCode status = ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                                    << "No action param found for action " << action_param.action;
                return status;
            }
            if (!param_value_it->second.empty())
            {
                udf_action_param.param_value = param_value_it->second;
            }
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        }
        auto set_action_rc = setActionValue(udf_action_param.param_name, udf_action_param.param_value, udf_action_param.format,
                                            udf_action_param.bitwidth,&udf_rule);
        if (!set_action_rc.ok())
        {
            return set_action_rc;
        }
    }
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    return ReturnCode();
}

ReturnCode UdfTableManager::setActionValue(const std::string attr_name, const std::string &attr_value,Format_UDF format,
                                           uint32_t bitwidth,P4UdfRule *udf_rule)
{
    SWSS_LOG_ENTER();
    
    SWSS_LOG_NOTICE("%s:%d Action attr_name: %s attr_value: %s",__func__,__LINE__,attr_name.c_str(),attr_value.c_str());
    switch (format)
    {
    case Format_UDF::HEX_STRING_UDF: {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        if(attr_value.find("0x") != std::string::npos)
            udf_rule->action_fvs[attr_name] = std::string(trim(attr_value));
        else{
            uint64_t value = to_uint<uint64_t>(attr_value);
            uint32_t bytes = (bitwidth + 7) / 8;
            std::ostringstream s_value;
            s_value << std::hex << std::setw(bytes)<<std::setfill('0')<<value;
            std::string S_value = s_value.str();
            udf_rule->action_fvs[attr_name] = std::string(trim(S_value));
        }

        break;
    }
    case Format_UDF::IPV4_UDF: {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        uint32_t ipaddr = 0;
        try
        {
            swss::IpAddress ip(attr_value);
            if (!ip.isV4())
            {
                return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                       << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                       << QuotedVar(udf_rule->udf_table_name) << ": Expect IPv4 address but got "
                       << QuotedVar(attr_value);
            }
            ipaddr= ip.getV4Addr();
        }
        catch (std::exception &e)
        {
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                   << QuotedVar(udf_rule->udf_table_name) << ": Expect IP address but got " << QuotedVar(attr_value);
        }

        //need to get to little endian byte.
        ipaddr = ntohl(ipaddr);
        //to little endian
        ipaddr = htole32(ipaddr);

        std::ostringstream s_ip;
        s_ip << std::hex << ipaddr;
        std::string S_ip = s_ip.str();

        udf_rule->action_fvs[attr_name] = std::string(S_ip);
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        break;
    }
    case Format_UDF::IPV6_UDF: {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        uint32_t *ipaddr = (uint32_t *)malloc(sizeof(uint32_t) * 4);
        if(!ipaddr){
                return ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                        << "malloc function return NULL pointer,cannot insert:" <<QuotedVar(attr_value);
            }

        memset(ipaddr , 0 ,sizeof(uint32_t) * 4);
        try
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            swss::IpAddress ip(attr_value);
            if (ip.isV4())
            {
                free(ipaddr);
                return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                       << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                       << QuotedVar(udf_rule->udf_table_name) << ": Expect IPv6 address but got "
                       << QuotedVar(attr_value);
            }
            memcpy(ipaddr, ip.getV6Addr(), sizeof(sai_ip6_t));
        }
        catch (std::exception &e)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            free(ipaddr);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                   << QuotedVar(udf_rule->udf_table_name) << ": Expect IP address but got " << QuotedVar(attr_value);
        }

        std::string S_ipV6;

        S_ipV6 = NetworkOrderTransToLittleEndian(ipaddr,4);

        udf_rule->action_fvs[attr_name] = std::string(S_ipV6);

        free(ipaddr);
        break;
    }
    case Format_UDF::MAC_UDF: {
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        uint16_t *mac_address = (uint16_t *)malloc(sizeof(uint16_t) * 3);
        if(!mac_address){
            return ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                    << "malloc function return NULL pointer,cannot insert:" <<QuotedVar(attr_value);
        }
        memset(mac_address, 0 ,sizeof(uint16_t) * 3);
        try
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            swss::MacAddress mac(attr_value);
            memcpy(mac_address, mac.getMac(), sizeof(sai_mac_t));
        }
        catch (std::exception &e)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            free(mac_address);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                   << QuotedVar(udf_rule->udf_table_name) << ": Expect MAC_UDF address but got " << QuotedVar(attr_value);
        }

        std::string S_macaddr;
        S_macaddr = U16NetworkOrderTransToLittleEndian(mac_address,3);
        udf_rule->action_fvs[attr_name] = std::string(S_macaddr);
        free(mac_address);
        break;
    }
    case Format_UDF::PORT_STRING_UDF: {
        try
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            uint16_t port = 0;
            port = to_uint<uint16_t>(attr_value);

            udf_rule->action_fvs[attr_name] = std::to_string(port);
        }
        catch (std::exception &e)
        {
            SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
            return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                   << "Action attribute " << QuotedVar(attr_name) << " is invalid for "
                   << QuotedVar(udf_rule->udf_table_name) << ": Expect integer but got " << QuotedVar(attr_value);
        }

        udf_rule->action_fvs[attr_name] = std::string(trim(attr_value));
        break;
    }
    default: {
        return ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
               << "Invalid UDF action " << attr_name << " for " << QuotedVar(udf_rule->udf_table_name);
    }
    }

    return ReturnCode();
}

ReturnCode UdfTableManager::waitResponse(void *m_socket, std::string& key, std::string& command, std::vector<uint8_t>& m_buffer)
{
    SWSS_LOG_ENTER();

    zmq_pollitem_t items [1] = { };

    items[0].socket = m_socket;
    items[0].events = ZMQ_POLLIN;
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    int rc = zmq_poll(items, 1, 5000);

    if(rc == 0 ){
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to get response from interface for: " << QuotedVar(key);
        SWSS_LOG_ERROR("ZMQ POLL time out for interface response");
        return status;
    }

    if(rc < 0){
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to get response from interface for: " << QuotedVar(key);
        SWSS_LOG_ERROR("ZMQ POLL failed for interface response");
        return status;
    }

    rc = zmq_recv(m_socket, m_buffer.data(), ZMQ_RESPONSE_UDF_BUFFER_SIZE, 0);

    if(rc < 0){
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to recv msg from interface for: " << QuotedVar(key);
        SWSS_LOG_ERROR("ZMQ RECV failed for interface response");
        return status;
    }

    if(rc > ZMQ_RESPONSE_UDF_BUFFER_SIZE){
       ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to recv msg from interface because overflow for: " << QuotedVar(key);
        SWSS_LOG_ERROR("ZMQ RECV overflow  for interface response");
        return status;
    }

    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    m_buffer.at(rc) = 0;

    std::vector<FieldValueTuple> values;

    JSon::readJson((char*)m_buffer.data(), values);

    FieldValueTuple fvt = values.at(0);

    const std::string& opkey = fvField(fvt);
    const std::string& op= fvValue(fvt);

    values.erase(values.begin());

    if(op == command && key == opkey){
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        /*success get response*/
        FieldValueTuple ret = values.at(0);
        const std::string& retvalue= fvValue(ret);

        if(retvalue != std::string("0")) {
            ReturnCode status = ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                            << "get invalid param for: " << QuotedVar(key);
        SWSS_LOG_ERROR("invalid param or no sys memory for udf interface");
        return status;
        }

    }
    else{
        SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "recv wrong msg from interface for: " << QuotedVar(key);
        SWSS_LOG_ERROR("ZMQ RECV wrong data from interface response");
        return status;
    }

    return ReturnCode();
}

ReturnCode UdfTableManager::zmqSendRequest(const std::string& msg, std::string key, std::string command)
{
    SWSS_LOG_ENTER();

    void *zmqctx = NULL;
	void *zmqsock;
    std::vector<uint8_t> m_buffer;
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    zmqctx = zmq_ctx_new();
	//zmq_ctx_set(zmqctx, ZMQ_IPV6, 1);
    zmqsock = zmq_socket(zmqctx, ZMQ_REQ);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    if (zmq_connect(zmqsock, ServerAddr)) {
		printf("zmq_connect failed\n");
		ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to create UDF entry in table " << QuotedVar(key);
        SWSS_LOG_ERROR("UDF Table manager connect interface failed");
        return status;
	}

    m_buffer.resize(ZMQ_RESPONSE_UDF_BUFFER_SIZE);


    int rc = zmq_send(zmqsock, msg.c_str(), msg.length(), 0);

    if (rc <= 0)
    {
        zmq_close(zmqsock);
        zmq_ctx_destroy(zmqctx);
        ReturnCode status = ReturnCode(StatusCode::SWSS_RC_NO_MEMORY)
                            << "Failed to create UDF entry in table " << QuotedVar(key);
        SWSS_LOG_ERROR("UDF Table manager send entry failed");
        return status;
    }
    else {
        ReturnCode status; 
        status = waitResponse(zmqsock, key, command, m_buffer);

        if (!status.ok())
        {
            zmq_close(zmqsock);
            zmq_ctx_destroy(zmqctx);
            SWSS_LOG_ERROR("Failed to ADD udf rule attributes: %s", status.message().c_str());
            return status;
        }
        
    }

    zmq_close(zmqsock);
    zmq_ctx_destroy(zmqctx);
    return ReturnCode();
}

ReturnCode UdfTableManager::createUdfRule(P4UdfRule &udf_rule,std::string command)
{
    
    SWSS_LOG_ENTER();
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    std::vector<FieldValueTuple> udf_entry_attrs;

    FieldValueTuple opcommand(udf_rule.udf_table_name, command);

    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    // Add matches
    long unsigned int match_length = udf_rule.match_fvs.size();
    std::string MatchLength = std::to_string(match_length);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField,MatchLength));

    for (const auto &match_fv : udf_rule.match_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(match_fv),fvValue(match_fv)));
    }

    //Add priority
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority,std::to_string(udf_rule.priority)));

    // Add actions
    udf_entry_attrs.push_back(std::make_pair(udf_rule.p4_action, std::to_string(udf_rule.action_fvs.size())));
    for (const auto &action_fv : udf_rule.action_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(action_fv),fvValue(action_fv)));
    }

    //print
     for(auto& udfentry : udf_entry_attrs){
         SWSS_LOG_NOTICE("%s:%d KEY:%s VALUE: %s",__func__,__LINE__,udfentry.first.c_str(), udfentry.second.c_str());
    }

    std::string msg = JSon::buildJson(udf_entry_attrs);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    ReturnCode status = zmqSendRequest(msg, udf_rule.udf_table_name,command);
    if(!status.ok()){
         SWSS_LOG_ERROR("Failed to create udf rule attributes: %s", status.message().c_str());
         return status;
    }

    m_p4OidMapper->setDummyOID(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, udf_rule.udf_rule_key);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    return ReturnCode();
}

ReturnCode UdfTableManager::updateUdfRule(P4UdfRule &udf_rule, std::string command)
{
    SWSS_LOG_ENTER();

    std::vector<FieldValueTuple> udf_entry_attrs;

    FieldValueTuple opcommand(udf_rule.udf_table_name, command);

    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    // Add matches
    long unsigned int match_length = udf_rule.match_fvs.size();
    std::string MatchLength = std::to_string(match_length);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField,MatchLength));

    for (const auto &match_fv : udf_rule.match_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(match_fv),fvValue(match_fv)));
    }

    //Add priority
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority,std::to_string(udf_rule.priority)));

    // Add actions
    udf_entry_attrs.push_back(std::make_pair(udf_rule.p4_action, std::to_string(udf_rule.action_fvs.size())));
    for (const auto &action_fv : udf_rule.action_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(action_fv),fvValue(action_fv)));
    }

    for(auto& udfentry : udf_entry_attrs){
         SWSS_LOG_NOTICE("%s:%d KEY:%s VALUE: %s",__func__,__LINE__,udfentry.first.c_str(), udfentry.second.c_str());
    }

    std::string msg = JSon::buildJson(udf_entry_attrs);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    ReturnCode status = zmqSendRequest(msg, udf_rule.udf_table_name,command);
    if(!status.ok()){
         SWSS_LOG_ERROR("Failed to create udf rule attributes: %s", status.message().c_str());
         return status;
    }
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    return ReturnCode();
}

ReturnCode UdfTableManager::removeUdfRule(const std::string &udf_table_name,const std::string &udf_rule_key)
{
    SWSS_LOG_ENTER();
    auto *udf_rule = getUdfRule(udf_table_name, udf_rule_key);
    std::vector<FieldValueTuple> udf_entry_attrs;
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    if (udf_rule == nullptr)
    {
        LOG_ERROR_AND_RETURN(ReturnCode(StatusCode::SWSS_RC_NOT_FOUND)
                             << "ACL rule with key " << QuotedVar(udf_rule_key) << " in table "
                             << QuotedVar(udf_table_name) << " does not exist");
    }

    FieldValueTuple opcommand(udf_rule->udf_table_name, P4RT_USER_TABLE_DEL);

    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    // Add matches
    long unsigned int match_length = udf_rule->match_fvs.size();
    std::string MatchLength = std::to_string(match_length);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField,MatchLength));

    for (const auto &match_fv : udf_rule->match_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(match_fv),fvValue(match_fv)));
    }

    //Add priority
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority,std::to_string(udf_rule->priority)));

    // Add actions
    udf_entry_attrs.push_back(std::make_pair(udf_rule->p4_action, std::to_string(udf_rule->action_fvs.size())));
    for (const auto &action_fv : udf_rule->action_fvs)
    {
        udf_entry_attrs.push_back(std::make_pair(fvField(action_fv),fvValue(action_fv)));
    }

    for(auto& udfentry : udf_entry_attrs){
         SWSS_LOG_NOTICE("%s:%d KEY:%s VALUE: %s",__func__,__LINE__,udfentry.first.c_str(), udfentry.second.c_str());
    }

    std::string msg = JSon::buildJson(udf_entry_attrs);
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    ReturnCode status = zmqSendRequest(msg, udf_rule->udf_table_name, P4RT_USER_TABLE_DEL);
    if(!status.ok()){
        SWSS_LOG_ERROR("Failed to delete udf rule attributes: %s", status.message().c_str());
         return status;
    }
    m_p4OidMapper->eraseOID(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, udf_rule_key);
    m_udfRuleTables[udf_table_name].erase(udf_rule_key);
    return ReturnCode();
}

ReturnCode UdfTableManager::processAddRuleRequest(const std::string &udf_rule_key,
                                                 const P4UdfTableAppDbEntry &app_db_entry)
{
    SWSS_LOG_ENTER();
    P4UdfRule udf_rule;
    udf_rule.priority = app_db_entry.priority;
    udf_rule.udf_rule_key = udf_rule_key;

    udf_rule.p4_action = app_db_entry.action;
    udf_rule.db_key = app_db_entry.db_key;

    udf_rule.udf_table_name = app_db_entry.udf_table_name; 
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    if(m_udftables.find(udf_rule.udf_table_name) == m_udftables.end())
    {
        ReturnCode error = ReturnCode(StatusCode::SWSS_RC_INVALID_PARAM)
                            << "Invalid table name " << QuotedVar(app_db_entry.udf_table_name);
        return error;
    }

    // Add match field values
    LOG_AND_RETURN_IF_ERROR(setAllMatchFieldValues(app_db_entry, udf_rule));
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    // Add action field values
    auto status = setAllActionFieldValues(app_db_entry, udf_rule);
    if (!status.ok())
    {
        SWSS_LOG_ERROR("Failed to add action field values for ACL rule %s: %s",
                       QuotedVar(udf_rule.udf_rule_key).c_str(), status.message().c_str());
        return status;
    }
    SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    status = createUdfRule(udf_rule,P4RT_USER_TABLE_ADD);
    if (!status.ok())
    {
        SWSS_LOG_ERROR("Failed to create ACL rule with key %s in table %s", QuotedVar(udf_rule.udf_rule_key).c_str(),
                       QuotedVar(app_db_entry.udf_table_name).c_str());
        return status;
    }
  
    m_udfRuleTables[udf_rule.udf_table_name][udf_rule.udf_rule_key] = udf_rule;
    SWSS_LOG_NOTICE("Suceeded to create udf rule %s", QuotedVar(udf_rule.udf_rule_key).c_str());
    return status;
}

ReturnCode UdfTableManager::processDeleteRuleRequest(const std::string &udf_table_name, const std::string &udf_rule_key)
{
    SWSS_LOG_ENTER();
    auto status = removeUdfRule(udf_table_name, udf_rule_key);
    if (!status.ok())
    {
        SWSS_LOG_ERROR("Failed to remove ACL rule with key %s in table %s", QuotedVar(udf_rule_key).c_str(),
                       QuotedVar(udf_table_name).c_str());
    }
    return status;
}

ReturnCode UdfTableManager::processUpdateRuleRequest(const P4UdfTableAppDbEntry &app_db_entry,
                                                    const P4UdfRule &old_udf_rule)
{
    SWSS_LOG_ENTER();

    P4UdfRule udf_rule;
    udf_rule.udf_table_name = old_udf_rule.udf_table_name;
    udf_rule.db_key = app_db_entry.db_key;

    // Skip match field comparison because the udf_rule_key including match
    // field value and priority should be the same with old one.
    udf_rule.match_fvs = old_udf_rule.match_fvs;
    udf_rule.priority = app_db_entry.priority;
    udf_rule.udf_rule_key = old_udf_rule.udf_rule_key;
    // Update action field
    udf_rule.p4_action = app_db_entry.action;
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    auto set_actions_rc = setAllActionFieldValues(app_db_entry, udf_rule);
    if (!set_actions_rc.ok())
    {
        SWSS_LOG_ERROR("Failed to add action field values for Udf rule %s: %s",
                       QuotedVar(udf_rule.udf_rule_key).c_str(), set_actions_rc.message().c_str());
        return set_actions_rc;
    }
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    auto status = updateUdfRule(udf_rule, P4RT_USER_TABLE_MOD);
    if (!status.ok())
    {
        SWSS_LOG_ERROR("Failed to update ACL rule %s", QuotedVar(udf_rule.udf_rule_key).c_str());
        return status;
    }
     SWSS_LOG_NOTICE("%s:%d",__func__,__LINE__);
    m_udfRuleTables[udf_rule.udf_table_name][udf_rule.udf_rule_key] = udf_rule;
    return ReturnCode();
}

} // namespace p4orch
