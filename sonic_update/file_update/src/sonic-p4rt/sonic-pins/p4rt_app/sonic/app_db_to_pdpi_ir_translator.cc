// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "p4rt_app/sonic/app_db_to_pdpi_ir_translator.h"

#include <iterator>
#include <unordered_map>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"
#include "absl/strings/substitute.h"
#include "glog/logging.h"
#include "gutil/collections.h"
#include "gutil/status.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/utils/ir.h"
#include "p4rt_app/utils/table_utility.h"
#include "swss/json.h"
#include "swss/json.hpp"

namespace p4rt_app {
namespace sonic {

namespace {

// P4RT match keys are identified by the P4Info match paramter alias and this
// prefix.
constexpr absl::string_view kMatchPrefix = "match/";

// P4RT action parameter keys are identified by the P4Info action parameter
// alias and this prefix.
constexpr absl::string_view kActionParamPrefix = "param/";

// P4RT ternary match delimiter.
constexpr absl::string_view kTernaryMatchDelimiter = "&";
constexpr absl::string_view kRangeMatchDelimiter = "&";

std::string AddAppDbMatchPrefix(absl::string_view key) {
  return absl::StrCat(kMatchPrefix, key);
}

absl::StatusOr<std::string> StripAppDbMatchPrefix(absl::string_view key) {
  if (!absl::StartsWith(key, kMatchPrefix)) {
    return gutil::InvalidArgumentErrorBuilder()
           << "SONiC AppDB match field does not start with " << kMatchPrefix
           << ": " << key;
  }
  return std::string{absl::StripPrefix(key, kMatchPrefix)};
}

std::string AddAppDbActionParamPrefix(absl::string_view param) {
  return absl::StrCat(kActionParamPrefix, param);
}

absl::StatusOr<std::string> StripAppDbActionParamPrefix(absl::string_view key) {
  if (!absl::StartsWith(key, kActionParamPrefix)) {
    return gutil::InvalidArgumentErrorBuilder()
           << "SONiC AppDB action parameter does not start with "
           << kActionParamPrefix << ": " << key;
  }
  return std::string{absl::StripPrefix(key, kActionParamPrefix)};
}

// The P4RT AppDb entries use ":" to delineate the table name, and the key.
std::string SonicDbKeyToAppDbKey(absl::string_view app_db_key) {
  auto p4rt_stripped = app_db_key.substr(app_db_key.find(':') + 1);
  return std::string(p4rt_stripped.substr(p4rt_stripped.find(':') + 1));
}

// The P4RT AppDb entries use ":" to delineate the table name, and the key.
absl::StatusOr<std::string> SonicDbKeyToP4TableName(
    absl::string_view app_db_key) {
  const std::vector<std::string> split = absl::StrSplit(app_db_key, ':');
  if (split.empty()) return std::string{""};

  // Strip off the "P4RT_" prefix if it exists.
  const std::string &table_name = split[0];
  if (!absl::StartsWith(table_name, kP4rtTablePrefix)) {
    return gutil::InvalidArgumentErrorBuilder()
           << "Key \"" << app_db_key << "\" does not start with "
           << "\"" << APP_P4RT_TABLE_NAME << ":" << "\".";
  }
  absl::string_view sonic_table_name = split[1];
  // Strip off the table type.
  auto split_pos = sonic_table_name.find('_');
  absl::string_view type_name = sonic_table_name.substr(0, split_pos);
  auto type_or = table::TypeParse(type_name);
  if (!type_or.ok()) {
    return gutil::InvalidArgumentErrorBuilder()
           << "Key \"" << app_db_key << "\" "
           << "does not follow the expected format: "
           << "\"" << APP_P4RT_TABLE_NAME << ":" << type_name
           << "<TableType>_<P4TableName>\"";
  }
  return absl::AsciiStrToLower(sonic_table_name.substr(++split_pos));
}

absl::StatusOr<std::string> IrValueToAppDbString(const pdpi::IrValue &value) {
  switch (value.format_case()) {
    case pdpi::IrValue::kHexStr:
      return value.hex_str();
    case pdpi::IrValue::kIpv4:
      return value.ipv4();
    case pdpi::IrValue::kIpv6:
      return value.ipv6();
    case pdpi::IrValue::kMac:
      return value.mac();
    case pdpi::IrValue::kStr:
      return value.str();
    default:
      return gutil::InvalidArgumentErrorBuilder()
             << "Unsupported IrValue type: " << value.ShortDebugString();
  }

  return gutil::InvalidArgumentErrorBuilder()
         << "Unsupported IrValue type: " << value.ShortDebugString();
}

absl::StatusOr<pdpi::IrMatch::IrLpmMatch> AppDbLpmValueToIrLpmMatch(
    const std::string &value, pdpi::Format format) {
  pdpi::IrMatch::IrLpmMatch lpm;
  const std::vector<std::string> split = absl::StrSplit(value, '/');
  if (split.size() != 2) {
    return gutil::InvalidArgumentErrorBuilder()
           << "Invalid LPM value: " << value;
  }
  ASSIGN_OR_RETURN(*lpm.mutable_value(),
                   FormattedStringToIrValue(split[0], format));
  lpm.set_prefix_length(std::stoi(split[1]));
  return lpm;
}

absl::StatusOr<pdpi::IrMatch::IrTernaryMatch> AppDbTernaryValuttoIrTernaryMatch(
    const std::string &value, pdpi::Format format) {
  pdpi::IrMatch::IrTernaryMatch ternary;
  const std::vector<std::string> split =
      absl::StrSplit(value, kTernaryMatchDelimiter);
  if (split.size() != 2) {
    return gutil::InvalidArgumentErrorBuilder()
           << "Invalid ternary value: " << value;
  }
  ASSIGN_OR_RETURN(*ternary.mutable_value(),
                   FormattedStringToIrValue(split[0], format));
  ASSIGN_OR_RETURN(*ternary.mutable_mask(),
                   FormattedStringToIrValue(split[1], format));
  return ternary;
}

absl::StatusOr<pdpi::IrMatch::IrRangeMatch> AppDbRangeValuttoIrRangeMatch(
    const std::string &value, pdpi::Format format) {
  pdpi::IrMatch::IrRangeMatch range;
  const std::vector<std::string> split =
      absl::StrSplit(value, kRangeMatchDelimiter);
  if (split.size() != 2) {
    return gutil::InvalidArgumentErrorBuilder()
           << "Invalid range value: " << value;
  }
  ASSIGN_OR_RETURN(*range.mutable_low(),
                   FormattedStringToIrValue(split[0], format));
  ASSIGN_OR_RETURN(*range.mutable_high(),
                   FormattedStringToIrValue(split[1], format));
  return range;
}

absl::StatusOr<pdpi::IrMatch> AppDbKeyValueStringsToIrMatch(
    const pdpi::IrP4Info &ir_p4_info, const std::string &table_name,
    const std::string &key, const std::string &value) {
  pdpi::IrMatch field;
  field.set_name(key);

  ASSIGN_OR_RETURN(auto p4_table,
                   gutil::FindOrStatus(ir_p4_info.tables_by_name(),
                                       absl::AsciiStrToLower(table_name)),
                   _ << "Could not find table " << table_name
                     << " for match field " << key << ".");
  ASSIGN_OR_RETURN(
      auto p4_match_field,
      gutil::FindOrStatus(p4_table.match_fields_by_name(),
                          absl::AsciiStrToLower(key)),
      _ << "Table " << table_name << " missing match field " << key << ".");

  switch (p4_match_field.match_field().match_type()) {
    case p4::config::v1::MatchField::EXACT: {
      ASSIGN_OR_RETURN(
          *field.mutable_exact(),
          FormattedStringToIrValue(value, p4_match_field.format()));
      return field;
    }
    case p4::config::v1::MatchField::LPM: {
      ASSIGN_OR_RETURN(
          *field.mutable_lpm(),
          AppDbLpmValueToIrLpmMatch(value, p4_match_field.format()));
      return field;
    }
    case p4::config::v1::MatchField::TERNARY: {
      ASSIGN_OR_RETURN(
          *field.mutable_ternary(),
          AppDbTernaryValuttoIrTernaryMatch(value, p4_match_field.format()));
      return field;
    }
    case p4::config::v1::MatchField::RANGE: {
      ASSIGN_OR_RETURN(
          *field.mutable_range(),
          AppDbRangeValuttoIrRangeMatch(value, p4_match_field.format()));
      return field;
    }
    case p4::config::v1::MatchField::OPTIONAL: {
      ASSIGN_OR_RETURN(
          *field.mutable_optional()->mutable_value(),
          FormattedStringToIrValue(value, p4_match_field.format()));
      return field;
    }
    default:
      break;
  }
  LOG(ERROR) << "Could not translate AppDb Key/Value: "
             << p4_match_field.match_field().ShortDebugString();
  return gutil::InvalidArgumentErrorBuilder()
         << "Unsupported match field type: "
         << p4_match_field.match_field().ShortDebugString();
}

absl::StatusOr<pdpi::IrActionInvocation::IrActionParam>
AppDbNameValueStringsToIrActionParam(const pdpi::IrP4Info &ir_p4_info,
                                     const std::string &table_name,
                                     const std::string &action_name,
                                     const std::string &app_db_param_name,
                                     const std::string &value) {
  VLOG(1) << "Translate AppDb action param for " << table_name << "."
          << action_name << ": " << app_db_param_name << ", " << value;
  ASSIGN_OR_RETURN(std::string param_name,
                   StripAppDbActionParamPrefix(app_db_param_name));

  pdpi::IrActionInvocation::IrActionParam param;
  param.set_name(param_name);
  ASSIGN_OR_RETURN(auto p4_table,
                   gutil::FindOrStatus(ir_p4_info.tables_by_name(),
                                       absl::AsciiStrToLower(table_name)),
                   _ << "Could not find table " << table_name << " for action "
                     << action_name << ".");
  VLOG(3) << "P4Info table description: " << p4_table.DebugString();

  for (const auto &action : p4_table.entry_actions()) {
    VLOG(2) << "P4Info action: " << action.DebugString();

    if (action.action().preamble().alias() == action_name) {
      ASSIGN_OR_RETURN(
          auto p4_action_param,
          gutil::FindOrStatus(action.action().params_by_name(), param_name),
          _ << "Failed to lookup action parameter \"" << param_name
            << "\" from table action [" << action.action().ShortDebugString()
            << "].");
      ASSIGN_OR_RETURN(
          *param.mutable_value(),
          FormattedStringToIrValue(value, p4_action_param.format()));
      return param;
    }
  }
  return gutil::InvalidArgumentErrorBuilder()
         << "Unsupported action " << action_name << " for table " << table_name
         << ".";
}

absl::StatusOr<pdpi::IrActionSet> AppDbValueToIrActionSet(
    const pdpi::IrP4Info &ir_p4_info, const std::string &table_name,
    const std::string &app_db_entry) {
  pdpi::IrActionSet action_set;
  nlohmann::json json;
  try {
    json = nlohmann::json::parse(app_db_entry);
  } catch (...) {
    return gutil::InternalErrorBuilder()
           << "Could not parse JSON string: " << app_db_entry;
  }

  for (const auto &json_action : json) {
    pdpi::IrActionSetInvocation *pi_action_set_invocation =
        action_set.add_actions();

    // In an action set entry the action name, and weight field should always
    // be present.
    std::string action_name;
    try {
      action_name = json_action.at("action").get<std::string>();
      pi_action_set_invocation->mutable_action()->set_name(action_name);
    } catch (...) {
      return gutil::InvalidArgumentErrorBuilder()
             << "JSON ActionSet action is missing a name: " << json_action;
    }
    try {
      pi_action_set_invocation->set_weight(json_action.at("weight").get<int>());
    } catch (...) {
      return gutil::InvalidArgumentErrorBuilder()
             << "JSON ActionSet action is missing a weight: " << json_action;
    }

    for (auto obj = json_action.begin(); obj != json_action.end(); ++obj) {
      // Ignore required fields.
      if (obj.key() == "action" || obj.key() == "weight") continue;

      // The watch port field is optional.
      if (obj.key() == "watch_port") {
        pi_action_set_invocation->set_watch_port(
            obj.value().get<std::string>());
        continue;
      }

      ASSIGN_OR_RETURN(
          *pi_action_set_invocation->mutable_action()->add_params(),
          AppDbNameValueStringsToIrActionParam(ir_p4_info, table_name,
                                               action_name, obj.key(),
                                               obj.value().get<std::string>()));
    }
  }
  return action_set;
}

absl::StatusOr<pdpi::IrTableEntry> AppDbKeyToIrTableEntry(
    const pdpi::IrP4Info &ir_p4_info, const std::string &table_name,
    const std::string &json_key) {
  pdpi::IrTableEntry entry;
  entry.set_table_name(table_name);

  nlohmann::json json;
  try {
    json = nlohmann::json::parse(json_key);
  } catch (...) {
    return gutil::UnknownErrorBuilder()
           << "Could not parse JSON string: " << json_key;
  }

  // A range based for loop cannot be used here because the dereferenced
  // nlohmann::json::iterator can only access the data value, and not the key
  // value.
  for (auto obj = json.cbegin(); obj != json.cend(); ++obj) {
    // The entry's priority is passed as part of the AppDB key, but it does
    // not match on a packet header field or metadata so it does not have a
    // match field prefix.
    if (obj.key() == "priority") {
      entry.set_priority(obj.value().get<int>());
      continue;
    }

    // All other fields should start with the P4RT match field prefix.
    ASSIGN_OR_RETURN(std::string key, StripAppDbMatchPrefix(obj.key()));
    ASSIGN_OR_RETURN(*entry.add_matches(), AppDbKeyValueStringsToIrMatch(
                                               ir_p4_info, table_name, key,
                                               obj.value().get<std::string>()));
  }
  return entry;
}

absl::StatusOr<std::vector<swss::FieldValueTuple>>
IrActionInvocationToAppDbValues(const pdpi::IrActionInvocation &action) {
  std::vector<swss::FieldValueTuple> result;

  result.push_back(std::make_pair("action", action.name()));
  for (const auto &param : action.params()) {
    ASSIGN_OR_RETURN(auto param_value, IrValueToAppDbString(param.value()));
    result.push_back(
        std::make_pair(AddAppDbActionParamPrefix(param.name()), param_value));
  }
  return result;
}

absl::StatusOr<nlohmann::json> IrActionSetInvocationToJsonValue(
    const pdpi::IrActionSetInvocation &action) {
  nlohmann::json json;
  json["action"] = action.action().name();
  json["weight"] = action.weight();

  if (!action.watch_port().empty()) {
    json["watch_port"] = action.watch_port();
  }

  for (const auto &param : action.action().params()) {
    ASSIGN_OR_RETURN(json[AddAppDbActionParamPrefix(param.name())],
                     IrValueToAppDbString(param.value()));
  }
  return json;
}

absl::StatusOr<std::vector<swss::FieldValueTuple>> IrActionSetToAppDbValues(
    const pdpi::IrActionSet &action_set) {
  std::vector<swss::FieldValueTuple> result;

  nlohmann::json json_array = nlohmann::json::array();
  for (const auto &action : action_set.actions()) {
    ASSIGN_OR_RETURN(nlohmann::json json,
                     IrActionSetInvocationToJsonValue(action));
    json_array.push_back(json);
  }
  result.push_back({"actions", json_array.dump()});
  return result;
}

std::vector<swss::FieldValueTuple> P4MeterConfigToAppDbValues(
    const p4::v1::MeterConfig &meter_config) {
  std::vector<swss::FieldValueTuple> app_db_values;
  if (meter_config.cir() != 0) {
    app_db_values.push_back(
        std::make_pair("meter/cir", absl::StrCat(meter_config.cir())));
  }
  if (meter_config.cburst() != 0) {
    app_db_values.push_back(
        std::make_pair("meter/cburst", absl::StrCat(meter_config.cburst())));
  }
  if (meter_config.pir() != 0) {
    app_db_values.push_back(
        std::make_pair("meter/pir", absl::StrCat(meter_config.pir())));
  }
  if (meter_config.pburst() != 0) {
    app_db_values.push_back(
        std::make_pair("meter/pburst", absl::StrCat(meter_config.pburst())));
  }
  return app_db_values;
}

absl::Status AddAppDbMeterDataToIrTableEntry(
    const swss::FieldValueTuple &meter_config,
    pdpi::IrTableEntry *table_entry) {
  const std::string &meter_key = meter_config.first;
  const std::string &meter_data = meter_config.second;

  int64_t int_value;
  if (!absl::SimpleAtoi(meter_data, &int_value)) {
    return gutil::InvalidArgumentErrorBuilder()
           << meter_key << " value (" << meter_data << ") is not an integer.";
  }

  if (meter_key == "meter/cir") {
    table_entry->mutable_meter_config()->set_cir(int_value);
    return absl::OkStatus();
  }
  if (meter_key == "meter/cburst") {
    table_entry->mutable_meter_config()->set_cburst(int_value);
    return absl::OkStatus();
  }
  if (meter_key == "meter/pir") {
    table_entry->mutable_meter_config()->set_pir(int_value);
    return absl::OkStatus();
  }
  if (meter_key == "meter/pburst") {
    table_entry->mutable_meter_config()->set_pburst(int_value);
    return absl::OkStatus();
  }
  return gutil::InvalidArgumentErrorBuilder()
         << meter_key << " is not a recognized meter value.";
}
}  // namespace

absl::StatusOr<std::string> IrTableEntryToAppDbKey(
    const pdpi::IrTableEntry &entry) {
  nlohmann::json json;
  if (entry.priority() > 0) {
    json["priority"] = entry.priority();
  }
  for (const auto &field : entry.matches()) {
    std::string field_name = AddAppDbMatchPrefix(field.name());
    switch (field.match_value_case()) {
      case pdpi::IrMatch::kExact: {
        ASSIGN_OR_RETURN(json[field_name], IrValueToAppDbString(field.exact()));
        break;
      }
      case pdpi::IrMatch::kLpm: {
        ASSIGN_OR_RETURN(auto lpm_value,
                         IrValueToAppDbString(field.lpm().value()));
        json[field_name] =
            absl::StrCat(lpm_value, "/", field.lpm().prefix_length());
        break;
      }
      case pdpi::IrMatch::kTernary: {
        ASSIGN_OR_RETURN(auto value,
                         IrValueToAppDbString(field.ternary().value()));
        ASSIGN_OR_RETURN(auto mask,
                         IrValueToAppDbString(field.ternary().mask()));
        json[field_name] = absl::StrCat(value, kTernaryMatchDelimiter, mask);
        break;
      }
      case pdpi::IrMatch::kOptional: {
        if (field.optional().has_value()) {
          ASSIGN_OR_RETURN(json[field_name],
                           IrValueToAppDbString(field.optional().value()));
        }
        break;
      }
      case pdpi::IrMatch::kRange: {
        ASSIGN_OR_RETURN(auto low,
                         IrValueToAppDbString(field.range().low()));
        ASSIGN_OR_RETURN(auto high,
                         IrValueToAppDbString(field.range().high()));
        json[field_name] = absl::StrCat(low,kRangeMatchDelimiter,high);
        break;
      }
      default: {
        return gutil::UnimplementedErrorBuilder()
               << "Could not translate " << field.match_value_case()
               << " type: " << field.ShortDebugString();
      }
    }
  }
  return json.dump();
}

absl::StatusOr<std::vector<swss::FieldValueTuple>> IrTableEntryToAppDbValues(
    const pdpi::IrTableEntry &entry) {
  std::vector<swss::FieldValueTuple> result;

  switch (entry.type_case()) {
    case pdpi::IrTableEntry::kAction: {
      ASSIGN_OR_RETURN(result, IrActionInvocationToAppDbValues(entry.action()));
      break;
    }
    case pdpi::IrTableEntry::kActionSet: {
      ASSIGN_OR_RETURN(result, IrActionSetToAppDbValues(entry.action_set()));
      break;
    }
    default: {
      return gutil::InvalidArgumentErrorBuilder()
             << "Unsupported IrTableEntry type: " << entry.ShortDebugString();
    }
  }

  if (entry.has_meter_config()) {
    auto meter_values = P4MeterConfigToAppDbValues(entry.meter_config());
    result.insert(result.end(), std::make_move_iterator(meter_values.begin()),
                  std::make_move_iterator(meter_values.end()));
  }

  if (!entry.controller_metadata().empty()) {
    result.push_back(
        std::make_pair("controller_metadata", entry.controller_metadata()));
  }

  return result;
}

absl::StatusOr<pdpi::IrTableEntry> AppDbKeyAndValuesToIrTableEntry(
    const pdpi::IrP4Info &ir_p4_info, absl::string_view app_db_key,
    const std::unordered_map<std::string, std::string> &app_db_values) {
  ASSIGN_OR_RETURN(std::string table_name, SonicDbKeyToP4TableName(app_db_key));
  ASSIGN_OR_RETURN(pdpi::IrTableEntry table_entry,
                   AppDbKeyToIrTableEntry(ir_p4_info, table_name,
                                          SonicDbKeyToAppDbKey(app_db_key)));

  // We need to know the table action when translating action parameters. If we
  // see an action paramter, but the action name isn't set it is an error.
  const auto &action_name = gutil::FindOrStatus(app_db_values, "action");

  // The IrTableEntry action and parameters are derived from the AppDb values.
  // We should never have an AppDb entry with both an IrAction and IrActionSet.
  bool has_action = false;
  bool has_action_set = false;
  for (const auto &value : app_db_values) {
    const std::string &value_key = value.first;
    const std::string &value_data = value.second;

    if (value_key == "action") {
      has_action = true;
      table_entry.mutable_action()->set_name(value_data);
    } else if (value_key == "actions") {
      has_action_set = true;
      ASSIGN_OR_RETURN(
          *table_entry.mutable_action_set(),
          AppDbValueToIrActionSet(ir_p4_info, table_name, value_data));
    } else if (absl::StartsWith(value_key, kActionParamPrefix)) {
      if (!action_name.ok()) {
        return gutil::InvalidArgumentErrorBuilder()
               << "AppDb entry has action parameter " << value_key
               << ", but no 'action' name.";
      }
      ASSIGN_OR_RETURN(
          *table_entry.mutable_action()->add_params(),
          AppDbNameValueStringsToIrActionParam(
              ir_p4_info, table_name, *action_name, value_key, value_data));
    } else if (absl::StartsWith(value_key, "meter/")) {
      RETURN_IF_ERROR(AddAppDbMeterDataToIrTableEntry(value, &table_entry));
    } else if (value_key == "controller_metadata") {
      table_entry.set_controller_metadata(value_data);
    } else {
      return gutil::InvalidArgumentErrorBuilder()
             << "AppDb Entry contained unknown value [" << value_key << " : "
             << value_data << "].";
    }
  }

  if (has_action && has_action_set) {
    return gutil::InternalErrorBuilder()
           << "AppDb entry has both an IrAction and an IrActionSet: "
           << app_db_key;
  }
  return table_entry;
}

}  // namespace sonic
}  // namespace p4rt_app
