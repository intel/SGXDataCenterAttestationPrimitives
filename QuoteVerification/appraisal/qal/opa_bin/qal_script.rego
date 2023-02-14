package sgx.quote.appraisal
import future.keywords.in

#
# Section 1: Appraise policies that are present and output appraisal results as appraisal_result
#
default both_tcbs_ok = false
both_tcbs_ok {
    platform_tcb_ok
    application_enclave_ok
}

default appraisal_result = {"appraised_tcbs":{"overall_appraisal_result": false}}
appraisal_result = appraiser_output {
    platform_tcb_policy_present
    application_enclave_tcb_policy_present
    appraiser_output := {
        "overall_appraisal_result": both_tcbs_ok,
        "appraisal_check_date": time.now_ns(),
        "appraised_tcbs": {
            "platform_tcb_appraisal_result": {
                "platform_tcb_accepted": platform_tcb_ok,
                "policy": {
                    "header" : input.policies.sgx_platform.header,
                    "signing_key" : input.policies.sgx_platform.signing_key,
                    "signature" : input.policies.sgx_platform.signature
                }
            },
            "application_enclave_tcb_appraisal_result": {
                "application_enclave_tcb_accepted": application_enclave_ok,
                "policy": {
                    "header" : input.policies.sgx_enclave.header,
                    "signing_key" : input.policies.sgx_enclave.signing_key,
                    "signature" : input.policies.sgx_enclave.signature
                }
            }
        },
       "qvl_result": input.qvl_result
    }
}
appraisal_result = appraiser_output {
    platform_tcb_policy_present
    not application_enclave_tcb_policy_present
    appraiser_output := {
        "overall_appraisal_result": platform_tcb_ok,
        "appraisal_check_date": time.now_ns(),
        "appraised_tcbs": {
            "platform_tcb_appraisal_result": {
                "platform_tcb_accepted": platform_tcb_ok,
                "policy": {
                    "header" : input.policies.sgx_platform.header,
                    "signing_key" : input.policies.sgx_platform.signing_key,
                    "signature" : input.policies.sgx_platform.signature
                }
            }
        },
       "qvl_result": input.qvl_result
    }
}
appraisal_result = appraiser_output {
    not platform_tcb_policy_present
    application_enclave_tcb_policy_present
    appraiser_output := {
        "overall_appraisal_result": application_enclave_ok,
        "appraisal_check_date": time.now_ns(),
        "appraised_tcbs": {
            "application_enclave_tcb_appraisal_result": {
                "application_enclave_tcb_accepted": application_enclave_ok,
                "policy": {
                    "header" : input.policies.sgx_enclave.header,
                    "signing_key" : input.policies.sgx_enclave.signing_key,
                    "signature" : input.policies.sgx_enclave.signature
                }
            }
       },
       "qvl_result": input.qvl_result
    }
}

#
# Section 2: Platform TCB appraisal, result in platform_tcb_ok
#
# Check to see if any in a set of status are not in the policy
default unaccepted_tcb_status_present = false
unaccepted_tcb_status_present {
    some i
    status := input.qvl_result.platform_tcb.tcb.tcb_status[i]
    not status in input.policies.sgx_platform.tcb.accepted_tcb_status
}

default tcb_status_present = false
tcb_status_present {
	input.qvl_result.platform_tcb.tcb.tcb_status
}

# Appraise required tcb_status - this must not contain any strings that are not in the policy
default tcb_status_ok = false

# tcb status is OK if none of the individual stati are rejected and the input contains a tcb_status
tcb_status_ok {
  tcb_status_present
  not unaccepted_tcb_status_present
}

# Appraise required platform_tcb expiration_date_check
#  if policy.sgx.platform_tcb.collateral_grace_period is provided,
#  then the platform TCB earliest_expiration_date must be within the grace period
default expiration_date_check_ok = false
expiration_date_check_ok {
    not input.policies.sgx_platform.tcb.collateral_grace_period
}
expiration_date_check_ok {
    # Convert grace period from seconds to ns
    grace_period := input.policies.sgx_platform.tcb.collateral_grace_period * 1000000000
    expiration_date := time.parse_rfc3339_ns(input.qvl_result.platform_tcb.tcb.earliest_expiration_date)
    expiration_date + grace_period >=  time.now_ns()
}

# Appraise platform_tcb.tcb_level_date_tag
#  if policy.sgx.platform_tcb.earliest_accepted_tcb_level_date_tag is provided, then it must not be
#   after the platform_tcb.tcb_level_date_tag
default earliest_accepted_tcb_level_date_tag_ok = false
earliest_accepted_tcb_level_date_tag_ok {
    not input.policies.sgx_platform.tcb.platform_grace_period
}
earliest_accepted_tcb_level_date_tag_ok {
    grace_period := input.policies.sgx_platform.tcb.platform_grace_period * 1000000000
    expiration_date := time.parse_rfc3339_ns(input.qvl_result.platform_tcb.tcb.tcb_level_date_tag)
    expiration_date + grace_period >=  time.now_ns()
}

# Appraise optional platform_tcb tcb_eval_num
default tcb_eval_num_ok = false
tcb_eval_num_ok {
    not input.policies.sgx_platform.tcb.min_eval_num
}
tcb_eval_num_ok {
    input.qvl_result.platform_tcb.tcb.tcb_eval_num >= input.policies.sgx_platform.tcb.min_eval_num
}

# Appraise optional platform_tcb platform_provider_id
default platform_provider_id_ok = false
platform_provider_id_ok {
    not input.policies.sgx_platform.tcb.accepted_platform_provider_ids
}
platform_provider_id_ok {
    some i
    input.qvl_result.platform_tcb.tcb.platform_provider_id == input.policies.sgx_platform.tcb.accepted_platform_provider_ids[i]
}

# Appraise sgx_type - all required_sgx_type in policy should not be missing
default missing_sgx_types = false
missing_sgx_types {
    some i
    required_sgx_type := input.policies.sgx_platform.tcb.required_sgx_types[i]
    not required_sgx_type in input.qvl_result.platform_tcb.tcb.sgx_types
}

default dynamic_platform_ok = false
dynamic_platform_ok {
	input.qvl_result.platform_tcb.tcb.is_dynamic_platform
	input.policies.sgx_platform.tcb.allow_dynamic_platform
}
dynamic_platform_ok {
	not input.qvl_result.platform_tcb.tcb.is_dynamic_platform
	input.policies.sgx_platform.tcb.allow_dynamic_platform
}
dynamic_platform_ok {
	not input.qvl_result.platform_tcb.tcb.is_dynamic_platform
	not input.policies.sgx_platform.tcb.allow_dynamic_platform
}

# Appraise optional platform_tcb advisory_ids
default advisory_ids_ok = false

advisory_ids_ok {
    not advisory_ids_rejected
}
advisory_ids_rejected {
    some i
    some j
    input.qvl_result.platform_tcb.tcb.advisory_ids[i] == input.policies.sgx_platform.tcb.rejected_advisory_ids[j]
}

# Sum up platform TCB appraisal
default platform_tcb_ok = false
platform_tcb_ok {
    not platform_tcb_policy_present
}
platform_tcb_ok {
    platform_tcb_policy_present
    tcb_status_ok
    expiration_date_check_ok
    earliest_accepted_tcb_level_date_tag_ok
    tcb_eval_num_ok
    platform_provider_id_ok
    not missing_sgx_types
    dynamic_platform_ok
    advisory_ids_ok
}

default platform_tcb_policy_present = false
platform_tcb_policy_present {
	input.policies.sgx_platform
    input.policies.sgx_platform.header.type == input.qvl_result.platform_tcb.header.type
}

#
# Section 3: application enclave appraisal, result in application_enclave_ok
#
default application_enclave_tcb_policy_present = false
application_enclave_tcb_policy_present {
    input.policies.sgx_enclave
    input.policies.sgx_enclave.header.type == input.qvl_result.enclave_tcb.header.type
}

default application_enclave_ok = false
application_enclave_ok {
    not application_enclave_tcb_policy_present
}
application_enclave_ok {
    application_enclave_tcb_policy_present
    miscselect_ok
    attributes_ok
    ce_attributes_ok
    enclave_id_ok
    configid_ok
    configsvn_ok
    isvextprodid_ok
    isvfamilyid_ok
}

# Appraise optional enclave_identity miscselect
default miscselect_ok = false
miscselect_ok {
    not input.policies.sgx_enclave.tcb.miscselect
}
miscselect_ok {
    hex2int := {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
    "8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15
    }
    value := split(upper(input.qvl_result.enclave_tcb.tcb.miscselect), "")
    policy := split(upper(input.policies.sgx_enclave.tcb.miscselect), "")
    mask := split(upper(input.policies.sgx_enclave.tcb.miscselect_mask), "")
    count({i | mask[i]; bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])}) == count(mask)
}

# Appraise required enclave_identity attributes
default attributes_ok = false
attributes_ok {
    hex2int := {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
    "8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15
    }
    value := split(upper(input.qvl_result.enclave_tcb.tcb.attributes), "")
    policy := split(upper(input.policies.sgx_enclave.tcb.attributes), "")
    mask := split(upper(input.policies.sgx_enclave.tcb.attributes_mask), "")
    count({i | mask[i]; bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])}) == count(mask)
}

# Appraise optional enclave_identity ce_attributes
default ce_attributes_ok = false
ce_attributes_ok {
    not input.policies.sgx_enclave.tcb.ce_attributes
}
ce_attributes_ok {
    hex2int := {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
    "8": 8, "9": 9, "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15
    }
    value := split(upper(input.qvl_result.enclave_tcb.tcb.ce_attributes), "")
    policy := split(upper(input.policies.sgx_enclave.tcb.ce_attributes), "")
    mask := split(upper(input.policies.sgx_enclave.tcb.ce_attributes_mask), "")
    count({i | mask[i]; bits.and(hex2int[value[i]], hex2int[mask[i]]) == bits.and(hex2int[policy[i]], hex2int[mask[i]])}) == count(mask)
}

# Appraise enclave_identity mrenclave or mrsigner + isvprodid + isvsvn
# Assumption: policy either contains mrenclave, or mrsigner + isvprodid + min_isvsvn
default enclave_id_ok = false
enclave_id_ok {
    mrenclave_ok
    mrsigner_ok
}
default mrenclave_ok = false
mrenclave_ok {
    not input.policies.sgx_enclave.tcb.mrenclave
}
mrenclave_ok {
    input.qvl_result.enclave_tcb.tcb.mrenclave == input.policies.sgx_enclave.tcb.mrenclave
}
default mrsigner_ok = false
mrsigner_ok {
    not input.policies.sgx_enclave.tcb.mrsigner
}
mrsigner_ok {
    input.qvl_result.enclave_tcb.tcb.mrsigner == input.policies.sgx_enclave.tcb.mrsigner
    input.qvl_result.enclave_tcb.tcb.isvprodid == input.policies.sgx_enclave.tcb.isvprodid
    input.qvl_result.enclave_tcb.tcb.isvsvn >= input.policies.sgx_enclave.tcb.min_isvsvn    
}

# Appraise optional kss fields: configid, min_configsvn, isvextprodid, isvfamilyid
default configid_ok = false
configid_ok {
    not input.policies.sgx_enclave.tcb.configid
}
configid_ok {
    input.qvl_result.enclave_tcb.tcb.configid == input.policies.sgx_enclave.tcb.configid
}
default configsvn_ok = false
configsvn_ok {
    not input.policies.sgx_enclave.tcb.min_configsvn
}
configsvn_ok {
    input.qvl_result.enclave_tcb.tcb.configsvn >= input.policies.sgx_enclave.tcb.min_configsvn
}
default isvextprodid_ok = false
isvextprodid_ok {
    not input.policies.sgx_enclave.tcb.isvextprodid
}
isvextprodid_ok {
    input.qvl_result.enclave_tcb.tcb.isvextprodid == input.policies.sgx_enclave.tcb.isvextprodid
}
default isvfamilyid_ok = false
isvfamilyid_ok {
    not input.policies.sgx_enclave.tcb.isvfamilyid
}
isvfamilyid_ok {
    input.qvl_result.enclave_tcb.tcb.isvfamilyid == input.policies.sgx_enclave.tcb.isvfamilyid
}
