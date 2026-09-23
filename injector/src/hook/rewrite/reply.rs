use super::*;

mod dispatch;
mod operation;

use operation::*;

pub(super) use dispatch::can_execute_one_way;
pub(in crate::hook) use dispatch::handle_synthetic_br_transaction;
pub(super) use operation::{
    build_no_carrier_create_operation_reply, build_operation_reply_rewrite,
};

fn register_security_level_carrier(
    carrier: &parcel::ReplyBinderCarrier,
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    source_method: ServiceMethod,
) -> anyhow::Result<()> {
    if !carrier.is_object {
        warn!(
            "event=route system security-level carrier for {:?} was null; skipping mapping",
            security_level
        );
        return Ok(());
    }

    let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
        .ok_or_else(|| anyhow::anyhow!("failed to parse local security-level carrier target"))?;
    tracker::remember_security_level_target(target, SecurityLevelTargetInfo { security_level });
    info!(
        "event=route registered security-level carrier ptr=0x{:x} cookie=0x{:x} security_level={:?} source_method={:?}",
        target.ptr, target.cookie, security_level, source_method
    );
    Ok(())
}

pub(super) fn build_ko_bing_status_reply(status: &Status) -> anyhow::Result<OutboundReply> {
    if status.exception_code() == ExceptionCode::ServiceSpecific {
        return parcel::build_status_reply(status);
    }

    Ok(synthetic_fallback_reply())
}

fn error_status(error: &anyhow::Error) -> Option<&Status> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Status>())
}

fn build_ko_bing_error_reply(error: &anyhow::Error) -> anyhow::Result<OutboundReply> {
    if let Some(status) = error_status(error) {
        return build_ko_bing_status_reply(status);
    }

    Ok(synthetic_fallback_reply())
}

pub(super) fn precomputed_ko_bing_error_reply(error: &anyhow::Error) -> Status {
    if let Some(status) = error_status(error) {
        if status.exception_code() == ExceptionCode::ServiceSpecific {
            return status.clone();
        }
    }

    Status::new_service_specific_error(ResponseCode::SYSTEM_ERROR.0, None)
}

fn build_ko_bing_error_reply_or_preserve_system(
    error: &anyhow::Error,
) -> anyhow::Result<Option<OutboundReply>> {
    if ko_bing_unavailable_error(error) {
        Ok(None)
    } else {
        build_ko_bing_error_reply(error).map(Some)
    }
}

fn build_ko_bing_status_reply_or_preserve_system(
    status: &Status,
) -> anyhow::Result<Option<OutboundReply>> {
    if ko_bing_unavailable_status(status) {
        Ok(None)
    } else {
        build_ko_bing_status_reply(status).map(Some)
    }
}

fn ko_bing_error_reply_for_method(
    method: &str,
    caller: &CallerInfo,
    error: &anyhow::Error,
) -> anyhow::Result<Option<OutboundReply>> {
    match build_ko_bing_error_reply_or_preserve_system(error)? {
        Some(reply) => {
            warn!(
                "event=reply KOBING {} failed for uid={} pid={}: {:#}; returning KOBING error",
                method, caller.uid, caller.pid, error
            );
            Ok(Some(reply))
        }
        None => {
            warn!(
                "event=reply KOBING {} unavailable for uid={} pid={}: {:#}; preserving original system reply",
                method, caller.uid, caller.pid, error
            );
            Ok(None)
        }
    }
}

fn ko_bing_status_reply_for_method(
    method: &str,
    caller: &CallerInfo,
    status: &Status,
) -> anyhow::Result<Option<OutboundReply>> {
    match build_ko_bing_status_reply_or_preserve_system(status)? {
        Some(reply) => {
            warn!(
                "event=reply KOBING {} failed for uid={} pid={}: {:#}; returning KOBING error",
                method, caller.uid, caller.pid, status
            );
            Ok(Some(reply))
        }
        None => {
            warn!(
                "event=reply KOBING {} unavailable for uid={} pid={}: {:#}; preserving original system reply",
                method, caller.uid, caller.pid, status
            );
            Ok(None)
        }
    }
}

pub(super) fn build_service_specific_reply(code: i32) -> anyhow::Result<parcel::OwnedReply> {
    parcel::build_status_reply(&Status::new_service_specific_error(code, None))
}

macro_rules! finalize_system_success {
    ($result:expr, $context:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    "event=route failed to finalize {} after System success: {:#}; replacing the reply with SYSTEM_ERROR",
                    $context, error
                );
                return Ok(Some(synthetic_fallback_reply()));
            }
        }
    };
}

unsafe fn malformed_system_success_reply(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    context: &str,
    error: anyhow::Error,
) -> anyhow::Result<Option<OutboundReply>> {
    if parcel::parse_reply_status(data, data_size, offsets, offsets_size)
        .is_ok_and(|status| !status.is_ok())
    {
        return Ok(None);
    }
    warn!(
        "event=route failed to decode {} after System success: {:#}; replacing the reply with SYSTEM_ERROR",
        context, error
    );
    Ok(Some(synthetic_fallback_reply()))
}

pub(super) fn build_precomputed_service_reply(
    precomputed: &PrecomputedServiceReply,
) -> anyhow::Result<OutboundReply> {
    match precomputed {
        PrecomputedServiceReply::UpdateSubcomponentSuccess => Ok(parcel::build_void_reply()?),
        PrecomputedServiceReply::GrantSuccess(ko_bing_grant) => {
            Ok(parcel::build_plain_reply(ko_bing_grant)?)
        }
        PrecomputedServiceReply::UngrantSuccess | PrecomputedServiceReply::DeleteKeySuccess => {
            Ok(parcel::build_void_reply()?)
        }
        PrecomputedServiceReply::Error(status) => build_ko_bing_status_reply(status),
    }
}

pub(super) fn build_precomputed_maintenance_reply(
    precomputed: &PrecomputedMaintenanceReply,
) -> anyhow::Result<OutboundReply> {
    match precomputed {
        PrecomputedMaintenanceReply::Success => Ok(parcel::build_void_reply()?),
        PrecomputedMaintenanceReply::Error(status) => build_ko_bing_status_reply(status),
    }
}

pub(super) fn build_no_carrier_ko_bing_key_entry_reply(
    entry: KeyEntryResponse,
    caller: &CallerInfo,
) -> anyhow::Result<parcel::OwnedReply> {
    if entry.r#iSecurityLevel.is_none() {
        return parcel::build_key_entry_reply(entry);
    }

    let carrier = register_synthetic_security_level_carrier(
        entry.r#metadata.keySecurityLevel,
        ServiceMethod::GetKeyEntry,
        caller,
    )?;
    parcel::build_key_entry_reply_with_carrier_bytes(
        entry.r#metadata,
        &carrier.bytes,
        carrier.is_object,
    )
}

fn build_direct_ko_bing_security_level_reply(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    match ipc::with_ko_bing_retry(|ko_bing| Ok(ko_bing.r#getSecurityLevel(security_level)?)) {
        Ok(_level) => {
            let carrier = register_synthetic_security_level_carrier(
                security_level,
                ServiceMethod::GetSecurityLevel,
                &pending.caller,
            )?;
            Ok(Some(
                parcel::build_get_security_level_reply_with_carrier_bytes(
                    &carrier.bytes,
                    carrier.is_object,
                )?,
            ))
        }
        Err(error) => ko_bing_error_reply_for_method("getSecurityLevel", &pending.caller, &error),
    }
}

pub(super) unsafe fn observe_system_service_reply(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } => {
            let carrier = match parcel::extract_direct_binder_reply_carrier(
                data,
                data_size,
                offsets,
                offsets_size,
            ) {
                Ok(carrier) => carrier,
                Err(error) => {
                    return malformed_system_success_reply(
                        data,
                        data_size,
                        offsets,
                        offsets_size,
                        "getSecurityLevel reply",
                        error,
                    );
                }
            };
            finalize_system_success!(
                register_security_level_carrier(
                    &carrier,
                    *security_level,
                    ServiceMethod::GetSecurityLevel,
                ),
                "getSecurityLevel security-level carrier"
            );
        }
        ParsedServiceRequest::GetKeyEntry { .. } => {
            let (carrier, metadata) =
                match parcel::parse_key_entry_reply(data, data_size, offsets, offsets_size) {
                    Ok(response) => response,
                    Err(error) => {
                        return malformed_system_success_reply(
                            data,
                            data_size,
                            offsets,
                            offsets_size,
                            "getKeyEntry reply",
                            error,
                        );
                    }
                };
            finalize_system_success!(
                register_security_level_carrier(
                    &carrier,
                    metadata.r#keySecurityLevel,
                    ServiceMethod::GetKeyEntry,
                ),
                "getKeyEntry security-level carrier"
            );
        }
        _ => {}
    }
    Ok(None)
}

pub(super) unsafe fn build_service_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    if pending.route != RouteTarget::KoBing {
        return observe_system_service_reply(tr, pending);
    }

    if matches!(
        &pending.request,
        ParsedServiceRequest::GetSecurityLevel { .. }
    ) {
        if let Err(error) = observe_system_service_reply(tr, pending).map(|_| ()) {
            warn!(
                "event=route failed to retain original System security-level target before KOBING reply rewrite: {:#}",
                error
            );
        }
    }

    if let Err(error) = ensure_mirror_state_recovered() {
        warn!(
            "event=route KOBING service {:?} blocked by unresolved mirror recovery for uid={} pid={}: {:#}",
            pending.request.method(), pending.caller.uid, pending.caller.pid, error
        );
        return Ok(Some(synthetic_fallback_reply()));
    }

    let caller = &pending.caller;
    let _guard = BypassGuard::enter();

    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } => {
            build_direct_ko_bing_security_level_reply(*security_level, pending)
        }
        ParsedServiceRequest::GetKeyEntry { key } => {
            let entry = match ipc::with_ko_bing_retry(|ko_bing| {
                Ok(ko_bing.r#getKeyEntry(Some(caller), key)?)
            }) {
                Ok(entry) => entry,
                Err(error) => {
                    return ko_bing_error_reply_for_method("getKeyEntry", &pending.caller, &error);
                }
            };
            Ok(Some(build_no_carrier_ko_bing_key_entry_reply(
                entry,
                &pending.caller,
            )?))
        }
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => {
            match ipc::with_ko_bing_once(|ko_bing| {
                Ok(ko_bing.r#updateSubcomponent(
                    Some(caller),
                    key,
                    public_cert.as_deref(),
                    certificate_chain.as_deref(),
                )?)
            }) {
                Ok(()) => Ok(Some(parcel::build_void_reply()?)),
                Err(error) => {
                    ko_bing_error_reply_for_method("updateSubcomponent", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::ListEntries { domain, nspace } => {
            match ipc::with_ko_bing_retry(|ko_bing| {
                Ok(ko_bing.r#listEntries(Some(caller), *domain, *nspace)?)
            }) {
                Ok(entries) => Ok(Some(parcel::build_plain_reply(&entries)?)),
                Err(error) => {
                    ko_bing_error_reply_for_method("listEntries", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => {
            let ko_bing_grant = match ipc::with_ko_bing_once(|ko_bing| {
                Ok(ko_bing.r#grant(Some(caller), key, *grantee_uid, *access_vector)?)
            }) {
                Ok(ko_bing_grant) => ko_bing_grant,
                Err(error) => {
                    return ko_bing_error_reply_for_method("grant", &pending.caller, &error)
                }
            };
            Ok(Some(parcel::build_plain_reply(&ko_bing_grant)?))
        }
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            match ipc::with_ko_bing_once(|ko_bing| {
                Ok(ko_bing.r#ungrant(Some(caller), key, *grantee_uid)?)
            }) {
                Ok(()) => Ok(Some(parcel::build_void_reply()?)),
                Err(error) => ko_bing_error_reply_for_method("ungrant", &pending.caller, &error),
            }
        }
        ParsedServiceRequest::GetNumberOfEntries { domain, nspace } => {
            match ipc::with_ko_bing_retry(|ko_bing| {
                Ok(ko_bing.r#getNumberOfEntries(Some(caller), *domain, *nspace)?)
            }) {
                Ok(count) => Ok(Some(parcel::build_plain_reply(&count)?)),
                Err(error) => {
                    ko_bing_error_reply_for_method("getNumberOfEntries", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::ListEntriesBatched {
            domain,
            nspace,
            starting_past_alias,
        } => {
            match ipc::with_ko_bing_retry(|ko_bing| {
                Ok(ko_bing.r#listEntriesBatched(
                    Some(caller),
                    *domain,
                    *nspace,
                    starting_past_alias.as_deref(),
                )?)
            }) {
                Ok(entries) => Ok(Some(parcel::build_plain_reply(&entries)?)),
                Err(error) => {
                    ko_bing_error_reply_for_method("listEntriesBatched", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::GetSupplementaryAttestationInfo { tag } => {
            match ipc::with_ko_bing_retry(|ko_bing| {
                Ok(ko_bing.r#getSupplementaryAttestationInfo(*tag)?)
            }) {
                Ok(info) => Ok(Some(parcel::build_plain_reply(&info)?)),
                Err(error) => ko_bing_error_reply_for_method(
                    "getSupplementaryAttestationInfo",
                    &pending.caller,
                    &error,
                ),
            }
        }
        ParsedServiceRequest::DeleteKey { key } => {
            match ipc::with_ko_bing_once(|ko_bing| Ok(ko_bing.r#deleteKey(Some(caller), key)?)) {
                Ok(()) => Ok(Some(parcel::build_void_reply()?)),
                Err(error) => ko_bing_error_reply_for_method("deleteKey", &pending.caller, &error),
            }
        }
    }
}

pub(super) unsafe fn observe_system_security_level_reply(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    if let ParsedSecurityLevelRequest::CreateOperation {
        operation_parameters,
        ..
    } = &pending.request
    {
        if let Err(error) = register_operation_target_from_reply(
            tr,
            RouteTarget::System,
            None,
            operation_allows_aad(operation_parameters),
        ) {
            return malformed_system_success_reply(
                data,
                data_size,
                offsets,
                offsets_size,
                "createOperation reply",
                error,
            );
        }
    }
    Ok(None)
}

pub(super) unsafe fn build_security_level_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<Option<OutboundReply>> {
    if pending.route != RouteTarget::KoBing {
        return observe_system_security_level_reply(tr, pending);
    }

    build_ko_bing_security_level_reply(pending, (tr.flags & super::super::binder::TF_ONE_WAY) == 0)
}

pub(super) fn build_ko_bing_security_level_reply(
    pending: &PendingSecurityLevelCall,
    publish_operation_carrier: bool,
) -> anyhow::Result<Option<OutboundReply>> {
    if let Err(error) = ensure_mirror_state_recovered() {
        warn!(
            "event=route KOBING security-level {:?} blocked by unresolved mirror recovery for uid={} pid={}: {:#}",
            pending.request.method(), pending.caller.uid, pending.caller.pid, error
        );
        return Ok(Some(synthetic_fallback_reply()));
    }
    let caller = &pending.caller;
    let _guard = BypassGuard::enter();
    let ko_bing_level = match ipc::with_ko_bing_retry(|ko_bing| {
        Ok(ko_bing.r#getKoBingSecurityLevel(pending.security_level)?)
    }) {
        Ok(level) => level,
        Err(error) => {
            let method = format!("security-level lookup {:?}", pending.security_level);
            return ko_bing_error_reply_for_method(&method, &pending.caller, &error);
        }
    };

    match &pending.request {
        ParsedSecurityLevelRequest::CreateOperation {
            key,
            operation_parameters,
            forced,
        } => {
            let ko_bing_response = match ko_bing_level.r#createOperation(
                Some(caller),
                key,
                operation_parameters,
                *forced,
            ) {
                Ok(response) => response,
                Err(error) => {
                    return ko_bing_status_reply_for_method(
                        "createOperation",
                        &pending.caller,
                        &error,
                    );
                }
            };
            Ok(Some(build_no_carrier_create_operation_reply(
                ko_bing_response,
                operation_allows_aad(operation_parameters),
                &pending.caller,
                publish_operation_carrier,
            )?))
        }
        ParsedSecurityLevelRequest::GenerateKey {
            key,
            attestation_key,
            params,
            flags,
            entropy,
        } => {
            match ko_bing_level.r#generateKey(
                Some(caller),
                key,
                attestation_key.as_ref(),
                params,
                *flags,
                entropy,
            ) {
                Ok(metadata) => Ok(Some(parcel::build_plain_reply(&metadata)?)),
                Err(error) => {
                    ko_bing_status_reply_for_method("generateKey", &pending.caller, &error)
                }
            }
        }
        ParsedSecurityLevelRequest::ImportKey {
            key,
            attestation_key,
            params,
            flags,
            key_data,
        } => {
            match ko_bing_level.r#importKey(
                Some(caller),
                key,
                attestation_key.as_ref(),
                params,
                *flags,
                key_data,
            ) {
                Ok(metadata) => Ok(Some(parcel::build_plain_reply(&metadata)?)),
                Err(error) => ko_bing_status_reply_for_method("importKey", &pending.caller, &error),
            }
        }
        ParsedSecurityLevelRequest::ImportWrappedKey {
            key,
            wrapping_key,
            masking_key,
            params,
            authenticators,
        } => {
            match ko_bing_level.r#importWrappedKey(
                Some(caller),
                key,
                wrapping_key,
                masking_key.as_deref(),
                params,
                authenticators,
            ) {
                Ok(metadata) => Ok(Some(parcel::build_plain_reply(&metadata)?)),
                Err(error) => {
                    ko_bing_status_reply_for_method("importWrappedKey", &pending.caller, &error)
                }
            }
        }
        ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key } => {
            match ko_bing_level.r#convertStorageKeyToEphemeral(Some(caller), storage_key) {
                Ok(response) => Ok(Some(parcel::build_plain_reply(&response)?)),
                Err(error) => ko_bing_status_reply_for_method(
                    "convertStorageKeyToEphemeral",
                    &pending.caller,
                    &error,
                ),
            }
        }
        ParsedSecurityLevelRequest::DeleteKey { key } => {
            match ko_bing_level.r#deleteKey(Some(caller), key) {
                Ok(()) => Ok(Some(parcel::build_void_reply()?)),
                Err(error) => ko_bing_status_reply_for_method("deleteKey", &pending.caller, &error),
            }
        }
    }
}

#[cfg(test)]
mod tests;
