// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOTIMPL, E_UNEXPECTED, S_OK};

const POLICY_DENIED: HRESULT = HRESULT(0x800704ec_u32 as i32);

struct FakeState {
    support: u32,
    query_result: HRESULT,
    result: HRESULT,
    outcome: u32,
    details_count: u32,
    handle: bool,
    invalid_header: bool,
    invalid_pool: bool,
    legacy_result: HRESULT,
    legacy_handle: bool,
    calls: Vec<&'static str>,
    inputs: Vec<(Vec<u8>, u32)>,
    contracts: Vec<(u32, u32, u32, u32)>,
    closes: usize,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            support: 0x10,
            query_result: S_OK,
            result: POLICY_DENIED,
            outcome: 3,
            details_count: 2,
            handle: false,
            invalid_header: false,
            invalid_pool: false,
            legacy_result: S_OK,
            legacy_handle: true,
            calls: Vec::new(),
            inputs: Vec::new(),
            contracts: Vec::new(),
            closes: 0,
        }
    }
}

thread_local! {
    // The injected exports are synchronous and the owned handles stay on this test thread.
    static STATE: RefCell<FakeState> = RefCell::new(FakeState::default());
    static INJECTED_API: Cell<Option<SecurityEnvironmentApi>> = const { Cell::new(None) };
}

pub(super) fn injected_api() -> Option<SecurityEnvironmentApi> {
    INJECTED_API.with(Cell::get)
}

struct ApiScope(Option<SecurityEnvironmentApi>);

impl ApiScope {
    fn new(api: SecurityEnvironmentApi) -> Self {
        Self(INJECTED_API.with(|slot| slot.replace(Some(api))))
    }
}

impl Drop for ApiScope {
    fn drop(&mut self) {
        INJECTED_API.with(|slot| slot.set(self.0));
    }
}

fn reset() -> SecurityEnvironmentApi {
    STATE.with(|state| *state.borrow_mut() = FakeState::default());
    let mut api = SecurityEnvironmentApi::from_raw_parts(create, query, close);
    api.create2 = Some(create2);
    api
}

fn calls() -> Vec<&'static str> {
    STATE.with(|state| state.borrow().calls.clone())
}

fn closes() -> usize {
    STATE.with(|state| state.borrow().closes)
}

unsafe extern "system" fn query(flags: *mut u32) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("query");
        if state.query_result.is_ok() {
            unsafe { *flags = state.support };
        }
        state.query_result
    })
}

unsafe extern "system" fn create(
    specification: *const c_void,
    size: u32,
    flags: u32,
    out: *mut HANDLE,
) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("create");
        let specification =
            unsafe { std::slice::from_raw_parts(specification.cast(), size as usize) };
        state.inputs.push((specification.to_vec(), flags));
        if state.legacy_handle {
            unsafe { *out = HANDLE(std::ptr::dangling_mut()) };
        }
        state.legacy_result
    })
}

unsafe extern "system" fn create2(
    specification: *const c_void,
    size: u32,
    flags: u32,
    result: *mut RawPolicyResult,
    out: *mut HANDLE,
) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("create2");
        let specification =
            unsafe { std::slice::from_raw_parts(specification.cast(), size as usize) };
        state.inputs.push((specification.to_vec(), flags));
        let result = unsafe { &mut *result };
        state.contracts.push((
            result.size,
            result.version,
            result.details_capacity,
            result.resource_capacity_chars,
        ));
        let header_size = if cfg!(target_pointer_width = "64") {
            48
        } else {
            40
        };
        if result.size < header_size
            || result.version != 1
            || result.details_capacity > 64
            || result.resource_capacity_chars > 32768
            || (result.details_capacity != 0 && result.details.is_null())
            || (result.resource_capacity_chars != 0 && result.resource_buffer.is_null())
        {
            return E_INVALIDARG;
        }
        result.outcome = state.outcome;
        result.details_count = state.details_count;
        if state.details_count == 2
            && result.details_capacity >= 2
            && result.resource_capacity_chars >= 14
        {
            let storage: Vec<u16> = "C:\\one\0C:\\two\0".encode_utf16().collect();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    storage.as_ptr(),
                    result.resource_buffer,
                    storage.len(),
                );
                for index in 0..2 {
                    *result.details.add(index) = RawPolicyDetail {
                        failure_class: 2,
                        failure_reason: 3,
                        required_action: 2,
                        resource_kind: 1,
                        value_kind: 1,
                        flags: 3,
                        requested_value: 2,
                        required_value: 0,
                        resource_offset_chars: (index * 7) as u32,
                        resource_chars_written: 7,
                        resource_chars_required: 7,
                    };
                }
            }
            result.resource_chars_written = storage.len() as u32;
            result.resource_chars_required = storage.len() as u32;
        }
        if state.invalid_header {
            result.version = 99;
        }
        if state.invalid_pool {
            result.resource_buffer = std::ptr::null_mut();
        }
        if state.handle {
            unsafe { *out = HANDLE(std::ptr::dangling_mut()) };
        }
        state.result
    })
}

unsafe extern "system" fn close(_: HANDLE) {
    STATE.with(|state| state.borrow_mut().closes += 1);
}

#[test]
fn reports_each_action_without_mutating_the_specification_or_retrying() {
    let api = reset();
    let specification = b"unchanged PSEC specification";
    let error = api.create_with_diagnostics(specification, 7).unwrap_err();
    let message = error.message(false);
    assert!(message.starts_with("failed to create the process security environment:"));
    assert!(message.contains("CreateProcessSecurityEnvironment2"));
    assert!(message.contains("0x800704EC"));
    assert!(message.contains("IT-managed policy rule"));
    assert!(message.contains("Returned constraints: 2 (non-exhaustive"));
    assert!(message.contains("Resource 1: \"C:\\\\one\""));
    assert!(message.contains("Resource 2: \"C:\\\\two\""));
    assert!(!error.is_api_unavailable());
    assert_eq!(calls(), ["query", "create2"]);
    STATE.with(|state| assert_eq!(state.borrow().inputs, [(specification.to_vec(), 7)]));
    assert_eq!(closes(), 0);
}

#[test]
fn missing_export_or_support_bit_uses_the_original_creation_api() {
    for missing_export in [false, true] {
        let mut api = reset();
        if missing_export {
            api.create2 = None;
        } else {
            STATE.with(|state| state.borrow_mut().support = 1);
        }
        let environment = api.create_with_diagnostics(b"spec", 0).unwrap();
        assert_eq!(
            calls(),
            if missing_export {
                vec!["create"]
            } else {
                vec!["query", "create"]
            }
        );
        drop(environment);
        assert_eq!(closes(), 1);
    }
}

#[test]
fn only_the_native_policy_result_bit_selects_cpse2() {
    for support in [0, 1, 2, 4, 8, 0x0f, 0x20, 0x10, 0x1f, 0x30] {
        let api = reset();
        STATE.with(|state| state.borrow_mut().support = support);
        let result = api.create_with_diagnostics(b"spec", 0);
        if support & 0x10 != 0 {
            assert!(result.is_err());
            assert_eq!(calls(), ["query", "create2"], "{support:#x}");
        } else {
            drop(result.unwrap());
            assert_eq!(calls(), ["query", "create"], "{support:#x}");
        }
    }
}

#[test]
fn creation_supplies_the_exact_native_v1_header_and_maximum_capacities() {
    let api = reset();
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == POLICY_DENIED.0)
    );
    let size = if cfg!(target_pointer_width = "64") {
        48
    } else {
        40
    };
    STATE.with(|state| assert_eq!(state.borrow().contracts, [(size, 1, 64, 32768)]));
}

#[test]
fn optional_discovery_failure_does_not_change_legacy_creation_success() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().query_result = E_FAIL);
    let environment = api.create_with_diagnostics(b"spec", 0).unwrap();
    assert_eq!(calls(), ["query", "create"]);
    drop(environment);
    assert_eq!(closes(), 1);
}

#[test]
fn discovery_failure_is_explained_if_legacy_creation_also_fails() {
    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.query_result = E_FAIL;
        state.legacy_result = POLICY_DENIED;
        state.legacy_handle = false;
    });
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let message = error.message(true);
    assert!(message.starts_with("captureDenials: failed to start learning-mode capture: CreateProcessSecurityEnvironment failed"));
    assert!(message.contains("IT-managed policy rule"));
    assert!(message.contains(
        "Creation-policy diagnostics unavailable: QueryProcessSecurityEnvironmentSupport failed"
    ));
    assert!(!error.is_api_unavailable());
    assert_eq!(calls(), ["query", "create"]);
    assert_eq!(closes(), 0);
}

#[test]
fn decision_free_unavailability_can_make_one_legacy_compatibility_call() {
    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = E_NOTIMPL;
        state.outcome = 0;
        state.details_count = 0;
    });
    let environment = api.create_with_diagnostics(b"same spec", 4).unwrap();
    assert_eq!(calls(), ["query", "create2", "create"]);
    STATE.with(|state| assert_eq!(state.borrow().inputs, vec![(b"same spec".to_vec(), 4); 2]));
    drop(environment);
    assert_eq!(closes(), 1);
}

#[test]
fn native_decisions_invalid_results_and_returned_handles_never_trigger_fallback() {
    for (outcome, count, invalid_header, invalid_pool, handle) in [
        (1, 0, false, false, false),
        (2, 0, false, false, false),
        (3, 0, false, false, false),
        (4, 0, false, false, false),
        (999, 0, false, false, false),
        (0, 2, false, false, false),
        (0, 0, true, false, false),
        (0, 0, false, true, false),
        (0, 0, false, false, true),
    ] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.result = E_NOTIMPL;
            state.outcome = outcome;
            state.details_count = count;
            state.invalid_header = invalid_header;
            state.invalid_pool = invalid_pool;
            state.handle = handle;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        assert_eq!(calls(), ["query", "create2"]);
        assert!(error.is_api_unavailable());
        assert_eq!(closes(), usize::from(handle));
    }
}

#[test]
fn native_failures_keep_their_status_and_close_unexpected_handles_once() {
    for result in [POLICY_DENIED, E_FAIL] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.result = result;
            state.handle = true;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        assert!(
            matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == result.0)
        );
        assert_eq!(calls(), ["query", "create2"]);
        assert_eq!(closes(), 1);
    }
}

#[test]
fn successful_creation_does_not_depend_on_optional_diagnostic_metadata() {
    for invalid in [false, true] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.result = S_OK;
            state.handle = true;
            state.outcome = if invalid { 999 } else { 2 };
            state.details_count = 0;
            state.invalid_header = invalid;
            state.invalid_pool = invalid;
        });
        let environment = api.create_with_diagnostics(b"spec", 0).unwrap();
        assert_eq!(calls(), ["query", "create2"]);
        assert_eq!(closes(), 0);
        drop(environment);
        assert_eq!(closes(), 1);
    }
}

#[test]
fn successful_hresult_without_an_environment_is_still_a_failure() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().result = S_OK);
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == E_UNEXPECTED.0)
    );
    assert_eq!(calls(), ["query", "create2"]);
    assert_eq!(closes(), 0);
}

#[test]
fn legacy_failure_closes_an_unexpected_native_handle() {
    let mut api = reset();
    api.create2 = None;
    STATE.with(|state| state.borrow_mut().legacy_result = E_FAIL);
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(matches!(error.cause, LearningModeError::HResultCall {
        function: "CreateProcessSecurityEnvironment", code,
    } if code == E_FAIL.0));
    assert_eq!(calls(), ["create"]);
    assert_eq!(closes(), 1);
}

#[test]
fn trace_errors_and_public_api_debug_preserve_their_existing_shapes() {
    let mut api = reset();
    let debug = format!("{api:?}");
    api.create2 = None;
    assert_eq!(format!("{api:?}"), debug);
    let cause = LearningModeError::HResultCall {
        function: "StartLearningModeTrace",
        code: E_NOTIMPL.0,
    };
    let expected = crate::launch_diagnostics::security_environment_failure_message(&cause, true);
    let error = CreationError::from(cause);
    assert_eq!(error.message(true), expected);
    assert!(error.is_api_unavailable());
}

#[test]
fn real_runner_propagates_cpse2_refusals_with_and_without_capture() {
    use crate::base_container_runner::BaseContainerRunner;
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::{ExecutionRequest, FailurePhase};
    use wxc_common::sandbox_process::{SandboxBackend, StdioMode};

    let directory = tempfile::tempdir().unwrap();
    let system_root = std::env::var("SystemRoot").unwrap();
    for capture in [false, true] {
        for complete_environment in [true, false] {
            let api = reset();
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.legacy_result = POLICY_DENIED;
                state.legacy_handle = false;
            });
            let _scope = ApiScope::new(api);
            let mut request = ExecutionRequest {
                script_code: "cmd.exe /d /c exit 0".into(),
                working_directory: directory.path().to_string_lossy().into_owned(),
                env: Some(if complete_environment {
                    vec![
                        format!("SystemRoot={system_root}"),
                        format!("LOCALAPPDATA={}", directory.path().display()),
                    ]
                } else {
                    Vec::new()
                }),
                ..Default::default()
            };
            if capture {
                request.policy.capture_denials = Some(Default::default());
            }
            let before = serde_json::to_value(&request).unwrap();
            let mut runner = BaseContainerRunner::new_for_selected_request();
            let mut logger = Logger::new(Mode::Buffer);
            let response = match runner.spawn(&request, &mut logger, StdioMode::Pipes) {
                Ok(_) => panic!("the injected refusal must not produce a live process"),
                Err(response) => response,
            };
            assert_eq!(serde_json::to_value(&request).unwrap(), before);
            assert_eq!(response.exit_code, -1);
            assert!(response.output_metadata.is_none());
            assert_eq!(closes(), 0);
            if !complete_environment {
                assert_eq!(response.failure_phase, FailurePhase::Rejected);
                assert!(response.error_message.contains("SYSTEMROOT"));
                assert!(calls().is_empty(), "preparation must fail before creation");
                continue;
            }
            assert_eq!(response.failure_phase, FailurePhase::LaunchFailed);
            assert_eq!(response.standard_err, response.error_message);
            assert_eq!(
                response.error_message.starts_with("captureDenials:"),
                capture
            );
            assert!(response
                .error_message
                .contains("CreateProcessSecurityEnvironment2"));
            assert!(response
                .error_message
                .contains("Returned constraints: 2 (non-exhaustive"));
            assert!(response.error_message.contains("Resource 1: \"C:\\\\one\""));
            assert!(response.error_message.contains("Resource 2: \"C:\\\\two\""));
            assert_eq!(calls(), ["query", "create2"]);
            STATE.with(|state| assert_eq!(state.borrow().inputs.len(), 1));
        }
    }
}
