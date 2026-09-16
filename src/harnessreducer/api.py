from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from harnessreducer.process_supervisor import termination_guard
from harnessreducer.reduction_engines import check_perses, validate_tool
from harnessreducer.check_mode import (
    emit_check_statistics_summary,
    record_check_reference,
    reset_check_state,
    run_treereducer_with_check,
)
from harnessreducer.fdp_transform import (
    PARSER,
    VALUES_HEADER_NAME,
    _iter_nodes,
    _node_text,
    inline_source_with_report,
    inject_ids,
    load_trace,
    strip_injected_ids,
)
from harnessreducer.reducer_runner import (
    PHASE3_DIRECT,
    PHASE3_SPLIT,
    DEFAULT_TREEREDUCE_JOBS,
    MAX_TREEREDUCE_JOBS,
    apply_coverage_guided_slice,
    append_exec_timeout_tester_args,
    candidate_files_match,
    check_reducer_crash_pattern,
    check_reducer_symbolized_reduction_oracle,
    check_reducer_symbolized_crash_pattern,
    check_tree_reducer,
    extract_crash_pattern_from_output,
    extract_first_dynamic_library_crash_site,
    extract_first_sanitizer_stack_trace,
    get_crash_tester_path,
    get_dynamic_reference_crash_site,
    get_last_interesting_file,
    get_normal_reference_stack_depth,
    get_poc_runtime_args,
    get_reference_crash_pattern_symbolize_1,
    get_symbolized_reference_stack_depth,
    check_harness_compilation,
    compile_dump_mode_harness,
    configure_debug_logging,
    configure_work_dir,
    dump_fdp_trace,
    format_reduced_harness,
    get_work_dir,
    has_static_target_libraries,
    HarnessCrashDetected,
    reset_stack_trace_state,
    reset_last_interesting_state,
    reset_poc_runtime_args,
    resolve_amortized_link_inputs,
    run_treereducer,
    run_command,
    set_current_exec_timeout_ms,
    validate_crash_pattern,
    validate_symbolized_crash_pattern_depth_location,
    validate_crash_pattern_and_stack_trace,
    validate_stack_trace,
    validate_phase3_mode,
    DEFAULT_EXEC_TIMEOUT_MS,
)

ADDITIONAL_HEADERS = [
    "#include <cstddef>",
    "#include <cstring>",
    "#include <string>",
    "#include <vector>",
    "#include <deque>",
    "#include <fstream>",
    "#include <map>",
    "#include <mutex>",
    "#include <sstream>",
    "#include <cmath>",
    "#include <iomanip>",
    "#include <limits>",
]

DIRECT_INPUT_HEADER_NAME = VALUES_HEADER_NAME


@dataclass(frozen=True)
class TaggedHarness:
    path: str
    fdp_callsite_count: int

    def __fspath__(self) -> str:
        return self.path

    def __str__(self) -> str:
        return self.path

@dataclass(frozen=True)
class ReductionConfig:
    harness_path: str
    compile_flags: str | None = None
    link_flags: str | None = None
    crash_input: str | None = None
    work_dir: str | None = None
    start_id: int = 100000
    marker: str = "FDP_ID"
    use_llm: bool = False
    stable: bool = False
    phase3_mode: str = PHASE3_SPLIT
    statistics: bool = False
    slice_enabled: bool = False
    check: bool = False
    debug: bool = False
    snapshot: bool = False
    amortize_link: bool = False
    symbolize: bool = False
    jobs: int = DEFAULT_TREEREDUCE_JOBS
    profile: bool = False
    tool: str = "treereduce"


@dataclass(frozen=True)
class ReductionResult:
    reduced_harness: str
    tagged_harness: str
    fdp_trace: str | None
    generated_headers: tuple[str, ...] = ()
    poc_runtime_args: tuple[str, ...] = ()
    success: bool = True


@dataclass(frozen=True)
class DirectInputEntry:
    insert_pos: int
    data_name: str | None
    size_name: str | None
    data_uses_canonical_type: bool
    size_uses_canonical_type: bool


def tag_harness_with_fdp_ids(
    harness_path: str,
    start_id: int,
    marker: str,
) -> TaggedHarness:
    source_path = Path(harness_path)
    source = source_path.read_text(encoding="utf-8")
    transformed, count = inject_ids(source, start_id, marker)

    # Keep the instrumented source separate from the input even when the user
    # chooses the input's directory as --work-dir.
    suffix = source_path.suffix or ".cpp"
    tagged_name = f"{source_path.stem}.tagged{suffix}"
    tagged_harness_file = str(Path(get_work_dir()) / tagged_name)
    Path(tagged_harness_file).write_text(transformed, encoding="utf-8")
    print(f"Injected {count} FDP callsite IDs into {tagged_harness_file}")
    return TaggedHarness(tagged_harness_file, count)


def _tagged_harness_path(tagged: TaggedHarness | str) -> str:
    return tagged.path if isinstance(tagged, TaggedHarness) else str(tagged)


def _tagged_harness_fdp_count(tagged: TaggedHarness | str) -> int:
    # Backward-compatible fallback for tests or callers that mock the older
    # string return value.
    return tagged.fdp_callsite_count if isinstance(tagged, TaggedHarness) else 1


def _prepend_additional_headers(harness_path: str) -> None:
    content = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
    missing = [header for header in ADDITIONAL_HEADERS if header not in content]
    if not missing:
        return
    headers_block = "\n".join(missing) + "\n"
    Path(harness_path).write_text(headers_block + content, encoding="utf-8")


def _finalize_fallback_harness(reduced_harness_path: str, start_id: int) -> str:
    fallback_source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    cleaned_source, removed = strip_injected_ids(fallback_source, start_id=start_id)
    if removed:
        Path(reduced_harness_path).write_text(cleaned_source, encoding="utf-8")
        print(f"Removed {removed} injected FDP IDs from fallback harness.")
    _prepend_additional_headers(reduced_harness_path)
    return reduced_harness_path


def _run_inline_stack_diagnostic(
    harness_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None,
    *,
    symbolize: bool,
) -> tuple[int, str, str | None]:
    cmd = [
        get_crash_tester_path(),
        harness_path,
        crash_pattern,
        "--crash-input",
        crash_input or "",
        f"--compile-flags={compile_flags or ''}",
        f"--link-flags={link_flags or ''}",
    ]
    if fdp_trace_file:
        cmd.extend(["--fdp-trace", fdp_trace_file])
    if symbolize:
        cmd.append("--symbolize")
    append_exec_timeout_tester_args(cmd)

    proc = run_command(
        cmd,
        "Inline stack diagnostic failed",
        ignore_errors=True,
    )
    output = proc.stdout + "\n" + proc.stderr
    return proc.returncode, output, extract_first_sanitizer_stack_trace(output)


def _append_inline_stack_diagnostics(
    log_path: str,
    *,
    before_path: str,
    after_path: str,
    crash_pattern: str,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    fdp_trace_file: str | None,
    crash_pattern_symbolize_0: str | None = None,
) -> None:
    expected_dynamic_site = get_dynamic_reference_crash_site()
    lines = [
        "\n===== inline before/after stack diagnostics =====",
        "These diagnostics are not used for the pass/fail decision above.",
    ]
    if expected_dynamic_site is not None:
        lines.extend(
            [
                "expected_dynamic_crash_site:",
                f"  library: {expected_dynamic_site.library_path}",
                f"  offset: {expected_dynamic_site.offset}",
            ]
        )

    for label, source_path in (
        ("before_inlining", before_path),
        ("after_inlining", after_path),
    ):
        lines.append(f"\n--- {label}: {source_path} ---")
        for symbolize in (False, True):
            pattern = (
                crash_pattern
                if symbolize
                else crash_pattern_symbolize_0 or crash_pattern
            )
            returncode, output, trace = _run_inline_stack_diagnostic(
                source_path,
                pattern,
                crash_input,
                compile_flags,
                link_flags,
                fdp_trace_file,
                symbolize=symbolize,
            )
            mode_label = f"symbolize={int(symbolize)}"
            lines.append(f"{mode_label} returncode: {returncode}")
            if expected_dynamic_site is not None:
                actual_site = extract_first_dynamic_library_crash_site(
                    output,
                    link_flags,
                    expected_library=expected_dynamic_site.library_path,
                )
                if actual_site is None:
                    lines.append(f"{mode_label} dynamic_crash_site: <not found>")
                else:
                    lines.append(
                        f"{mode_label} dynamic_crash_site: "
                        f"{actual_site.library_path}+{actual_site.offset}"
                    )
            lines.append(f"{mode_label} first_stack_trace:")
            lines.append(trace if trace else "<no-first-stack-trace-found>")

    lines.append("===== end inline before/after stack diagnostics =====\n")
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def _cpp_byte(value: int) -> str:
    return f"0x{value & 0xFF:02x}"


def _direct_input_header_source(data: bytes) -> str:
    byte_values = list(data)
    if byte_values:
        lines = ["{"]
        for start in range(0, len(byte_values), 16):
            chunk = byte_values[start : start + 16]
            suffix = "," if start + 16 < len(byte_values) else ""
            byte_text = ", ".join(_cpp_byte(value) for value in chunk)
            lines.append("    " + byte_text + suffix)
        lines.append("}")
        initializer = "\n".join(lines)
        size_expression = "sizeof(fuzz_values)"
        declaration = f"static uint8_t fuzz_values[] = {initializer};"
    else:
        declaration = "static uint8_t fuzz_values[1] = {0x00};"
        size_expression = "0"

    return (
        "#pragma once\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n\n"
        f"{declaration}\n"
        f"static constexpr size_t fuzz_index = {size_expression};\n"
    )


def _find_first_descendant(node, node_type: str):
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == node_type:
            return current
        stack.extend(reversed(current.children))
    return None


def _declarator_identifier_text(node, source_bytes: bytes) -> str | None:
    """Follow the declared name, never identifiers in types, sizes or defaults."""
    while node is not None:
        if node.type == "identifier":
            return _node_text(source_bytes, node).strip()
        child = node.child_by_field_name("declarator")
        if child is None and node.type in {"parenthesized_declarator", "attributed_declarator"}:
            children = [n for n in node.named_children if n.type != "comment"]
            child = children[0] if children else None
        node = child
    return None


def _function_declarator_has_name(
    node,
    source_bytes: bytes,
    expected_name: str,
) -> bool:
    return _declarator_identifier_text(node, source_bytes) == expected_name


def _normalized_type_text(text: str) -> str:
    return " ".join(text.strip().split())


def _parameter_name_and_shape(node, source_bytes: bytes) -> tuple[str | None, str, str]:
    type_node = node.child_by_field_name("type")
    declarator_node = node.child_by_field_name("declarator")
    if type_node is None or node.has_error:
        raise ValueError("Unsupported input parameter declaration.")
    name = _declarator_identifier_text(declarator_node, source_bytes)
    if declarator_node is not None:
        if any(child.type in {
            "function_declarator", "abstract_function_declarator",
            "reference_declarator", "abstract_reference_declarator",
            "pointer_type_declarator", "variadic_declarator",
        } for child in _iter_nodes(declarator_node)):
            raise ValueError("Unsupported input parameter declarator.")
        if name is None and not declarator_node.type.startswith("abstract_"):
            raise ValueError("Could not identify the input parameter name safely.")
        # Assigning to a const pointer is invalid. Pointee constness, which is
        # outside the pointer declarator, remains supported.
        if name is not None and declarator_node.type == "pointer_declarator" and any(
            child.type == "type_qualifier" and _node_text(source_bytes, child) == "const"
            for child in declarator_node.children
        ):
            raise ValueError("The input pointer parameter is not assignable.")
    if name is not None and declarator_node.type == "identifier" and any(
        child.type == "type_qualifier" and _node_text(source_bytes, child) == "const"
        for child in node.children
    ):
        raise ValueError("The input parameter is not assignable.")
    return (
        name,
        _normalized_type_text(_node_text(source_bytes, type_node)),
        _node_text(source_bytes, declarator_node) if declarator_node is not None else "",
    )


def _is_canonical_direct_data_parameter(type_text: str, declarator_text: str) -> bool:
    byte_types = {"uint8_t", "std::uint8_t", "unsigned char"}
    return type_text in byte_types and (
        "*" in declarator_text or "[" in declarator_text
    )


def _is_canonical_direct_size_parameter(type_text: str) -> bool:
    return type_text in {"size_t", "std::size_t"}


def _find_fuzzer_entry_for_direct_input(source: str) -> DirectInputEntry:
    source_bytes = source.encode("utf-8")
    tree = PARSER.parse(source_bytes)

    entries = []
    for node in _iter_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None or not _function_declarator_has_name(
            declarator, source_bytes, "LLVMFuzzerTestOneInput"
        ):
            continue

        entries.append((node, declarator))

    if len(entries) != 1:
        raise ValueError("Could not identify a unique LLVMFuzzerTestOneInput definition.")
    node, declarator = entries[0]
    function = _find_first_descendant(declarator, "function_declarator")
    parameter_list = function.child_by_field_name("parameters") if function is not None else None
    body = node.child_by_field_name("body")
    if declarator.has_error or parameter_list is None or body is None or body.type != "compound_statement":
        raise ValueError("Unsupported LLVMFuzzerTestOneInput definition.")
    parameter_nodes = [n for n in parameter_list.named_children if n.type != "comment"]
    if any(n.type not in {"parameter_declaration", "optional_parameter_declaration"} for n in parameter_nodes) or any(
        n.type == "..." for n in parameter_list.children
    ):
        raise ValueError("Unsupported LLVMFuzzerTestOneInput parameter list.")

    # Keep unnamed parameters in their original positions. Filtering them out
    # would misidentify a remaining length parameter as the data pointer.
    parameters = [_parameter_name_and_shape(n, source_bytes) for n in parameter_nodes]
    if not parameters or parameters == [(None, "void", "")]:
        return DirectInputEntry(body.start_byte + 1, None, None, False, False)
    if len(parameters) != 2:
        raise ValueError("Cannot safely map a reduced parameter list to data and size.")
    data_name, data_type, data_declarator = parameters[0]
    size_name, size_type, _size_declarator = parameters[1]
    return DirectInputEntry(
        insert_pos=body.start_byte + 1,
        data_name=data_name,
        size_name=size_name,
        data_uses_canonical_type=_is_canonical_direct_data_parameter(data_type, data_declarator),
        size_uses_canonical_type=_is_canonical_direct_size_parameter(size_type),
    )


def _inline_direct_input_source(source: str, header_name: str) -> str:
    entry = _find_fuzzer_entry_for_direct_input(source)
    if entry.data_name is None and entry.size_name is None:
        return source
    data_value = (
        "::fuzz_values"
        if entry.data_uses_canonical_type
        else f"reinterpret_cast<decltype({entry.data_name})>(::fuzz_values)"
    )
    size_value = (
        "::fuzz_index"
        if entry.size_uses_canonical_type
        else f"static_cast<decltype({entry.size_name})>(::fuzz_index)"
    )
    assignments = []
    if entry.data_name is not None:
        assignments.append(f"    {entry.data_name} = {data_value};")
    if entry.size_name is not None:
        assignments.append(f"    {entry.size_name} = {size_value};")
    assignment = "\n" + "\n".join(assignments) + "\n"
    # Tree-sitter offsets are UTF-8 byte offsets, not Python string indices.
    source_bytes = source.encode("utf-8")
    transformed = (
        source_bytes[: entry.insert_pos] + assignment.encode("utf-8") + source_bytes[entry.insert_pos :]
    ).decode("utf-8")
    include_line = f'#include "{header_name}"\n'
    if include_line.strip() not in transformed:
        transformed = include_line + transformed
    return transformed


def _inline_direct_input_in_reduced_harness(
    reduced_harness_path: str,
    crash_pattern_symbolize_1: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    start_id: int,
    phase3_mode: str,
    snapshot: bool,
    crash_pattern_symbolize_0: str,
    symbolize: bool = False,
) -> tuple[str, tuple[str, ...]]:
    if not crash_input:
        print(
            "[!] Direct-input inlining requires --crash-input. "
            "Returning the non-inlined reduced harness without final validation."
        )
        return _finalize_fallback_harness(reduced_harness_path, start_id), ()

    crash_input_path = Path(crash_input)
    if not crash_input_path.exists():
        print(
            f"[!] Direct-input inlining could not find crash input {crash_input}. "
            "Returning the non-inlined reduced harness without final validation."
        )
        return _finalize_fallback_harness(reduced_harness_path, start_id), ()

    crash_bytes = crash_input_path.read_bytes()

    def _attempt_direct_inline(
        base_harness_path: str,
        *,
        attempt_label: str,
    ) -> tuple[str, tuple[str, ...]] | None:
        source = Path(base_harness_path).read_text(encoding="utf-8", errors="ignore")
        inline_harness_path = str(Path(base_harness_path).with_suffix(".inline.cpp"))
        header_path = Path(inline_harness_path).with_name(DIRECT_INPUT_HEADER_NAME)
        generated_headers: tuple[str, ...] = ()
        try:
            transformed = _inline_direct_input_source(
                source,
                DIRECT_INPUT_HEADER_NAME,
            )
        except ValueError as exc:
            transformed = source
            print(
                "[!] Input parameters could not be mapped safely; validating without "
                f"direct-input inlining for the {attempt_label} harness: {exc}"
            )
        else:
            if transformed == source:
                print(
                    "[+] No named input parameters remain; validating without "
                    "direct-input inlining."
                )

        if transformed != source:
            header_path.write_text(
                _direct_input_header_source(crash_bytes),
                encoding="utf-8",
            )
            generated_headers = (str(header_path),)
            print(
                f"Inlined direct crash input ({len(crash_bytes)} bytes) into "
                f"{inline_harness_path} using {header_path}"
            )
        Path(inline_harness_path).write_text(transformed, encoding="utf-8")
        _prepend_additional_headers(inline_harness_path)

        validation_log_path = f"{inline_harness_path}.validation.log"
        print(
            "Verifying crash preservation for post-reduction harness: "
            f"{inline_harness_path}"
        )
        if symbolize:
            if crash_pattern_symbolize_1 is None:
                raise ValueError(
                    "--symbolize inline validation requires a symbolize=1 crash pattern."
                )
            crash_preserved = validate_symbolized_crash_pattern_depth_location(
                inline_harness_path,
                crash_pattern_symbolize_1,
                crash_input,
                compile_flags,
                link_flags,
                fdp_trace_file=None,
                phase3_mode=phase3_mode,
                validation_log_path=validation_log_path,
                debug_stage="post_reduction_direct_input_inline",
                retry_oom_without_rss_limit=True,
            )
        else:
            crash_preserved = validate_crash_pattern_and_stack_trace(
                inline_harness_path,
                crash_pattern_symbolize_0,
                crash_pattern_symbolize_1,
                crash_input,
                compile_flags,
                link_flags,
                fdp_trace_file=None,
                phase3_mode=phase3_mode,
                validation_log_path=validation_log_path,
                debug_stage="post_reduction_direct_input_inline",
                retry_oom_without_rss_limit=True,
            )
        if crash_preserved:
            print("[+] Post-reduction validation preserved crash behavior.")
            return inline_harness_path, generated_headers

        print(
            f"[-] Post-reduction validation failed to preserve crash behavior for "
            f"the {attempt_label} harness. Validation log: {validation_log_path}"
        )
        _append_inline_stack_diagnostics(
            validation_log_path,
            before_path=base_harness_path,
            after_path=inline_harness_path,
            crash_pattern=crash_pattern_symbolize_1 or crash_pattern_symbolize_0,
            crash_pattern_symbolize_0=crash_pattern_symbolize_0,
            crash_input=crash_input,
            compile_flags=compile_flags,
            link_flags=link_flags,
            fdp_trace_file=None,
        )
        return None

    direct_result = _attempt_direct_inline(
        reduced_harness_path,
        attempt_label="reduced",
    )
    if direct_result is not None:
        return direct_result

    if snapshot:
        last_interesting_path = get_last_interesting_file()
        if (
            os.path.exists(last_interesting_path)
            and not candidate_files_match(reduced_harness_path, last_interesting_path)
        ):
            print(
                "[!] Retrying direct-input preparation and validation from the last interesting "
                f"snapshot: {last_interesting_path}"
            )
            snapshot_result = _attempt_direct_inline(
                last_interesting_path,
                attempt_label="last interesting snapshot",
            )
            if snapshot_result is not None:
                return snapshot_result
            print(
                "[-] Snapshot post-reduction validation also failed. "
                "Returning the non-inlined last interesting snapshot harness; "
                "this fallback has not passed final validation."
            )
            return _finalize_fallback_harness(last_interesting_path, start_id), ()

    print(
        "[-] Returning the non-inlined reduced harness; "
        "this fallback has not passed final validation."
    )
    return _finalize_fallback_harness(reduced_harness_path, start_id), ()


def inline_literals_in_reduced_harness(
    reduced_harness_path: str,
    fdp_trace_file: str | None,
    crash_pattern_symbolize_1: str | None,
    crash_input: str | None,
    compile_flags: str | None,
    link_flags: str | None,
    start_id: int = 100000,
    phase3_mode: str = PHASE3_DIRECT,
    snapshot: bool = False,
    crash_pattern_symbolize_0: str | None = None,
    symbolize: bool = False,
) -> tuple[str, tuple[str, ...]]:
    fast_crash_pattern = crash_pattern_symbolize_0 or crash_pattern_symbolize_1
    if not fast_crash_pattern:
        raise ValueError("A symbolize=0 crash pattern is required for inline validation.")
    if fdp_trace_file is None:
        return _inline_direct_input_in_reduced_harness(
            reduced_harness_path,
            crash_pattern_symbolize_1,
            crash_input,
            compile_flags,
            link_flags,
            start_id,
            phase3_mode,
            snapshot,
            fast_crash_pattern,
            symbolize,
        )

    def _attempt_inline(base_harness_path: str, *, attempt_label: str) -> tuple[str, tuple[str, ...]] | None:
        source = Path(base_harness_path).read_text(encoding="utf-8", errors="ignore")
        streams = load_trace(Path(fdp_trace_file))
        inline_result = inline_source_with_report(source, streams)
        transformed, count = inline_result.source, inline_result.replaced
        inline_harness_path = str(Path(base_harness_path).with_suffix(".inline.cpp"))
        Path(inline_harness_path).write_text(transformed, encoding="utf-8")

        generated_headers: list[str] = []
        if inline_result.header_source and inline_result.header_name:
            header_path = Path(inline_harness_path).with_name(inline_result.header_name)
            header_path.write_text(inline_result.header_source, encoding="utf-8")
            generated_headers.append(str(header_path))
            details = []
            if inline_result.loop_replaced:
                details.append(f"{inline_result.loop_replaced} repeated")
            if inline_result.large_buffer_replaced:
                details.append(f"{inline_result.large_buffer_replaced} large-buffer")
            detail_text = f" ({', '.join(details)})" if details else ""
            print(
                f"Moved {inline_result.header_replaced} FDP callsites{detail_text} into "
                f"header-backed values: {header_path}"
            )

        _prepend_additional_headers(inline_harness_path)
        print(f"Inlined/replayed {count} FDP calls into {inline_harness_path}")

        unsupported_skips = [
            skip for skip in inline_result.skipped if skip.reason == "unsupported-repeated-trace-id"
        ]
        if unsupported_skips:
            skipped_ids = ", ".join(
                f"{skip.key}({skip.method}, {skip.record_count} records)" for skip in unsupported_skips
            )
            print(
                "[!] Could not header-replay some repeated FDP callsites; "
                f"they remain as FDP calls for validation/replay: {skipped_ids}"
            )

        if count == 0 and inline_result.detected_calls == 0:
            print(
                "[+] No FDP callsites remain; validating the reduced harness "
                "without FDP inlining."
            )
        elif count == 0:
            print(
                "[!] No FDP callsites were replayed, but FDP callsites remain in the "
                "reduced harness; validating crash preservation before accepting it."
            )

        print(f"Verifying crash preservation for post-reduction harness: {inline_harness_path}")
        validation_log_path = f"{inline_harness_path}.validation.log"
        if symbolize:
            if crash_pattern_symbolize_1 is None:
                raise ValueError(
                    "--symbolize inline validation requires a symbolize=1 crash pattern."
                )
            crash_preserved = validate_symbolized_crash_pattern_depth_location(
                inline_harness_path,
                crash_pattern_symbolize_1,
                crash_input,
                compile_flags,
                link_flags,
                fdp_trace_file=fdp_trace_file,
                phase3_mode=phase3_mode,
                validation_log_path=validation_log_path,
                debug_stage="post_reduction_fdp_inline",
                retry_oom_without_rss_limit=True,
            )
        else:
            crash_preserved = validate_crash_pattern_and_stack_trace(
                inline_harness_path,
                fast_crash_pattern,
                crash_pattern_symbolize_1,
                crash_input,
                compile_flags,
                link_flags,
                fdp_trace_file=fdp_trace_file,
                phase3_mode=phase3_mode,
                validation_log_path=validation_log_path,
                debug_stage="post_reduction_fdp_inline",
                retry_oom_without_rss_limit=True,
            )
        if crash_preserved:
            print("[+] Post-reduction validation preserved crash behavior.")
            inline_source_text = Path(inline_harness_path).read_text(encoding="utf-8", errors="ignore")
            cleaned, removed = strip_injected_ids(inline_source_text, start_id=start_id)
            if removed:
                Path(inline_harness_path).write_text(cleaned, encoding="utf-8")
                print(f"Removed {removed} remaining injected FDP IDs from inline harness.")
            return inline_harness_path, tuple(generated_headers)

        print(
            f"[-] Post-reduction validation failed to preserve crash behavior for the {attempt_label} harness. "
            f"Validation log: {validation_log_path}"
        )
        _append_inline_stack_diagnostics(
            validation_log_path,
            before_path=base_harness_path,
            after_path=inline_harness_path,
            crash_pattern=crash_pattern_symbolize_1 or fast_crash_pattern,
            crash_pattern_symbolize_0=fast_crash_pattern,
            crash_input=crash_input,
            compile_flags=compile_flags,
            link_flags=link_flags,
            fdp_trace_file=fdp_trace_file,
        )
        return None

    inline_result = _attempt_inline(reduced_harness_path, attempt_label="reduced")
    if inline_result is not None:
        return inline_result

    if snapshot:
        last_interesting_path = get_last_interesting_file()
        if (
            os.path.exists(last_interesting_path)
            and not candidate_files_match(reduced_harness_path, last_interesting_path)
        ):
            print(
                "[!] Retrying inline reduction from the last interesting snapshot: "
                f"{last_interesting_path}"
            )
            snapshot_inline_result = _attempt_inline(
                last_interesting_path,
                attempt_label="last interesting snapshot",
            )
            if snapshot_inline_result is not None:
                return snapshot_inline_result
            print(
                "[-] Snapshot post-reduction validation also failed. "
                "Returning the non-inlined last interesting snapshot harness; "
                "this fallback has not passed final validation."
            )
            return _finalize_fallback_harness(last_interesting_path, start_id), ()

    print(
        "[-] Returning the non-inlined reduced harness; "
        "this fallback has not passed final validation."
    )
    return _finalize_fallback_harness(reduced_harness_path, start_id), ()


@termination_guard()
def reduce_with_config(config: ReductionConfig) -> ReductionResult:
    validate_tool(config.tool)
    configure_work_dir(config.work_dir)
    if config.debug and config.check:
        raise ValueError("debug and check modes cannot be enabled together.")
    if config.profile and config.check:
        raise ValueError("profile and check modes cannot be enabled together.")
    configure_debug_logging(config.debug)
    if not 1 <= config.jobs <= MAX_TREEREDUCE_JOBS:
        raise ValueError(
            f"jobs must be between 1 and {MAX_TREEREDUCE_JOBS}."
        )
    set_current_exec_timeout_ms(DEFAULT_EXEC_TIMEOUT_MS)
    reset_stack_trace_state()
    reset_last_interesting_state()
    reset_poc_runtime_args()
    reset_check_state()
    if config.statistics:
        from harnessreducer.reducer_runner import reset_statistics_state
        reset_statistics_state()
    validate_phase3_mode(config.phase3_mode)
    if config.amortize_link and config.phase3_mode == PHASE3_DIRECT:
        raise ValueError("--amortize-link requires split or PCH mode; it cannot be used with direct/single-step mode.")
    if config.amortize_link:
        resolve_amortized_link_inputs(config.link_flags)
    if has_static_target_libraries(config.link_flags):
        print("[WARN] Static target libraries were detected. Cannot fully guarantee final crash preservation.")
    validation_phase3_mode = PHASE3_DIRECT
    reduction_phase3_mode = config.phase3_mode
    if config.tool == "treereduce":
        check_tree_reducer()
    else:
        check_perses()
    check_harness_compilation(config.harness_path, config.compile_flags, config.link_flags)
    crash_pattern_kwargs = {}
    if config.symbolize:
        crash_pattern_kwargs["record_symbolized_crash_location"] = True
    try:
        crash_pattern_symbolize_0 = extract_crash_pattern_from_output(
            config.crash_input,
            harness_path=config.harness_path,
            link_flags=config.link_flags,
            **crash_pattern_kwargs,
        )
    except HarnessCrashDetected as exc:
        print(f"[!] Warning: Crash location is inside the harness: {exc.location}")
        print(
            "[*] Harness minimization stopped early because this is a harness "
            "crash, not a library crash."
        )
        return ReductionResult(
            reduced_harness="",
            tagged_harness="",
            fdp_trace="",
            success=False,
        )
    if not crash_pattern_symbolize_0:
        return ReductionResult(
            reduced_harness="",
            tagged_harness="",
            fdp_trace="",
            success=False
        )
    recorded_symbolized_pattern = get_reference_crash_pattern_symbolize_1()
    crash_pattern_symbolize_1 = recorded_symbolized_pattern

    print(f"[+] Extracted symbolize=0 crash pattern: {crash_pattern_symbolize_0}")
    if recorded_symbolized_pattern:
        print(f"[+] Using symbolize=1 crash pattern: {recorded_symbolized_pattern}")
    else:
        print(
            "[!] No separate symbolize=1 crash pattern was recorded; "
            "symbolized stack validations will not require a symbolized crash regex."
        )
    if config.symbolize:
        if crash_pattern_symbolize_1 is None:
            raise ValueError(
                "--symbolize requires an extractable symbolize=1 crash pattern."
            )
        check_reducer_symbolized_reduction_oracle(
            config.harness_path,
            crash_pattern_symbolize_1,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            phase3_mode=validation_phase3_mode,
        )
    else:
        check_reducer_crash_pattern(
            config.harness_path,
            crash_pattern_symbolize_0,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            phase3_mode=validation_phase3_mode,
        )
        check_reducer_symbolized_crash_pattern(
            config.harness_path,
            recorded_symbolized_pattern,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            phase3_mode=validation_phase3_mode,
        )
    if config.check:
        print(
            "[+] Stored reference depths: "
            f"fast(symbolize=0)={get_normal_reference_stack_depth()}, "
            f"symbolized(symbolize=1)={get_symbolized_reference_stack_depth()}"
        )
        reference = record_check_reference(
            config.crash_input,
            recorded_symbolized_pattern or ".*",
            config.link_flags,
        )
        print(
            "[+] Recorded check reference: "
            f"{reference.frame_count} symbolized frame(s), "
            f"{getattr(reference, 'frame_count_symbolize_0', 0)} "
            "unsymbolized frame(s)."
        )
    if config.slice_enabled:
        effective_harness_path = apply_coverage_guided_slice(
            config.harness_path,
            recorded_symbolized_pattern,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            phase3_mode=validation_phase3_mode,
            crash_pattern_symbolize_0=crash_pattern_symbolize_0,
            symbolize=config.symbolize,
        )
    else:
        effective_harness_path = config.harness_path
    tagged_harness = tag_harness_with_fdp_ids(
        effective_harness_path,
        start_id=config.start_id,
        marker=config.marker,
    )
    tagged_harness_file = _tagged_harness_path(tagged_harness)
    fdp_callsite_count = _tagged_harness_fdp_count(tagged_harness)
    fdp_trace_file: str | None = None
    if fdp_callsite_count > 0:
        tagged_harness_bin = compile_dump_mode_harness(
            tagged_harness_file,
            config.compile_flags,
            config.link_flags,
        )
        fdp_trace_file = dump_fdp_trace(
            tagged_harness_bin,
            config.crash_input,
            config.link_flags,
        )
    else:
        print(
            "[+] No FDP callsites detected; using direct crash input during "
            "reduction and direct-input inlining after reduction."
        )
    if config.check:
        reduced_harness = run_treereducer_with_check(
            tagged_harness_file,
            fdp_trace_file,
            recorded_symbolized_pattern,
            config.compile_flags,
            config.link_flags,
            config.crash_input,
            stable=config.stable,
            phase3_mode=reduction_phase3_mode,
            snapshot=config.snapshot,
            amortize_link=config.amortize_link,
            crash_pattern_symbolize_0=crash_pattern_symbolize_0,
            require_crash_pattern=recorded_symbolized_pattern is not None,
            jobs=config.jobs,
            tool=config.tool,
        )
        emit_check_statistics_summary()
    else:
        reduced_harness = run_treereducer(
            tagged_harness_file,
            fdp_trace_file,
            crash_pattern_symbolize_1 if config.symbolize else crash_pattern_symbolize_0,
            config.compile_flags,
            config.link_flags,
            config.crash_input,
            stable=config.stable,
            phase3_mode=reduction_phase3_mode,
            statistics=config.statistics,
            snapshot=config.snapshot,
            amortize_link=config.amortize_link,
            symbolize=config.symbolize,
            jobs=config.jobs,
            profile=config.profile,
            tool=config.tool,
        )
    format_reduced_harness(reduced_harness)
    if config.debug:
        print(
            "[DEBUG] Recording direct post-reduction validation for the "
            "reduced harness."
        )
        if config.symbolize:
            validate_symbolized_crash_pattern_depth_location(
                reduced_harness,
                crash_pattern_symbolize_1,
                config.crash_input,
                config.compile_flags,
                config.link_flags,
                fdp_trace_file=fdp_trace_file,
                phase3_mode=validation_phase3_mode,
                debug_stage="post_reduction_tree_harness_symbolize_1",
                retry_oom_without_rss_limit=True,
            )
        else:
            validate_crash_pattern(
                reduced_harness,
                crash_pattern_symbolize_0,
                config.crash_input,
                config.compile_flags,
                config.link_flags,
                fdp_trace_file=fdp_trace_file,
                phase3_mode=validation_phase3_mode,
                debug_stage="post_reduction_tree_harness_symbolize_0",
                retry_oom_without_rss_limit=True,
            )
            validate_stack_trace(
                reduced_harness,
                crash_pattern_symbolize_1,
                config.crash_input,
                config.compile_flags,
                config.link_flags,
                fdp_trace_file=fdp_trace_file,
                phase3_mode=validation_phase3_mode,
                require_crash_pattern=crash_pattern_symbolize_1 is not None,
                debug_stage="post_reduction_tree_harness_symbolize_1",
                retry_oom_without_rss_limit=True,
            )
    reset_poc_runtime_args()
    post_inline_harness, generated_headers = inline_literals_in_reduced_harness(
        reduced_harness,
        fdp_trace_file,
        recorded_symbolized_pattern,
        config.crash_input,
        config.compile_flags,
        config.link_flags,
        config.start_id,
        phase3_mode=validation_phase3_mode,
        snapshot=config.snapshot,
        crash_pattern_symbolize_0=crash_pattern_symbolize_0,
        symbolize=config.symbolize,
    )

    if config.use_llm:
        from harnessreducer.llm_reducer import apply_llm_reduction
        final_harness = apply_llm_reduction(
            post_inline_harness,
            crash_pattern_symbolize_1 if config.symbolize else crash_pattern_symbolize_0,
            config.crash_input,
            config.compile_flags,
            config.link_flags,
            fdp_trace_file,
            phase3_mode=validation_phase3_mode,
            symbolize=config.symbolize,
        )
    else:
        final_harness = post_inline_harness

    return ReductionResult(
        reduced_harness=final_harness,
        tagged_harness=tagged_harness_file,
        fdp_trace=fdp_trace_file,
        generated_headers=generated_headers,
        poc_runtime_args=get_poc_runtime_args(),
        success=True
    )


def process(
    harness_path: str,
    compile_flags: str | None = None,
    crash_input: str | None = None,
    link_flags: str | None = None,
    work_dir: str | None = None,
    use_llm: bool = False,
    phase3_mode: str = PHASE3_SPLIT,
    statistics: bool = False,
    slice_enabled: bool = False,
    check: bool = False,
    debug: bool = False,
    snapshot: bool = False,
    amortize_link: bool = False,
    symbolize: bool = False,
    jobs: int = DEFAULT_TREEREDUCE_JOBS,
    profile: bool = False,
    tool: str = "treereduce",
) -> str | None:
    config = ReductionConfig(
        harness_path=harness_path,
        compile_flags=compile_flags,
        link_flags=link_flags,
        crash_input=crash_input,
        work_dir=work_dir,
        use_llm=use_llm,
        phase3_mode=phase3_mode,
        amortize_link=amortize_link,
        statistics=statistics,
        slice_enabled=slice_enabled,
        check=check,
        debug=debug,
        snapshot=snapshot,
        symbolize=symbolize,
        jobs=jobs,
        profile=profile,
        tool=tool,
    )
    result = reduce_with_config(config)
    return result.reduced_harness if result.success else None
