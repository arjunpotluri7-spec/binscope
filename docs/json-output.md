# JSON output (schema version 1)

`binscope inspect --format json` writes one document. Field order is stable, numbers are
plain integers (offsets, sizes, addresses) or fixed-point decimals with three digits
(entropy). `schema_version` changes only when a field is removed or changes meaning;
new fields may be added within a version.

```text
{
  schema_version: 1
  tool:     { name: "binscope", version: "0.1.0" }
  files: [
    {
      path:       string               as given on the command line
      error:      string | null        set when the file could not be read or recognised
      container:  "elf" | "macho" | "macho-fat" | "pe" | ""   ("" when error is set)
      size:       integer              bytes
      entropy:    number               whole-file Shannon entropy, bits per byte
      score:      integer              highest target score (0-100)
      label:      "low" | "moderate" | "high" | "very high"
      targets: [                       one per image; a universal file has one per slice
        {
          format, format_name, arch, bits, endian ("little"|"big"), file_type,
          slice_offset: integer        offset of this image in the file (0 for thin files)
          size, entropy,
          entry:      integer | null   virtual address (RVA for PE)
          hardening:  [ { key, label, enabled: true|false|null, detail } ]
                      keys: ELF pie, nx_stack, relro, bind_now
                            Mach-O pie, nx_stack, no_heap_exec, code_signature
                            PE aslr, high_entropy_va, dep, cfg, certificate
                      null means "not applicable to this file type"
          properties: { key: string | integer | boolean }   format-specific facts, e.g.
                      interpreter, build_id, runpath, relro, symtab_symbols (ELF);
                      uuid, min_os, entryoff, cryptid, dylinker (Mach-O);
                      timestamp, timestamp_utc, image_base, subsystem, overlay_bytes (PE)
          segments, sections: [
            { name, kind ("segment"|"section"), type, offset, file_size, vaddr, mem_size,
              flags, readable, writable, executable, has_file_data, past_eof,
              entropy, entropy_bytes }
          ]                            region offsets are relative to slice_offset
          libraries:  [ { name, functions: [string] } ]
          unbound_imports: [string]    imported symbols not tied to a library (ELF)
          import_count: integer
          rpaths:     [string]         DT_RPATH/DT_RUNPATH entries or LC_RPATH paths
          issues:     [ { kind: "malformed"|"out_of_bounds"|"limit", message, offset } ]
          findings: [
            { id, severity ("info"|"low"|"medium"|"high"), title, summary, explanation,
              points, evidence: [ { location, offset: integer|null, detail } ] }
          ]                            evidence offsets are whole-file offsets
          score: { total, raw, label, factors: [ { id, points, summary } ] }
        }
      ]
    }
  ]
  summary: { files, errors, findings_by_severity: { high, medium, low, info } }
}
```

`binscope diff --format json` writes a separate document:

```text
{
  schema_version: 1, tool, old, new, entropy_delta, fail_on, regression: boolean,
  architectures_removed: [string], architectures_added: [string],
  targets: [
    { arch, format_name, score_before, score_after,
      hardening_removed, hardening_added, libraries_added, libraries_removed,
      imports_added, imports_removed,       "library!function" or a bare symbol name
      sections_added, sections_removed,
      entropy_changes: [ { region, before, after } ],
      findings_new: [ { id, severity, points, summary } ],
      findings_resolved: [string] }
  ]
}
```

SARIF output (`--format sarif`) follows SARIF 2.1.0: one run, every rule in
`tool.driver.rules`, one result per finding with `ruleId`, `ruleIndex`, `level`
(high = error, medium = warning, low/info = note), the artifact URI and, when known, a
`region.byteOffset`. Files that could not be analysed appear as
`invocations[0].toolExecutionNotifications`.
