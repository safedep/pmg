# Steps to introduce a new Package Manager

Use this checklist to add a new package manager ecosystem (e.g., npm or PyPI). Keep changes consistent with existing patterns.

1. Create a new CLI command
   - Add a new cmd in `cmd/` (e.g., `cmd/npm/` or `cmd/pypi/`).
   - Follow existing command patterns for the chosen ecosystem.
   - Wire flags, args, and output format similarly to other cmds.

2. Define Package Manager config
   - Introduce config logic in `packagemanager/npm/` or `packagemanager/pypi/` depending on the ecosystem.
   - Keep interfaces and structs consistent with other managers.

3. Implement or update the parser
   - For npm: update the existing parser to support the new manager specifics.
   - For PyPI: define a new parser as needed.
   - Ensure it extracts all the required information & matches other parser's structure.

4. Add parser tests
   - Create unit tests for the new parser covering:
     - Single dependency
     - Multiple dependencies
     - Edge cases (e.g., missing fields, malformed entries)

5. Create an extractor
   - In `extractor/`, add an extractor for the new ecosystem under `extractor/npm` or `extractor/pypi`.
   - Update the `NewExtractorManager` to include the newly introduced `PackageManagerExtractor`.
   - Update `getExtractorForFile` to recognize and support the ecosystem’s manifests/lockfiles.

6. Register alias
   - In `internal/alias/alias.go`, add the new package manager’s alias to `DefaultConfig.packageManagers`.
   - Verify default alias and invocation match conventions.

7. Add analytics
   - Define a new analytics event similar to existing ones.
   - Implement a `Track` function for the event.
   - Invoke tracking in the new package manager cmd.

8. Update documentation
   - Update the README to list the new supported package manager.
   - Add usage examples consistent with existing examples.

9. Add e2e workflow
   - In `.github/workflows/pmg-e2e.yml`, add an e2e job for the new manager.
   - Mirror structure and steps used by other ecosystems.

10. Verify end-to-end behavior
    - Test the CLI locally for:
      - Single package installation
      - Multiple package installation
      - Suspicious package handling
      - Malicious package blocking
      - Manifests/lockfiles installation flow
      - `pmg setup install` to verify alias is set and works

11. Consistency pass
    - Confirm naming, errors, logs, and UX align with existing ecosystems.
    - Ensure code follows project patterns and is covered by tests.
