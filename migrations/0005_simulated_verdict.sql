-- 0005 — a simulated gate is not a passing gate.
--
-- Without a GitHub App (local runs, the e2e script, a fresh deploy before the App is installed)
-- the repo-side gates cannot run at all. The worker still has to record something, and until now
-- it recorded `pass`, with the word "simulated" buried in the detail text. Every consumer that
-- reads the verdict column — the API, the evidence page, anything counting green checks — then
-- sees a clean pass for tests that never executed.
--
-- That is the one lie the pipeline cannot afford. The project's claim is that nothing reaches
-- main without the gates proving it, and a row saying `pass` for a test run that did not happen
-- makes that claim unverifiable from the data. A separate verdict makes it impossible to confuse
-- the two by accident: code that wants real passes must now name `simulated` to include it, and
-- the evidence page can label it in red rather than having to parse prose.

ALTER TABLE gate_results DROP CONSTRAINT IF EXISTS gate_results_verdict_check;
ALTER TABLE gate_results ADD CONSTRAINT gate_results_verdict_check CHECK (
    verdict IN ('pass', 'warn', 'block', 'pending', 'simulated')
);

-- Rewrite the history too, so nothing in the table still claims a pass it never earned. These
-- rows are identifiable beyond doubt: head_sha is the literal 'simulated', which no real commit
-- can be. gate_results is append-only by trigger (0003), so this runs with the trigger disabled
-- for the length of the statement: correcting a verdict that was never true is not the kind of
-- rewriting the trigger exists to prevent, and leaving the lie in place would be worse.
ALTER TABLE gate_results DISABLE TRIGGER gate_results_append_only;
UPDATE gate_results SET verdict = 'simulated'
 WHERE head_sha = 'simulated' AND verdict = 'pass';
ALTER TABLE gate_results ENABLE TRIGGER gate_results_append_only;
