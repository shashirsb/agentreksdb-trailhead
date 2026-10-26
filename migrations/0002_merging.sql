-- A governor's merge decision is recorded first; the merge itself happens once GitHub's required checks
-- (including train-gate, which re-runs after the decision labels are added) are green.
ALTER TABLE intents DROP CONSTRAINT status_ok;
ALTER TABLE intents ADD CONSTRAINT status_ok CHECK (status IN ('draft','submitted','guardrails','held','generating','gates',
                                                              'review','merging','flagged','merged','on_hold','rejected'));
