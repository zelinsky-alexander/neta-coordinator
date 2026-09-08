-- MS5.2 false-positive guard. Expected privilege-broker transitions remain in
-- the agent's local evidence. Older agents may still announce them, so the
-- coordinator accepts/audits the protocol message but suppresses creation of a
-- coordinator finding row.

CREATE OR REPLACE FUNCTION neta_suppress_expected_process_elevation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF upper(COALESCE(NEW.subject_type,'')) = 'PROCESS'
       AND NEW.rule_id = 'PROCESS_UNEXPECTED_ELEVATION'
       AND EXISTS (
           SELECT 1
           FROM jsonb_array_elements_text(COALESCE(NEW.changes,'[]'::jsonb)) AS change(value)
           WHERE lower(change.value) IN (
               'parent image: /usr/bin/sudo',
               'parent image: /bin/su',
               'parent image: /usr/bin/su',
               'parent image: /usr/bin/pkexec',
               'parent image: /usr/local/bin/doas',
               'parent image: /usr/bin/doas'
           )
           OR lower(change.value) LIKE 'parent image: %/consent.exe'
       )
    THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS findings_expected_process_elevation_guard ON findings;
CREATE TRIGGER findings_expected_process_elevation_guard
BEFORE INSERT ON findings
FOR EACH ROW
EXECUTE FUNCTION neta_suppress_expected_process_elevation();

-- Remove already-ingested benign broker transitions. Their signed protocol
-- messages remain in protocol_messages/audit history and the originating agent
-- retains the local SUPPRESSED process finding.
DELETE FROM findings f
WHERE upper(COALESCE(f.subject_type,''))='PROCESS'
  AND f.rule_id='PROCESS_UNEXPECTED_ELEVATION'
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(COALESCE(f.changes,'[]'::jsonb)) AS change(value)
      WHERE lower(change.value) IN (
          'parent image: /usr/bin/sudo',
          'parent image: /bin/su',
          'parent image: /usr/bin/su',
          'parent image: /usr/bin/pkexec',
          'parent image: /usr/local/bin/doas',
          'parent image: /usr/bin/doas'
      )
      OR lower(change.value) LIKE 'parent image: %/consent.exe'
  );

DELETE FROM incidents i
WHERE NOT EXISTS (
    SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id
);
