-- MS5.2 false-positive guard. Expected privilege brokers are retained as
-- evidence/protocol messages but are not active security findings.

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
        NEW.status := 'SUPPRESSED';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS findings_expected_process_elevation_guard ON findings;
CREATE TRIGGER findings_expected_process_elevation_guard
BEFORE INSERT OR UPDATE OF subject_type,rule_id,changes,status ON findings
FOR EACH ROW
EXECUTE FUNCTION neta_suppress_expected_process_elevation();

-- Clean up already-ingested benign privilege-broker findings so deployment of
-- this migration immediately removes them from active finding/incident views.
UPDATE findings f
SET status='SUPPRESSED'
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

DELETE FROM incident_findings m
USING findings f
WHERE m.finding_id=f.finding_id
  AND f.status='SUPPRESSED';

DELETE FROM incidents i
WHERE NOT EXISTS (
    SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id
);
