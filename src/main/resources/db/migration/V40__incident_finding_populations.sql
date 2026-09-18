-- Incident lifecycle alignment with EDR-Q1 finding populations.
-- Candidate-only groups remain correlation containers but are no longer operator-actionable OPEN incidents.

-- Retained findings that are already resolved/suppressed must not remain incident members.
DELETE FROM incident_findings m
USING findings f
WHERE m.finding_id=f.finding_id
  AND upper(COALESCE(f.status,'')) NOT IN ('ACTIVE','CANDIDATE');

DELETE FROM incidents i
WHERE NOT EXISTS (
    SELECT 1 FROM incident_findings m WHERE m.incident_id=i.incident_id
);

ALTER TABLE incidents
    ADD COLUMN population text NOT NULL DEFAULT 'CANDIDATE_ONLY';

ALTER TABLE incidents
    ADD CONSTRAINT incidents_population_values
    CHECK (population IN ('CURRENT_ACTIONABLE','ACTIVE_HISTORICAL','CANDIDATE_ONLY'));

WITH classified AS (
    SELECT i.incident_id,
           CASE
             WHEN count(*) FILTER (
                      WHERE upper(COALESCE(f.status,''))='ACTIVE'
                        AND f.last_seen >= now() - interval '24 hours') > 0
               THEN 'CURRENT_ACTIONABLE'
             WHEN count(*) FILTER (
                      WHERE upper(COALESCE(f.status,''))='ACTIVE') > 0
               THEN 'ACTIVE_HISTORICAL'
             ELSE 'CANDIDATE_ONLY'
           END AS population
      FROM incidents i
      JOIN incident_findings m ON m.incident_id=i.incident_id
      JOIN findings f ON f.finding_id=m.finding_id
     WHERE upper(COALESCE(f.status,'')) IN ('ACTIVE','CANDIDATE')
     GROUP BY i.incident_id
)
UPDATE incidents i
   SET population=c.population,
       status=CASE WHEN c.population='CURRENT_ACTIONABLE' THEN 'OPEN' ELSE 'CLOSED' END,
       updated_at=now()
  FROM classified c
 WHERE c.incident_id=i.incident_id;

CREATE INDEX incidents_population_last_seen_idx
    ON incidents(population,last_seen DESC);
