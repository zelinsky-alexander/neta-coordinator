from __future__ import annotations

import importlib.util
import pathlib
import sqlite3
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).parent / "remote/collect-agent-lab-evidence.py"
SPEC = importlib.util.spec_from_file_location("collect_agent_lab_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AgentLabEvidenceDiagnosticsTest(unittest.TestCase):
    def test_preserves_retransmission_resolver_tls_and_verdict_diagnostics(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".sqlite") as temporary:
            database = sqlite3.connect(temporary.name)
            database.row_factory = sqlite3.Row
            database.executescript("""
                CREATE TABLE processes(id INTEGER PRIMARY KEY,comm TEXT,executable_path TEXT);
                CREATE TABLE connections(
                  id INTEGER PRIMARY KEY,process_id INTEGER,target_host TEXT,local_ip TEXT,
                  local_port INTEGER,remote_ip TEXT,remote_port INTEGER,direction TEXT,
                  lifecycle_state TEXT,first_seen_ns INTEGER,last_seen_ns INTEGER,
                  performance_state TEXT,trust_state TEXT);
                CREATE TABLE transport_samples(
                  connection_id INTEGER,rtt_us INTEGER,rttvar_us INTEGER,total_retrans INTEGER);
                CREATE TABLE connection_transfer_evidence(
                  connection_id INTEGER,observed_ns INTEGER,bytes_sent INTEGER,
                  bytes_received INTEGER,source TEXT,fidelity TEXT);
                CREATE TABLE connection_name_resolution_evidence(
                  id INTEGER PRIMARY KEY,connection_id INTEGER,query_name TEXT,result_code INTEGER,
                  source TEXT,observation_fidelity TEXT,correlation_fidelity TEXT,relation TEXT,
                  completed_ns INTEGER);
                CREATE TABLE connection_name_resolution_addresses(
                  evidence_id INTEGER,address TEXT);
                CREATE TABLE connection_tls_session_evidence(
                  connection_id INTEGER,local_role TEXT,relation TEXT,source TEXT,
                  observation_fidelity TEXT,correlation_fidelity TEXT,tls_version TEXT,sni TEXT,
                  expected_peer_name TEXT,matched_peer_name TEXT,peer_authenticated INTEGER,
                  verify_result INTEGER,spki_sha256 TEXT,issuer TEXT,observed_ns INTEGER);
                CREATE TABLE verdicts(
                  connection_id INTEGER,performance_state TEXT,trust_state TEXT,
                  performance_hypothesis TEXT,trust_hypothesis TEXT,rule_confidence REAL,
                  rule_set_version TEXT,rule_set_hash TEXT,baseline_hash TEXT,input_hash TEXT);
                INSERT INTO processes VALUES(1,'loss-client','/usr/bin/python3');
                INSERT INTO connections VALUES(
                  80,1,'','10.203.0.1',41000,'10.203.0.2',18450,'OUTBOUND','CLOSED',1,10,
                  'DEGRADED','UNVERIFIED');
                INSERT INTO transport_samples VALUES(80,1000,100,0);
                INSERT INTO transport_samples VALUES(80,4000,800,7);
                INSERT INTO connection_transfer_evidence VALUES(80,9,33554432,128,'linux:tcp-info','EXACT');
                INSERT INTO connection_name_resolution_evidence VALUES(
                  1,80,'neta-lab.local',0,'glibc:getaddrinfo','EXACT','STRONGLY_CORRELATED',
                  'RESOLVED_ADDRESS_FOR_OUTBOUND_CONNECTION',2);
                INSERT INTO connection_name_resolution_addresses VALUES(1,'10.203.0.2');
                INSERT INTO connection_tls_session_evidence VALUES(
                  80,'CLIENT','OUTBOUND_SERVER_IDENTITY','openssl3:application-shim',
                  'EXACT','EXACT','TLSv1.3','neta-lab.local','neta-lab.local','neta-lab.local',
                  1,0,'spki-a','lab-ca',3);
                INSERT INTO verdicts VALUES(
                  80,'DEGRADED','UNVERIFIED','NETWORK_PATH_DEGRADATION','',0.9,
                  'central-8','sha256:rules','sha256:baseline','sha256:input');
            """)
            rows = MODULE.rows_for_port(database, 18450)
            diagnostics = MODULE.connection_diagnostics(database, rows)
            self.assertEqual(2, diagnostics["transport"][0]["sample_count"])
            self.assertEqual(2, diagnostics["transport"][0]["nonzero_rtt_samples"])
            self.assertEqual(7, diagnostics["transport"][0]["retransmission_delta"])
            self.assertEqual("10.203.0.2", diagnostics["resolver"][0]["addresses"])
            self.assertEqual("EXACT", diagnostics["tls"][0]["correlation_fidelity"])
            self.assertEqual("DEGRADED", diagnostics["verdicts"][0]["performance_state"])
            database.close()


if __name__ == "__main__":
    unittest.main()
