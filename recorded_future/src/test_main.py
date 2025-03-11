import json
from copy import deepcopy
from datetime import datetime

import pytest
from models import DefaultRiskList, Times, _GlobalTimeHolder
from time_helper import rel_time_to_date

REL_TIME = '2025-01-10T12:20:30Z'
MOCK_RISKLIST_ENTRY = {
    'Name': 'test.com',
    'Risk': '99',
    'RiskString': '10/52',
    'EvidenceDetails': '{"EvidenceDetails": [{"Name": "dhsAis", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported by DHS AIS", "SourcesCount": 1.0, "Sources": ["source:UZNze8"], "Timestamp": "2021-02-03T21:32:08.000Z", "SightingsCount": 2.0, "Criticality": 1.0}, {"Name": "defanged", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported as a Defanged DNS Name", "SourcesCount": 93.0, "Sources":["source:uM1P9p","source:Vj7fE4"], "Timestamp": "2020-12-17T19:38:55.000Z", "SightingsCount": 311.0, "Criticality": 1.0}, {"Name": "analystNote", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported by Insikt Group", "SourcesCount": 1.0, "Sources": ["source:VKz42X"], "Timestamp": "2020-12-22T00:00:00.000Z", "SightingsCount": 3.0, "Criticality": 1.0}, {"Name": "relatedNote", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Referenced by Insikt Group", "SourcesCount": 1.0, "Sources": ["source:VKz42X"], "Timestamp": "2021-06-29T00:00:00.000Z", "SightingsCount": 6.0, "Criticality": 1.0}, {"Name": "observedTelemetry", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Observed in the Wild by Recorded Future Telemetry", "SourcesCount": 1.0, "Sources": ["report:oJewMx"], "Timestamp": "2025-01-13T03:04:14.751Z", "SightingsCount": 4.0, "Criticality": 1.0}, {"Name": "historicalThreatListMembership", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported in Threat List", "SourcesCount": 3.0, "Sources": ["report:QhR8Qs", "report:Tluf00", "report:oJewMx"], "Timestamp": "2025-01-13T03:04:14.938Z", "SightingsCount": -1.0, "Criticality": 1.0}, {"Name": "resolvedUnusualIp", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Recently Resolved to Unusual IP", "SourcesCount": 1.0, "Sources": ["Recorded Future DNS Resolution"], "Timestamp": "2025-01-13T03:04:14.981Z", "SightingsCount": -1.0, "Criticality": 1.0}, {"Name": "resolvedSuspiciousIp", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Recently Resolved to Suspicious IP", "SourcesCount": 1.0, "Sources": ["Recorded Future DNS Resolution"], "Timestamp": "2025-01-13T03:04:14.981Z", "SightingsCount": -1.0, "Criticality": 1.0}, {"Name": "resolvedMaliciousIp", "EvidenceString": "abc", "CriticalityLabel": "Suspicious", "MitigationString": "", "Rule": "Recently Resolved to Malicious IP", "SourcesCount": 1.0, "Sources": ["Recorded Future DNS Resolution"], "Timestamp": "2025-01-13T03:04:14.981Z", "SightingsCount": -1.0, "Criticality": 2.0}, {"Name": "recentCncSite", "EvidenceString": "abc", "CriticalityLabel": "Very Malicious", "MitigationString": "", "Rule": "Recent C&C DNS Name", "SourcesCount": 1.0, "Sources": ["report:QhR8Qs"], "Timestamp": "2025-01-13T03:04:14.750Z", "SightingsCount": 1.0, "Criticality": 4.0}]}',  # noqa: E501
}


MOCK_EVIDENCE_MINIMIZED_RISKLIST = {
    'EvidenceString': '',
    'CriticalityLabel': '',
    'Timestamp': '',
    'Name': '',
}


MOCK_FULL_RISKLIST_ENTRY = {
    'Name': 'test.com',
    'Risk': '99',
    'RiskString': '10/52',
    'EvidenceDetails': '{"EvidenceDetails": [{"Name": "suspectedCnc", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historical Suspected C&C Server", "SourcesCount": 3.0, "Sources": ["source:UZNze8", "source:sIoEOQ", "source:qs_-cU"], "Timestamp": "2023-12-27T23:58:00.000Z", "SightingsCount": 65.0, "Criticality": 1.0}, {"Name": "maliciousInfrastructureAdminServer", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historical Malicious Infrastructure Admin Server", "SourcesCount": 2.0, "Sources": ["source:uR8gML", "source:uCr47M"], "Timestamp": "2024-12-30T10:05:04.094Z", "SightingsCount": 1510.0, "Criticality": 1.0}, {"Name": "dhsAis", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported by DHS AIS", "SourcesCount": 1.0, "Sources": ["source:UZNze8"], "Timestamp": "2024-07-01T12:00:48.170Z", "SightingsCount": 15.0, "Criticality": 1.0}, {"Name": "phishingHost", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historical Phishing Host", "SourcesCount": 2.0, "Sources": ["source:uCr47a", "source:NKaUXl"], "Timestamp": "2025-01-06T13:06:01.567Z", "SightingsCount": 1084.0, "Criticality": 1.0}, {"Name": "historicalThreatListMembership", "EvidenceString": "abc", "CriticalityLabel": "Unusual", "MitigationString": "", "Rule": "Historically Reported in Threat List", "SourcesCount": 2.0, "Sources": ["report:oJewMx", "report:POW5Yc"], "Timestamp": "2025-01-13T14:18:46.073Z", "SightingsCount": -1.0, "Criticality": 1.0}, {"Name": "reportedCnc", "EvidenceString": "abc", "CriticalityLabel": "Suspicious", "MitigationString": "", "Rule": "Historically Reported C&C Server", "SourcesCount": 2.0, "Sources": ["source:b5tNVA", "source:qU_q-9"], "Timestamp": "2023-06-06T08:22:03.753Z", "SightingsCount": 23.0, "Criticality": 2.0}, {"Name": "recentPhishingHost", "EvidenceString": "abc", "CriticalityLabel": "Suspicious", "MitigationString": "", "Rule": "Recent Phishing Host", "SourcesCount": 1.0, "Sources": ["source:uCr47a"], "Timestamp": "2025-01-13T12:07:50.896Z", "SightingsCount": 31.0, "Criticality": 2.0}, {"Name": "validatedCnc", "EvidenceString": "abc", "CriticalityLabel": "Suspicious", "MitigationString": "", "Rule": "Previously Validated C&C Server", "SourcesCount": 1.0, "Sources": ["source:qGriFQ"], "Timestamp": "2025-01-11T04:31:33.000Z", "SightingsCount": 1786.0, "Criticality": 2.0}, {"Name": "recentMaliciousInfrastructureAdminServer", "EvidenceString": "abc", "CriticalityLabel": "Malicious", "MitigationString": "", "Rule": "Recent Malicious Infrastructure Admin Server", "SourcesCount": 1.0, "Sources": ["source:uR8gML"], "Timestamp": "2025-01-13T13:06:26.594Z", "SightingsCount": 127.0, "Criticality": 3.0}, {"Name": "recentReportedCnc", "EvidenceString": "abc", "CriticalityLabel": "Malicious", "MitigationString": "", "Rule": "Recently Reported C&C Server", "SourcesCount": 1.0, "Sources": ["report:POW5Yc"], "Timestamp": "2025-01-13T14:18:45.865Z", "SightingsCount": 1.0, "Criticality": 3.0}, {"Name": "recentValidatedCnc", "EvidenceString": "abc", "CriticalityLabel": "Very Malicious", "MitigationString": "", "Rule": "Validated C&C Server", "SourcesCount": 1.0, "Sources": ["source:qGriFQ"], "Timestamp": "2025-01-13T06:05:27.000Z", "SightingsCount": 11.0, "Criticality": 4.0}]}',  # noqa: E501
}

ingest_start = f'{datetime.now().isoformat(timespec="seconds")}Z'
ingest_end = rel_time_to_date('1d', ingest_start)
ingest_end = rel_time_to_date('1h', ingest_end)
_GlobalTimeHolder.set_ingestion_times(ingest_start, ingest_end)


class TestModels:
    def test_times_iso_format_dates(self):
        times = Times()
        assert times.start_time
        assert times.end_time
        assert times.start_time.endswith('Z')
        assert times.end_time.endswith('Z')
        assert rel_time_to_date('1h', rel_time_to_date('1d', times.start_time)) == times.end_time

    def test_timestamp_present_in_model(self):
        entry = DefaultRiskList(**MOCK_RISKLIST_ENTRY)
        assert isinstance(entry.timestamps, Times)
        assert entry.timestamps.start_time
        assert entry.timestamps.end_time

    def test_model_renaming(self):
        entry = DefaultRiskList(**MOCK_RISKLIST_ENTRY).model_dump(by_alias=True, exclude_none=True)
        must_be_present = ('Value', 'Risk', 'Details', 'RiskRules', 'Timestamps')
        assert all(entry[k] is not None for k in must_be_present)
        assert entry['Details']['EvidenceDetails']

    @pytest.mark.parametrize(
        ('evidence', 'expected'),
        [
            ([{'Rule': 'RiskRule1', 'Criticality': 5}], 'RiskRule1'),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 5}, {'Rule': 'RiskRule2', 'Criticality': 5}],
                'RiskRule1 | RiskRule2',
            ),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 5}, {'Rule': 'RiskRule2', 'Criticality': 4}],
                'RiskRule1 | RiskRule2',
            ),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 5}, {'Rule': 'RiskRule2', 'Criticality': 3}],
                'RiskRule1 | RiskRule2',
            ),
            (
                [
                    {'Rule': 'RiskRule1', 'Criticality': 5},
                    {'Rule': 'RiskRule2', 'Criticality': 3},
                    {'Rule': 'RiskRule3', 'Criticality': 3},
                ],
                'RiskRule1 | RiskRule2 | RiskRule3',
            ),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 5}, {'Rule': 'RiskRule2', 'Criticality': 1}],
                'RiskRule1',
            ),
        ],
    )
    def test_riskrules_with_high_score_risks(self, evidence, expected):
        data = deepcopy(MOCK_RISKLIST_ENTRY)
        [d.update(MOCK_EVIDENCE_MINIMIZED_RISKLIST) for d in evidence]
        data['EvidenceDetails'] = json.dumps({'EvidenceDetails': evidence})
        entry = DefaultRiskList.model_validate(data)
        assert entry.risk_rules == expected

    @pytest.mark.parametrize(
        ('evidence', 'expected'),
        [
            ([{'Rule': 'RiskRule1', 'Criticality': 2}], 'RiskRule1'),
            ([{'Rule': 'RiskRule1', 'Criticality': 3}], 'RiskRule1'),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 2}, {'Rule': 'RiskRule2', 'Criticality': 2}],
                'RiskRule1 | RiskRule2',
            ),
            (
                [
                    {'Rule': 'RiskRule1', 'Criticality': 2},
                    {'Rule': 'RiskRule2', 'Criticality': 2},
                    {'Rule': 'RiskRule3', 'Criticality': 1},
                ],
                'RiskRule1 | RiskRule2',
            ),
            (
                [{'Rule': 'RiskRule1', 'Criticality': 2}, {'Rule': 'RiskRule2', 'Criticality': 1}],
                'RiskRule1',
            ),
        ],
    )
    def test_riskrules_with_low_score_risks(self, evidence, expected):
        data = deepcopy(MOCK_RISKLIST_ENTRY)
        [d.update(MOCK_EVIDENCE_MINIMIZED_RISKLIST) for d in evidence]
        data['EvidenceDetails'] = json.dumps({'EvidenceDetails': evidence})
        entry = DefaultRiskList.model_validate(data)
        assert entry.risk_rules == expected

    def test_full_risklist(self):
        assert DefaultRiskList.model_validate(MOCK_FULL_RISKLIST_ENTRY)


class TestTime:
    @pytest.mark.parametrize(
        ('skew', 'expected'),
        [
            ('1h', '2025-01-10T13:20:30Z'),
            ('2h', '2025-01-10T14:20:30Z'),
            ('4h', '2025-01-10T16:20:30Z'),
            ('8h', '2025-01-10T20:20:30Z'),
            ('12h', '2025-01-11T00:20:30Z'),
            ('24h', '2025-01-11T12:20:30Z'),
        ],
    )
    def test_time_skew_hours(self, skew, expected):
        date = rel_time_to_date(skew, REL_TIME)
        assert date == expected

    @pytest.mark.parametrize(
        ('skew', 'expected'),
        [
            ('1d', '2025-01-11T12:20:30Z'),
            ('2d', '2025-01-12T12:20:30Z'),
            ('4d', '2025-01-14T12:20:30Z'),
            ('8d', '2025-01-18T12:20:30Z'),
            ('12d', '2025-01-22T12:20:30Z'),
            ('24d', '2025-02-03T12:20:30Z'),
        ],
    )
    def test_time_skew_days(self, skew, expected):
        date = rel_time_to_date(skew, REL_TIME)
        assert date == expected

    def test_time_raises_ValueError(self):
        with pytest.raises(ValueError, match='Invalid relative time'):
            rel_time_to_date('2m', '2025-01-10T12:20:30Z')
