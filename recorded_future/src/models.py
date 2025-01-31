import json
from datetime import datetime
from typing import Optional

from psengine.common_models import RFBaseModel
from pydantic import Field, field_validator, model_validator


class _GlobalTimeHolder:
    """Singleton for saving start and end time of IOCs, redefined at every new risklist ingested."""

    start_time: str | None = None
    end_time: str | None = None

    @classmethod
    def set_ingestion_times(cls, start: str, end: str) -> None:
        cls.start_time = start
        cls.end_time = end

    @classmethod
    def get_start_time(cls) -> str:
        return cls.start_time

    @classmethod
    def get_end_time(cls) -> str:
        return cls.end_time


class Times(RFBaseModel):
    """Times Model"""

    start_time: str = Field(default_factory=_GlobalTimeHolder.get_start_time, alias='StartTime')
    end_time: str = Field(default_factory=_GlobalTimeHolder.get_end_time, alias='EndTime')


class EvidenceDetail(RFBaseModel):
    """EvidenceDetail Model"""

    name: Optional[str] = Field(default=None, alias='Name')
    evidence_string: str = Field(alias='EvidenceString')
    criticality_label: str = Field(alias='CriticalityLabel')
    mitigation_string: Optional[str] = Field(default=None, alias='MitigationString')
    criticality: int = Field(alias='Criticality')
    rule: str = Field(alias='Rule')
    timestamp: datetime | str = Field(alias='Timestamp')


class Details(RFBaseModel):
    """Details Model"""

    evidence_details: list[EvidenceDetail] = Field(alias='EvidenceDetails')


class DefaultRiskList(RFBaseModel):
    """Model used for formatting each risklsit's row."""

    ioc: str = Field(validation_alias='Name', serialization_alias='Value')
    algorithm: Optional[str] = Field(alias='Algorithm', default=None)
    risk_score: int = Field(alias='Risk')
    risk_string: str = Field(alias='RiskString')
    evidence_details: list[EvidenceDetail] | Details = Field(
        validation_alias='EvidenceDetails', serialization_alias='Details'
    )
    timestamps: Times = Field(default_factory=Times, alias='Timestamps')
    risk_rules: Optional[str] = Field(default=None, alias='RiskRules')

    @field_validator('evidence_details', mode='before')
    @classmethod
    def evidence_to_dict(cls, v):
        """Dump the EvidenceDetails block to dict, if possible."""
        if isinstance(v, str):
            try:
                return json.loads(v)['EvidenceDetails']
            except (json.JSONDecodeError, KeyError) as err:
                raise ValueError(
                    'Evidence details cannot be converted to json or key not found'
                ) from err

    @field_validator('evidence_details', mode='after')
    @classmethod
    def assign_correct_type_to_evidence_details(cls, f):
        """EvidenceDetails has to named 'Details' during the serialization.
        Now we add an inner evidenceDetails block.
        """
        return Details.model_validate({'EvidenceDetails': f})

    @model_validator(mode='after')
    def add_risk_rule(self):
        """Calculate and add the RiskRule attribute."""
        evidence = self.evidence_details.evidence_details
        max_criticality = min(3, max(e.criticality for e in evidence))
        risk_rules = ' | '.join(e.rule for e in evidence if e.criticality >= max_criticality)

        self.risk_rules = risk_rules
        return self
