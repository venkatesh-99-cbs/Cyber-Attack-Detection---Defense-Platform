from sqlalchemy.orm import Session
from BlueTeam.database.models.lifecycle import (
    DetectionRecord, RiskRecord, AlertRecord, IncidentRecord, ResponseRecord
)
from BlueTeam.database.models.validation import ValidationRecord
from BlueTeam.validation.config import get_expected_for_attack, ExpectedResult

class ValidationEngine:
    """Evaluates expected vs actual lifecycle results and records the validation."""
    
    def validate(self, db: Session, event_id: str, attack_type: str, custom_expected: ExpectedResult = None) -> ValidationRecord:
        expected = custom_expected or get_expected_for_attack(attack_type)
        if not expected:
            # Fallback to empty expected if unknown
            expected = ExpectedResult(attack_type=attack_type)
            
        # Retrieve actual records
        detections = db.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).all()
        risk = db.query(RiskRecord).filter(RiskRecord.event_id == event_id).order_by(RiskRecord.id.desc()).first()
        alert = db.query(AlertRecord).filter(AlertRecord.event_id == event_id).order_by(AlertRecord.id.desc()).first()
        incident = db.query(IncidentRecord).filter(IncidentRecord.event_id == event_id).order_by(IncidentRecord.id.desc()).first()
        response = db.query(ResponseRecord).filter(ResponseRecord.event_id == event_id).order_by(ResponseRecord.id.desc()).first()
        
        # Calculate actual values
        actual_detection = None
        if expected.detection:
            # Find if the specific expected rule fired
            match = next((d for d in detections if d.rule_name == expected.detection and d.detected), None)
            if match:
                actual_detection = expected.detection
            elif detections:
                actual_detection = detections[0].rule_name
        elif detections and any(d.detected for d in detections):
            actual_detection = next(d.rule_name for d in detections if d.detected)
            
        actual_risk_level = risk.risk_level if risk else None
        actual_alert = True if alert else False
        actual_incident = True if incident else False
        actual_response = response.mode if response else None

        # Compare
        detection_match = (expected.detection == actual_detection) if expected.detection is None or expected.detection else True
        if expected.detection and actual_detection == expected.detection:
            detection_match = True
        elif expected.detection and actual_detection != expected.detection:
            detection_match = False

        risk_match = (expected.risk_level == actual_risk_level) if expected.risk_level else True
        alert_match = (expected.alert == actual_alert) if expected.alert is not None else True
        incident_match = (expected.incident == actual_incident) if expected.incident is not None else True
        response_match = (expected.response == actual_response) if expected.response is not None else True
        
        reasons = []
        if expected.detection:
            reasons.append(f"Detection rule '{expected.detection}' match: {'PASS' if detection_match else 'FAIL'}")
        if expected.risk_level:
            reasons.append(f"Risk level '{expected.risk_level}' match: {'PASS' if risk_match else 'FAIL'}")
        if expected.alert is not None:
            reasons.append(f"Alert generation '{expected.alert}' match: {'PASS' if alert_match else 'FAIL'}")
        if expected.incident is not None:
            reasons.append(f"Incident creation '{expected.incident}' match: {'PASS' if incident_match else 'FAIL'}")
        if expected.response is not None:
            reasons.append(f"Response mode '{expected.response}' match: {'PASS' if response_match else 'FAIL'}")

        overall_result = "PASS" if all([detection_match, risk_match, alert_match, incident_match, response_match]) else "FAIL"

        validation_record = ValidationRecord(
            event_id=event_id,
            attack_type=expected.attack_type,
            expected_detection=expected.detection,
            expected_risk_level=expected.risk_level,
            expected_alert=expected.alert,
            expected_incident=expected.incident,
            expected_response=expected.response,
            actual_detection=actual_detection,
            actual_risk_level=actual_risk_level,
            actual_alert=actual_alert,
            actual_incident=actual_incident,
            actual_response=actual_response,
            detection_match=detection_match,
            risk_match=risk_match,
            alert_match=alert_match,
            incident_match=incident_match,
            response_match=response_match,
            overall_result=overall_result,
            reasons=reasons
        )
        
        db.add(validation_record)
        db.commit()
        db.refresh(validation_record)
        
        return validation_record

