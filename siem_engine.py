from datetime import datetime, timezone, timedelta
from sqlalchemy import and_

from models import db, SecurityEvent, Alert
from logging_engine import log_event


# -------------------------------------------------
# Helper: Check if similar alert already exists
# (Prevents duplicate alert spam)
# -------------------------------------------------
def alert_exists_recent(alert_type, source_ip=None, device_id=None, minutes=5):
    time_limit = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    query = Alert.query.filter(
        
        Alert.alert_type == alert_type,
        Alert.created_at >= time_limit
    )

    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)

    if device_id:
        query = query.filter(Alert.related_device_id == device_id)

    return query.first() is not None


# -------------------------------------------------
# Rule 1: Brute Force Login Detection
# -------------------------------------------------
def detect_bruteforce_login():
    alerts_created = 0
    time_window = datetime.now(timezone.utc) - timedelta(minutes=2)

    events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "LOGIN_FAIL",
        SecurityEvent.created_at >= time_window,
        SecurityEvent.ip_address.isnot(None)
    ).all()

    ip_counts = {}
    for e in events:
        ip_counts[e.ip_address] = ip_counts.get(e.ip_address, 0) + 1

    for ip, count in ip_counts.items():
        if count >= 5:
            if not alert_exists_recent("BRUTE_FORCE_LOGIN", source_ip=ip):
                alert = Alert(
                    alert_type="BRUTE_FORCE_LOGIN",
                    severity="HIGH",
                    description=f"Brute force suspected: {count} failed logins within 2 minutes from IP {ip}",
                    source_ip=ip,
                    event_count=count
                )
                db.session.add(alert)
                db.session.commit()

                log_event(
                    event_type="ALERT_GENERATED",
                    severity="HIGH",
                    message=f"SIEM Alert: BRUTE_FORCE_LOGIN detected from IP {ip} ({count} attempts)",
                    ip_address=ip
                )

                alerts_created += 1

    return alerts_created


# -------------------------------------------------
# Rule 2: Invalid Device Flood Detection
# -------------------------------------------------
def detect_invalid_device_flood():
    alerts_created = 0
    time_window = datetime.now(timezone.utc) - timedelta(minutes=5)

    events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "INVALID_DEVICE",
        SecurityEvent.created_at >= time_window,
        SecurityEvent.ip_address.isnot(None)
    ).all()

    ip_counts = {}
    for e in events:
        ip_counts[e.ip_address] = ip_counts.get(e.ip_address, 0) + 1

    for ip, count in ip_counts.items():
        if count >= 10:
            if not alert_exists_recent("DEVICE_ENUMERATION_ATTACK", source_ip=ip):
                alert = Alert(
                    alert_type="DEVICE_ENUMERATION_ATTACK",
                    severity="HIGH",
                    description=f"Device enumeration suspected: {count} invalid device attempts within 5 minutes from IP {ip}",
                    source_ip=ip,
                    event_count=count
                )
                db.session.add(alert)
                db.session.commit()

                log_event(
                    event_type="ALERT_GENERATED",
                    severity="HIGH",
                    message=f"SIEM Alert: DEVICE_ENUMERATION_ATTACK from IP {ip} ({count} invalid devices)",
                    ip_address=ip
                )

                alerts_created += 1

    return alerts_created


# -------------------------------------------------
# Rule 3: HMAC Verification Failures Detection
# -------------------------------------------------
def detect_hmac_failures():
    alerts_created = 0
    time_window = datetime.now(timezone.utc) - timedelta(minutes=3)

    events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "HMAC_MISMATCH",
        SecurityEvent.created_at >= time_window,
        SecurityEvent.device_id.isnot(None)
    ).all()

    device_counts = {}
    for e in events:
        device_counts[e.device_id] = device_counts.get(e.device_id, 0) + 1

    for device_id, count in device_counts.items():
        if count >= 5:
            if not alert_exists_recent("HMAC_ATTACK_ATTEMPT", device_id=device_id):
                alert = Alert(
                    alert_type="HMAC_ATTACK_ATTEMPT",
                    severity="HIGH",
                    description=f"Repeated HMAC verification failures: {count} attempts in 3 minutes for device {device_id}",
                    related_device_id=device_id,
                    event_count=count
                )
                db.session.add(alert)
                db.session.commit()

                log_event(
                    event_type="ALERT_GENERATED",
                    severity="HIGH",
                    message=f"SIEM Alert: HMAC_ATTACK_ATTEMPT detected for device {device_id} ({count} failures)",
                    device_id=device_id
                )

                alerts_created += 1

    return alerts_created


# -------------------------------------------------
# Rule 4: Replay Attack Detection (Critical)
# -------------------------------------------------
def detect_replay_attack():
    alerts_created = 0
    time_window = datetime.now(timezone.utc) - timedelta(minutes=10)

    events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "NONCE_REPLAY_ATTEMPT",
        SecurityEvent.created_at >= time_window
    ).all()

    for e in events:
        device_id = e.device_id
        ip = e.ip_address

        if not alert_exists_recent("REPLAY_ATTACK_DETECTED", source_ip=ip, device_id=device_id, minutes=10):
            alert = Alert(
                alert_type="REPLAY_ATTACK_DETECTED",
                severity="CRITICAL",
                description=f"Replay attack attempt detected for device {device_id} from IP {ip}",
                source_ip=ip,
                related_device_id=device_id,
                event_count=1
            )
            db.session.add(alert)
            db.session.commit()

            log_event(
                event_type="ALERT_GENERATED",
                severity="CRITICAL",
                message=f"SIEM Alert: REPLAY_ATTACK_DETECTED for device {device_id} from IP {ip}",
                device_id=device_id,
                ip_address=ip
            )

            alerts_created += 1

    return alerts_created

# -------------------------------------------------
# Rule 5: Blockchain Tamper Detection (Critical)
# -------------------------------------------------
def detect_blockchain_tamper():
    alerts_created = 0
    time_window = datetime.now(timezone.utc) - timedelta(minutes=10)

    events = SecurityEvent.query.filter(
        SecurityEvent.event_type == "BLOCKCHAIN_TAMPER_DETECTED",
        SecurityEvent.created_at >= time_window
    ).all()

    for e in events:
        if not alert_exists_recent(
            "BLOCKCHAIN_TAMPER_ALERT",
            source_ip=e.ip_address,
            device_id=e.device_id,
            minutes=10
        ):
            alert = Alert(
                alert_type="BLOCKCHAIN_TAMPER_ALERT",
                severity="CRITICAL",
                description="Blockchain ledger integrity violation detected",
                source_ip=e.ip_address,
                related_device_id=e.device_id,
                event_count=1
            )
            db.session.add(alert)
            db.session.commit()

            log_event(
                event_type="ALERT_GENERATED",
                severity="CRITICAL",
                message="SIEM Alert: BLOCKCHAIN_TAMPER_ALERT generated",
                device_id=e.device_id,
                ip_address=e.ip_address
            )

            alerts_created += 1

    return alerts_created


# -------------------------------------------------
# Run All Detection Rules
# -------------------------------------------------
def run_all_detections():
    total_alerts = 0

    total_alerts += detect_bruteforce_login()
    total_alerts += detect_invalid_device_flood()
    total_alerts += detect_hmac_failures()
    total_alerts += detect_replay_attack()
    total_alerts += detect_blockchain_tamper()

    return total_alerts
