from models import db, SecurityEvent


def log_event(event_type, severity, message, device_id=None, user_id=None, ip_address=None):
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        message=message,
        device_id=device_id,
        user_id=user_id,
        ip_address=ip_address
    )

    db.session.add(event)
    db.session.commit()
