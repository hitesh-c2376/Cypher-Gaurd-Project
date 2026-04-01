from models import db, Alert, BlockedIP, Device, User
from logging_engine import log_event


def execute_soar_actions():
    """
    Reads unprocessed alerts and performs automated containment actions.
    Prevents re-execution using soar_executed flag.
    """

    pending_alerts = Alert.query.filter_by(soar_executed=False).all()

    for alert in pending_alerts:
        action_taken = None

        # ===============================
        # 1️⃣ BRUTE FORCE LOGIN
        # ===============================
        if alert.alert_type == "BRUTE_FORCE_LOGIN":

            if alert.source_ip:
                existing_block = BlockedIP.query.filter_by(
                    ip_address=alert.source_ip
                ).first()

                if not existing_block:
                    blocked_ip = BlockedIP(
                        ip_address=alert.source_ip,
                        reason="Blocked due to brute force login"
                    )
                    db.session.add(blocked_ip)
                    action_taken = "IP_BLOCKED"

        # ===============================
        # 2️⃣ DEVICE ENUMERATION
        # ===============================
        elif alert.alert_type == "DEVICE_ENUMERATION_ATTACK":

            if alert.source_ip:
                existing_block = BlockedIP.query.filter_by(
                    ip_address=alert.source_ip
                ).first()

                if not existing_block:
                    blocked_ip = BlockedIP(
                        ip_address=alert.source_ip,
                        reason="Blocked due to device enumeration attack"
                    )
                    db.session.add(blocked_ip)
                    action_taken = "IP_BLOCKED"

        # ===============================
        # 3️⃣ HMAC ATTACK ATTEMPT
        # ===============================
        elif alert.alert_type == "HMAC_ATTACK_ATTEMPT":

            if alert.related_device_id:
                device = Device.query.filter_by(
                    device_id=alert.related_device_id
                ).first()

                if device:
                    device.status = "LOCKED"
                    device.key_rotation_required = True
                    action_taken = "DEVICE_LOCKED_AND_KEY_ROTATION_FLAGGED"

        # ===============================
        # 4️⃣ REPLAY ATTACK DETECTED
        # ===============================
        elif alert.alert_type == "REPLAY_ATTACK_DETECTED":

            if alert.related_device_id:
                device = Device.query.filter_by(
                    device_id=alert.related_device_id
                ).first()

                if device:
                    device.status = "LOCKED"
                    device.key_rotation_required = True
                    action_taken = "DEVICE_LOCKED_REPLAY_ATTACK"

        # ===============================
        # 5️⃣ BLOCKCHAIN TAMPER ALERT
        # ===============================
        elif alert.alert_type == "BLOCKCHAIN_TAMPER_ALERT":

            # Extreme case — lock affected device
            if alert.related_device_id:
                device = Device.query.filter_by(
                    device_id=alert.related_device_id
                ).first()

                if device:
                    device.status = "LOCKED"
                    action_taken = "DEVICE_LOCKED_BLOCKCHAIN_TAMPER"

        # ===============================
        # Execute logging + mark handled
        # ===============================
        if action_taken:
            alert.soar_executed = True
            alert.soar_action = action_taken

            log_event(
                event_type="SOAR_ACTION_EXECUTED",
                severity="CRITICAL",
                message=f"{action_taken} triggered by alert {alert.alert_type}",
                device_id=alert.related_device_id,
                user_id=alert.related_user_id,
                ip_address=alert.source_ip
            )

    db.session.commit()