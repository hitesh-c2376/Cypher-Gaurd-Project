from flask import jsonify, request
from flask_jwt_extended import jwt_required
from datetime import timezone, timedelta, datetime

from models import Alert, Device, SecurityEvent, BlockchainBlock
from siem_engine import run_all_detections
from auth import require_role
from soar_engine import execute_soar_actions
from blockchain_engine import validate_chain, get_chain

IST = timezone(timedelta(hours=5, minutes=30))

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def register_siem_routes(app):

    # =====================================================
    # RUN DETECTIONS
    # =====================================================
    @app.route("/run-detections", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def run_detections():
        total_alerts = run_all_detections()
        execute_soar_actions()
        return jsonify({
            "status": "success",
            "message": "SIEM detection rules executed successfully",
            "alerts_generated": total_alerts
        }), 200


    # =====================================================
    # GET ALERTS — with pagination
    # =====================================================
    @app.route("/alerts", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def get_alerts():
        page = request.args.get("page", 1, type=int)
        per_page = min(
            request.args.get("per_page", DEFAULT_PAGE_SIZE, type=int),
            MAX_PAGE_SIZE
        )

        pagination = Alert.query.order_by(
            Alert.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

        alert_list = []
        for a in pagination.items:
            created_at = a.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            created_ist = created_at.astimezone(IST) if created_at else None

            alert_list.append({
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "source_ip": a.source_ip,
                "related_user_id": a.related_user_id,
                "related_device_id": a.related_device_id,
                "event_count": a.event_count,
                "soar_executed": a.soar_executed,
                "soar_action": a.soar_action,
                "created_at_ist": created_ist.strftime("%Y-%m-%d %H:%M:%S") if created_ist else None
            })

        return jsonify({
            "alerts": alert_list,
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages
        }), 200


    # =====================================================
    # BLOCKCHAIN EXPLORER (ADMIN ONLY)
    # Added: was completely missing before
    # =====================================================
    @app.route("/blockchain", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def get_blockchain():
        chain_valid = validate_chain()
        chain = get_chain()
        return jsonify({
            "chain_valid": chain_valid,
            "total_blocks": len(chain),
            "blocks": chain
        }), 200


    # =====================================================
    # DASHBOARD STATS (ADMIN ONLY)
    # Added: needed by the Overview page
    # =====================================================
    @app.route("/dashboard-stats", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def dashboard_stats():
        last_24h = datetime.now(timezone.utc) - timedelta(hours=24)

        return jsonify({
            "total_devices": Device.query.count(),
            "active_devices": Device.query.filter_by(status="ACTIVE").count(),
            "locked_devices": Device.query.filter_by(status="LOCKED").count(),
            "active_alerts": Alert.query.filter_by(soar_executed=False).count(),
            "events_today": SecurityEvent.query.filter(
                SecurityEvent.created_at >= last_24h
            ).count(),
            "chain_valid": validate_chain(),
            "total_blocks": BlockchainBlock.query.count()
        }), 200