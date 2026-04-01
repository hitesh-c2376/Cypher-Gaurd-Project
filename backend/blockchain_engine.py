import hashlib
from models import db, BlockchainBlock


# -----------------------------------------
# Genesis Block Creation
# -----------------------------------------
def create_genesis_block():
    if BlockchainBlock.query.first():
        return  # already exists

    genesis = BlockchainBlock(
        device_id="GENESIS",
        key_hash="0",
        key_version=0,
        key_status="GENESIS",
        previous_hash="0",
        block_hash="0"
    )
    genesis.block_hash = genesis.compute_hash()

    try:
        db.session.add(genesis)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


# -----------------------------------------
# Add New Block
# -----------------------------------------
def add_block(device_id, key_hash, key_version, key_status):
    last_block = BlockchainBlock.query.order_by(BlockchainBlock.id.desc()).first()

    new_block = BlockchainBlock(
        device_id=device_id,
        key_hash=key_hash,
        key_version=key_version,
        key_status=key_status,
        previous_hash=last_block.block_hash if last_block else "0"
    )
    new_block.block_hash = new_block.compute_hash()

    # SAFE FIX: caller is responsible for the outer transaction,
    # so we use flush() here instead of commit().
    # This avoids partial commits when add_block is called inside
    # a larger try/except block in device.py.
    db.session.add(new_block)
    db.session.flush()


# -----------------------------------------
# Validate Entire Chain
# -----------------------------------------
def validate_chain():
    blocks = BlockchainBlock.query.order_by(BlockchainBlock.id.asc()).all()

    for i in range(1, len(blocks)):
        current = blocks[i]
        previous = blocks[i - 1]

        if current.previous_hash != previous.block_hash:
            return False

        if current.block_hash != current.compute_hash():
            return False

    return True


# -----------------------------------------
# Get Chain as List (for API/dashboard)
# -----------------------------------------
def get_chain():
    blocks = BlockchainBlock.query.order_by(BlockchainBlock.id.asc()).all()
    return [
        {
            "id": b.id,
            "device_id": b.device_id,
            "key_hash": b.key_hash,
            "key_version": b.key_version,
            "key_status": b.key_status,
            "previous_hash": b.previous_hash,
            "block_hash": b.block_hash,
            "created_at": b.created_at.isoformat() if b.created_at else None
        }
        for b in blocks
    ]