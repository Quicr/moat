-- Enforce that use_count never exceeds max_uses at the database level
ALTER TABLE room_invites ADD CONSTRAINT check_invite_use_count
    CHECK (max_uses IS NULL OR use_count <= max_uses);
