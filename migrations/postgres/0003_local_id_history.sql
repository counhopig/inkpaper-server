-- Keep every local id that has been assigned to a device/list. A deleted id
-- remains reserved until a future protocol can confirm that the device has
-- applied the deletion, so a stale dirty upload cannot change a new record.
CREATE TABLE IF NOT EXISTS device_local_ids (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('alarm', 'todo')),
    local_id BIGINT NOT NULL,
    released BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, kind, local_id)
);

INSERT INTO device_local_ids (device_id, kind, local_id)
SELECT device_id, 'alarm', local_id FROM alarms
ON CONFLICT (device_id, kind, local_id) DO NOTHING;
INSERT INTO device_local_ids (device_id, kind, local_id)
SELECT device_id, 'todo', local_id FROM todos
ON CONFLICT (device_id, kind, local_id) DO NOTHING;
