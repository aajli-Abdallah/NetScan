ALTER TABLE devices ADD COLUMN online BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN missed INT NOT NULL DEFAULT 0;

CREATE TABLE device_events (
    id          VARCHAR(36) NOT NULL PRIMARY KEY,
    device_id   VARCHAR(36) NOT NULL,
    mac         VARCHAR(17) NOT NULL,
    label       VARCHAR(100),
    ip          VARCHAR(45),
    known       BOOLEAN NOT NULL,
    type        VARCHAR(10) NOT NULL,
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL
);
CREATE INDEX idx_events_time ON device_events (occurred_at);
CREATE INDEX idx_events_device ON device_events (device_id);
