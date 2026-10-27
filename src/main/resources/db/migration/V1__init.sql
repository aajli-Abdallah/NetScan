CREATE TABLE devices (
    id         VARCHAR(36) NOT NULL PRIMARY KEY,
    mac        VARCHAR(17) NOT NULL,
    label      VARCHAR(100),
    known      BOOLEAN NOT NULL DEFAULT FALSE,
    last_ip    VARCHAR(45),
    first_seen TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_seen  TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_devices_mac UNIQUE (mac)
);
CREATE INDEX idx_devices_last_seen ON devices (last_seen);
