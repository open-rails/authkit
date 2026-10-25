ALTER TABLE {{schema}}.notify_items
    ADD COLUMN action_requested boolean NOT NULL DEFAULT false;
UPDATE {{schema}}.notify_items SET action_requested = true WHERE status <> '';
