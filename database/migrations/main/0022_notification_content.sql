ALTER TABLE notifications ADD COLUMN template_version TEXT;
ALTER TABLE notifications ADD COLUMN content TEXT;
ALTER TABLE notifications ADD CONSTRAINT notification_content_pair CHECK (
    (template_version IS NULL AND content IS NULL)
    OR (template_version = 'v1' AND content IS NOT NULL AND length(content) BETWEEN 1 AND 4096)
);
