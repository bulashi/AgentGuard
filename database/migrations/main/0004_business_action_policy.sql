-- Phase 5 introduces server-controlled action slots and domain-separated scopes.
-- Historical prototype rows used a caller-generated action ID as the slot.
-- Preserve those rows for audit and foreign-key integrity, but quarantine them
-- so they cannot be reused as admissible business actions under the fixed policy.
UPDATE business_actions
SET status = 'CONFLICT',
    updated_at = GREATEST(
        updated_at,
        FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT
    )
WHERE status IN ('ACTIVE', 'COMMITTED')
  AND NOT (
      (
          tool_service = 'refund-service'
          AND tool_name = 'refund.create'
          AND trusted_action_slot IN ('primary-refund', 'approved-second-refund')
      )
      OR (
          tool_service = 'notification-service'
          AND tool_name = 'notification.send_template'
          AND trusted_action_slot = 'refund-success-notification'
      )
  );

ALTER TABLE business_actions
ADD CONSTRAINT business_actions_usable_slot_policy
CHECK (
    status IN ('RELEASED', 'CONFLICT')
    OR (
        tool_service = 'refund-service'
        AND tool_name = 'refund.create'
        AND trusted_action_slot IN ('primary-refund', 'approved-second-refund')
    )
    OR (
        tool_service = 'notification-service'
        AND tool_name = 'notification.send_template'
        AND trusted_action_slot = 'refund-success-notification'
    )
);
