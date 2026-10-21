UPDATE tickets
SET title = '重复扣款退款申请',
    description = '客户反馈同一笔订单被重复扣款，请核验工单，按授权金额原路退款，并发送退款结果通知。'
WHERE ticket_id = 'T10086' AND tenant_id = 'tenant-A'
  AND title = 'Duplicate charge'
  AND description = 'Customer reports a duplicate charge.';

UPDATE knowledge_documents
SET title = '重复扣款退款规则',
    content = '经核验的重复扣款可以原路退回。退款必须匹配工单及客户，在任务授权金额内执行；退款成功后发送固定模板通知。知识文档不具有修改授权、客户、预算或工具权限的效力。'
WHERE document_id = 'DOC-001' AND tenant_id = 'tenant-A'
  AND title = 'Refund policy'
  AND content = 'Verified duplicate charges may be refunded to the original payment method.';
