import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { savedSnapshot } from '../test/fixtures'
import { HistoryView } from './HistoryView'

describe('HistoryView', () => {
  it('does not reset a newly loaded page after the initial search debounce', async () => {
    const task = { ...savedSnapshot.task, credential_count: 1, execution_count: 1 }
    const older = { ...task, task_id: 'TASK-earlier-record' }
    const tasksApi = vi.spyOn(api, 'tasks').mockImplementation(async (options) => options?.offset
      ? { items: [older], has_more: false } : { items: [task], has_more: true })
    try {
      render(<HistoryView tasks={[]} selectedTaskId={null} onSelect={vi.fn()} />)
      await screen.findByTestId(`history-task-${task.task_id}`)
      const button = screen.getByRole('button', { name: '加载更早记录' })
      await waitFor(() => expect(button).toBeEnabled())
      fireEvent.click(button)
      await screen.findByTestId(`history-task-${older.task_id}`)
      await new Promise((resolve) => setTimeout(resolve, 350))
      expect(screen.getByTestId(`history-task-${older.task_id}`)).toBeInTheDocument()
      expect(tasksApi).toHaveBeenLastCalledWith({ offset: 40, search: '', status: '' })
    } finally { tasksApi.mockRestore() }
  })
  it('loads older records from the BFF and opens an individual task', async () => {
    const task = { ...savedSnapshot.task, credential_count: 1, execution_count: 1 }
    const tasksApi = vi.spyOn(api, 'tasks').mockResolvedValue({ items: [task], has_more: false })
    const open = vi.fn()
    try {
      render(<HistoryView tasks={[]} selectedTaskId={null} onSelect={open} />)
      const row = await screen.findByTestId(`history-task-${task.task_id}`)
      fireEvent.click(row)
      expect(open).toHaveBeenCalledWith(task.task_id)
      expect(await screen.findByText('已到最早记录')).toBeInTheDocument()
      expect(tasksApi).toHaveBeenCalledWith({ offset: 0, search: '', status: '' })
    } finally { tasksApi.mockRestore() }
  })
})
