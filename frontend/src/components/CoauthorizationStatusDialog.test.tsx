import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import type { CoauthorizationStatus } from '../types'
import { CoauthorizationStatusDialog } from './CoauthorizationStatusDialog'

const enabled: CoauthorizationStatus = {
  schema_version: '1.0', enabled: true,
  policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY',
}

afterEach(() => vi.restoreAllMocks())

describe('CoauthorizationStatusDialog', () => {
  it('only reads configuration when opened and does not infer task approvals', async () => {
    const read = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(enabled)
    render(<CoauthorizationStatusDialog />)
    expect(read).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '共同授权状态' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('要求两方审批')).toBeInTheDocument()
    expect(within(dialog).getByText('强制拒绝')).toBeInTheDocument()
    expect(within(dialog).getByText('本入口未查询审批记录')).toBeInTheDocument()
    expect(within(dialog).queryByText('审批通过')).not.toBeInTheDocument()
    expect(read).toHaveBeenCalledTimes(1)
  })

  it('does not preserve a successful configuration after a failed refresh', async () => {
    const read = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValueOnce(enabled).mockRejectedValueOnce(new Error('unavailable'))
    render(<CoauthorizationStatusDialog />)
    fireEvent.click(screen.getByRole('button', { name: '共同授权状态' }))
    const dialog = await screen.findByRole('dialog')
    await within(dialog).findByText('要求两方审批')
    const refresh = within(dialog).getByRole('button', { name: '刷新共同授权状态' })
    await waitFor(() => expect(refresh).not.toHaveClass('ant-btn-loading'))
    fireEvent.click(refresh)
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('配置读取失败，未判定为关闭或已审批')
    expect(within(dialog).queryByText('强制拒绝')).not.toBeInTheDocument()
    expect(within(dialog).queryByText('未启用')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('未判定为关闭或已审批')
  })

  it('ignores an earlier response after closing and reopening', async () => {
    let resolveEarlier!: (value: CoauthorizationStatus) => void
    const earlier = new Promise<CoauthorizationStatus>((resolve) => { resolveEarlier = resolve })
    const read = vi.spyOn(api, 'coauthorizationStatus').mockReturnValueOnce(earlier)
      .mockResolvedValueOnce({ ...enabled, enabled: false })
    render(<CoauthorizationStatusDialog />)
    fireEvent.click(screen.getByRole('button', { name: '共同授权状态' }))
    const first = await screen.findByRole('dialog')
    fireEvent.click(within(first).getByRole('button', { name: '关闭' }))
    fireEvent.click(screen.getByRole('button', { name: '共同授权状态' }))
    const dialog = await screen.findByRole('dialog')
    await within(dialog).findByText('未启用')
    await act(async () => { resolveEarlier(enabled); await earlier })
    expect(within(dialog).queryByText('要求两方审批')).not.toBeInTheDocument()
    expect(within(dialog).getByText('未启用')).toBeInTheDocument()
    expect(read).toHaveBeenCalledTimes(2)
  })
})
