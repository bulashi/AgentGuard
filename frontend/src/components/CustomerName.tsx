import { customerLabel } from '../customerDisplay'

export function CustomerName({ id }: { id: string }) {
  return <span title={id}>{customerLabel(id)}</span>
}
