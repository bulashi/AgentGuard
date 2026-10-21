import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef } from 'react'
import { Button, type ButtonProps } from 'antd'
import '../liquid-glass.css'

export interface LiquidGlassButtonProps extends ButtonProps {
  glassTone?: 'primary' | 'neutral'
}

type ButtonElement = HTMLButtonElement | HTMLAnchorElement
type PointerHandler = NonNullable<ButtonProps['onPointerMove']>
const staticSelector = ':disabled, [aria-disabled="true"], [data-glass-busy="true"]'
const motionProperties = ['--lg-pointer-x', '--lg-pointer-y', '--lg-shift-x', '--lg-shift-y']

export const LiquidGlassButton = forwardRef<ButtonElement, LiquidGlassButtonProps>(
  function LiquidGlassButton({
    glassTone, className, children, disabled, loading,
    onPointerEnter, onPointerMove, onPointerLeave, onPointerCancel, onBlur, ...props
  }, forwardedRef) {
    const buttonRef = useRef<ButtonElement>(null)
    const frame = useRef<number | null>(null)
    const point = useRef<{ x: number; y: number } | null>(null)
    const canAnimate = useRef(false)
    const isGlassBusy = Boolean(loading)
    const resolvedTone = glassTone ?? (props.type === 'primary' || props.color === 'primary' ? 'primary' : 'neutral')

    useImperativeHandle(forwardedRef, () => buttonRef.current!)

    const reset = useCallback(() => {
      if (frame.current !== null) cancelAnimationFrame(frame.current)
      frame.current = null
      point.current = null
      motionProperties.forEach((property) => buttonRef.current?.style.removeProperty(property))
    }, [])

    useEffect(() => {
      if (typeof window.matchMedia !== 'function') return reset
      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
      const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)')
      const forcedColors = window.matchMedia('(forced-colors: active)')
      const moreContrast = window.matchMedia('(prefers-contrast: more)')
      const sync = () => {
        canAnimate.current = !reducedMotion.matches && !forcedColors.matches && !moreContrast.matches && finePointer.matches
        if (!canAnimate.current) reset()
      }
      sync()
      reducedMotion.addEventListener('change', sync)
      finePointer.addEventListener('change', sync)
      forcedColors.addEventListener('change', sync)
      moreContrast.addEventListener('change', sync)
      return () => {
        canAnimate.current = false
        reducedMotion.removeEventListener('change', sync)
        finePointer.removeEventListener('change', sync)
        forcedColors.removeEventListener('change', sync)
        moreContrast.removeEventListener('change', sync)
        reset()
      }
    }, [reset])

    useEffect(() => {
      if (disabled || isGlassBusy) reset()
    }, [disabled, isGlassBusy, reset])

    const updateHighlight: PointerHandler = (event) => {
      if (event.defaultPrevented || !buttonRef.current || !canAnimate.current || disabled || isGlassBusy
        || event.pointerType === 'touch' || event.currentTarget.matches(staticSelector)) {
        reset()
        return
      }
      point.current = { x: event.clientX, y: event.clientY }
      if (frame.current !== null) return
      // Coalesce pointer events into one layout read and one visual update per frame.
      frame.current = requestAnimationFrame(() => {
        frame.current = null
        const node = buttonRef.current
        const position = point.current
        if (!node || !position || !canAnimate.current || node.matches(staticSelector)) return
        const bounds = node.getBoundingClientRect()
        if (!bounds.width || !bounds.height) return
        const x = Math.max(0, Math.min(1, (position.x - bounds.left) / bounds.width))
        const y = Math.max(0, Math.min(1, (position.y - bounds.top) / bounds.height))
        node.style.setProperty('--lg-pointer-x', `${x * 100}%`)
        node.style.setProperty('--lg-pointer-y', `${y * 100}%`)
        node.style.setProperty('--lg-shift-x', `${(x - 0.5) * 2.4}px`)
        node.style.setProperty('--lg-shift-y', `${(y - 0.5) * 1.6}px`)
      })
    }

    return (
      <Button
        {...props}
        aria-label={props['aria-label'] ?? (typeof children === 'string' ? children : undefined)}
        ref={buttonRef}
        disabled={disabled}
        loading={loading}
        className={['liquid-glass-button', className].filter(Boolean).join(' ')}
        data-glass-tone={resolvedTone}
        data-glass-busy={isGlassBusy ? 'true' : 'false'}
        onPointerEnter={(event) => { onPointerEnter?.(event); updateHighlight(event) }}
        onPointerMove={(event) => { onPointerMove?.(event); updateHighlight(event) }}
        onPointerLeave={(event) => { onPointerLeave?.(event); reset() }}
        onPointerCancel={(event) => { onPointerCancel?.(event); reset() }}
        onBlur={(event) => { onBlur?.(event); reset() }}
      >
        {children}
      </Button>
    )
  },
)

export default LiquidGlassButton
