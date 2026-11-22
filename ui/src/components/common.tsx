import { useEffect, useState, type ReactNode } from "react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { Json } from "@/lib/api"
import { cn } from "@/lib/utils"

/** Load data with loading and error state; re-runs when deps change. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    setError(null)
    fn().then(
      (d) => live && setData(d),
      (e: Error) => live && setError(e.message),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  return { data, error, reload: () => setTick((t) => t + 1) }
}

export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  )
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <Card className="border-destructive/40">
      <CardContent className="text-sm text-destructive">{error}</CardContent>
    </Card>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-muted-foreground">{children}</p>
}

export function Kpi({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <Card size="sm" className="gap-1">
      <CardContent>
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums tracking-tight">{value}</div>
        {hint && <div className="mt-0.5 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  )
}

const STATUS: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  mapped: "default",
  parsed: "secondary",
  queued: "outline",
  new: "outline",
  longtail: "outline",
  drift: "destructive",
  pending: "outline",
  dlq: "destructive",
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge variant={STATUS[status] ?? "secondary"}>{status}</Badge>
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs break-all", className)}>{children}</span>
}

export function RawLine({ text, className }: { text: string; className?: string }) {
  return <div className={cn("font-mono text-xs leading-relaxed break-all whitespace-pre-wrap", className)}>{text}</div>
}

/** Read-only JSON with light syntax colouring. */
export function JsonView({ value, className }: { value: Json | undefined; className?: string }) {
  return (
    <pre
      className={cn(
        "max-h-[480px] overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap",
        className,
      )}
    >
      {render(value ?? null, 0)}
    </pre>
  )
}

function render(v: Json, depth: number): ReactNode {
  const pad = "  ".repeat(depth)
  if (v === null) return <span className="text-muted-foreground">null</span>
  if (typeof v === "string") return <span className="text-emerald-700 dark:text-emerald-400">"{v}"</span>
  if (typeof v === "number" || typeof v === "boolean")
    return <span className="text-amber-700 dark:text-amber-400">{String(v)}</span>
  if (Array.isArray(v)) {
    if (!v.length) return "[]"
    return (
      <>
        {"[\n"}
        {v.map((x, i) => (
          <span key={i}>
            {pad + "  "}
            {render(x, depth + 1)}
            {i < v.length - 1 ? ",\n" : "\n"}
          </span>
        ))}
        {pad + "]"}
      </>
    )
  }
  const ent = Object.entries(v)
  if (!ent.length) return "{}"
  return (
    <>
      {"{\n"}
      {ent.map(([k, x], i) => (
        <span key={k}>
          {pad + "  "}
          <span className="text-sky-700 dark:text-sky-400">"{k}"</span>: {render(x, depth + 1)}
          {i < ent.length - 1 ? ",\n" : "\n"}
        </span>
      ))}
      {pad + "}"}
    </>
  )
}

export function Crumbs({ items }: { items: { label: string; href?: string }[] }) {
  return (
    <nav className="mb-3 flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
      {items.map((it, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <span>/</span>}
          {it.href ? (
            <a href={it.href} className="text-primary hover:underline">
              {it.label}
            </a>
          ) : (
            <span className="font-mono text-xs text-foreground">{it.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
