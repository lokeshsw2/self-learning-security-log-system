import { useState } from "react"
import { Search } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Crumbs, Empty, ErrorNote, Loading, Mono, useLoad } from "@/components/common"
import { ago, api, fmt } from "@/lib/api"
import { go, href, type Route } from "@/lib/router"
import { RuleCard } from "./Sources"

const KINDS = ["all", "parser", "mapping", "source", "mask", "split", "longtail", "detect", "dialect", "sign", "words", "directive", "framing"]

export function RulesPage({ route }: { route: Route }) {
  const kind = route.params.kind ?? ""
  const q = route.params.q ?? ""
  const [form, setForm] = useState({ kind: kind || "all", q })
  const { data, error } = useLoad(() => api.rules(kind, q), [kind, q])
  return (
    <div className="space-y-4">
      <Card>
        <CardContent>
          <form
            className="grid items-end gap-3 sm:grid-cols-[200px_1fr_auto]"
            onSubmit={(e) => { e.preventDefault(); go("rules", undefined, { kind: form.kind === "all" ? "" : form.kind, q: form.q }) }}
          >
            <div className="grid gap-1.5">
              <Label className="text-xs text-muted-foreground">Kind</Label>
              <Select value={form.kind} onValueChange={(v) => setForm({ ...form, kind: String(v) })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {KINDS.map((k) => <SelectItem key={k} value={k}>{k}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs text-muted-foreground">Search</Label>
              <Input value={form.q} onChange={(e) => setForm({ ...form, q: e.target.value })} placeholder="rule id or text in the rule" />
            </div>
            <Button type="submit"><Search /> Search</Button>
          </form>
        </CardContent>
      </Card>
      {error && <ErrorNote error={error} />}
      {!data && !error && <Loading rows={8} />}
      {data && (
        <Card>
          <CardHeader>
            <CardTitle>{fmt(data.length)} rules</CardTitle>
            <CardDescription>Everything here was written as data, by an agent or a seed, and passed its save gate.</CardDescription>
          </CardHeader>
          <CardContent>
            {data.length === 0 ? (
              <Empty>No rules match.</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead className="text-right">Version</TableHead>
                    <TableHead>Written by</TableHead>
                    <TableHead>Body</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((r) => (
                    <TableRow key={r.rule_id} className="cursor-pointer" onClick={() => go("rule", r.rule_id)}>
                      <TableCell className="max-w-72 whitespace-normal"><Mono>{r.rule_id}</Mono></TableCell>
                      <TableCell><Badge variant="secondary">{r.kind}</Badge></TableCell>
                      <TableCell className="text-right tabular-nums">{r.version}</TableCell>
                      <TableCell className="text-muted-foreground">{r.created_by} <span className="text-xs">{ago(r.created_at)}</span></TableCell>
                      <TableCell className="max-w-md truncate"><Mono className="text-muted-foreground">{r.summary}</Mono></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export function RulePage({ ruleId }: { ruleId: string }) {
  const { data, error } = useLoad(() => api.rule(ruleId), [ruleId])
  if (error) return <ErrorNote error={error} />
  if (!data) return <Loading rows={6} />
  const versions = [...data.versions].reverse()
  return (
    <div className="space-y-4">
      <Crumbs items={[{ label: "Rules", href: href("rules") }, { label: ruleId }]} />
      <Card>
        <CardHeader>
          <CardTitle>Used by {fmt(data.used_by_groups.length)} group{data.used_by_groups.length === 1 ? "" : "s"}</CardTitle>
          {data.used_by_groups.length === 0 && (
            <CardDescription>None directly: a base rule other mappings extend, or a detection, source or grouping rule.</CardDescription>
          )}
        </CardHeader>
        {data.used_by_groups.length > 0 && (
          <CardContent className="flex flex-wrap gap-1.5">
            {data.used_by_groups.slice(0, 60).map((s) => (
              <a key={s} href={href("group", s)}><Badge variant="outline" className="font-mono">{s}</Badge></a>
            ))}
          </CardContent>
        )}
      </Card>
      {versions.map((v) => <RuleCard key={v.version} version={v} />)}
    </div>
  )
}
