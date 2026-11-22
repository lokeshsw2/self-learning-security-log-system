import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Empty, ErrorNote, Loading, Mono, useLoad } from "@/components/common"
import { ago, api } from "@/lib/api"
import { go } from "@/lib/router"

export function QueuePage() {
  const { data, error } = useLoad(() => api.queue(), [])
  if (error) return <ErrorNote error={error} />
  if (!data) return <Loading rows={6} />
  return (
    <Card>
      <CardHeader>
        <CardTitle>Work waiting for the AI agents</CardTitle>
        <CardDescription>
          Groups that need a parser or mapping, sources to name, and grouping questions. Agents write rules as data; code
          verifies every rule before it goes live.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <Empty>Nothing waiting.</Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Work</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Detail</TableHead>
                <TableHead>Waiting</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((x) => {
                const sig = typeof x.payload.signature === "string" ? x.payload.signature : null
                const detail = x.payload.reason ?? x.payload.question ?? x.payload.source ?? ""
                return (
                  <TableRow key={`${x.name}-${x.key}`} className={sig ? "cursor-pointer" : ""} onClick={() => sig && go("group", sig)}>
                    <TableCell><Badge variant="outline">{x.name}</Badge></TableCell>
                    <TableCell className="max-w-72 whitespace-normal"><Mono>{x.key}</Mono></TableCell>
                    <TableCell className="max-w-md whitespace-normal text-muted-foreground">{String(detail)}</TableCell>
                    <TableCell className="text-muted-foreground">{ago(x.created_at)}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
