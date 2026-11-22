import { Toaster } from "@/components/ui/sonner"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { go, useRoute } from "@/lib/router"
import { EventsPage } from "@/pages/Events"
import { IngestPage } from "@/pages/Ingest"
import { QueuePage } from "@/pages/Queue"
import { ReviewPage } from "@/pages/Review"
import { RulePage, RulesPage } from "@/pages/Rules"
import { GroupPage, SourcePage, SourcesPage } from "@/pages/Sources"
import { UnparsedPage } from "@/pages/Unparsed"

const TABS = [
  { id: "ingest", label: "Ingest" },
  { id: "events", label: "Events" },
  { id: "unparsed", label: "Unparsed" },
  { id: "sources", label: "Sources & groups" },
  { id: "rules", label: "Rules" },
  { id: "queue", label: "AI agents" },
  { id: "review", label: "Review" },
]

// detail views highlight their parent tab
const PARENT: Record<string, string> = { group: "sources", rule: "rules" }

export default function App() {
  const route = useRoute()
  const tab = PARENT[route.view] ?? route.view

  let page
  switch (route.view) {
    case "events": page = <EventsPage route={route} />; break
    case "unparsed": page = <UnparsedPage />; break
    case "sources": page = route.arg ? <SourcePage source={route.arg} /> : <SourcesPage />; break
    case "group": page = <GroupPage signature={route.arg} />; break
    case "rules": page = <RulesPage route={route} />; break
    case "rule": page = <RulePage ruleId={route.arg} />; break
    case "queue": page = <QueuePage />; break
    case "review": page = <ReviewPage />; break
    default: page = <IngestPage />
  }

  return (
    <div className="min-h-svh bg-background">
      <header className="sticky top-0 z-10 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <div className="text-sm font-semibold tracking-tight">Log Parser Console</div>
          <Tabs value={tab} onValueChange={(v) => go(String(v))}>
            <TabsList>
              {TABS.map((t) => <TabsTrigger key={t.id} value={t.id}>{t.label}</TabsTrigger>)}
            </TabsList>
          </Tabs>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-5">{page}</main>
      <Toaster />
    </div>
  )
}
