import { useCallback, useEffect, useMemo, useState } from 'react'
import { clsx } from 'clsx'
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  Download,
  FileJson,
  RefreshCw,
  Server
} from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts'

type RunStatus =
  | 'queued'
  | 'preparing'
  | 'generating_genesis'
  | 'generating_topology'
  | 'generating_shadow_yaml'
  | 'running_shadow'
  | 'collecting_stats'
  | 'complete'
  | 'warning'
  | 'error'

interface RunSummary {
  id: number
  run_id: string
  run_index: number | null
  seed: number | null
  status: RunStatus
  stage: string
  started_at: string
  updated_at: string
  ended_at: string | null
  duration_secs: number | null
  simulated_seconds: number
  wall_seconds: number
  current_slot: number
  progress: number
  warnings: string[]
  error: string | null
}

interface DashboardStats {
  total_runs: number
  success_runs: number
  warning_runs: number
  error_runs: number
  active_runs: number
  runs_per_minute: number
  recent_runs: RunSummary[]
}

interface RunDetail extends RunSummary {
  run_dir: string
  metadata: Record<string, any>
  stats: Record<string, any>
}

interface SlotSummary {
  slot: number
  proposer?: number
  published_ms?: number
  n_received?: number
  block_count?: number
  attestation_coverage?: number
  attestation_nodes?: number
  warning?: string
}

interface SlotDetail {
  run_id: string
  slot: number
  state: 'ok' | 'conflict' | 'no_data'
  error?: string
  block_count?: number
  blocks?: Array<Record<string, any>>
  block?: Record<string, any> | null
  cdf?: Array<{ latency_ms: number; received: number; percent: number }>
  slot_stats?: Record<string, any>
}

interface EventRow {
  id: number
  run_id: string
  ts_ms: number
  kind: string
  host: string | null
  slot: number | null
  message: string
  payload: Record<string, any>
}

interface ChainPeer {
  peer: string
  reported_slot: number
  head_slot?: number | null
  justified_slot?: number | null
  finalized_slot?: number | null
  ts_ms?: number
  source?: string
}

interface ChainResponse {
  run_id: string
  selected_slot: number | null
  slots: number[]
  peers: ChainPeer[]
}

interface CoverageDatum {
  slot: string
  ms: number
  warning: boolean
}

const EVENT_KINDS = [
  ['all', 'All events'],
  ['attestation_sent', 'Attestation sent'],
  ['attestation_received', 'Attestation received'],
  ['aggregation_received', 'Aggregation received'],
  ['block_published', 'Block published'],
  ['block_received', 'Block received'],
  ['justified', 'Justified'],
  ['finalized', 'Finalized'],
  ['chain_status', 'Chain status'],
  ['warning', 'Warnings'],
  ['error', 'Errors']
]

const COLORS = ['#2563eb', '#16a34a', '#7c3aed', '#d97706', '#0891b2', '#475569']
const GENESIS_DELAY_SECONDS = 60
const SLOT_SECONDS = 4

function api<T>(path: string): Promise<T> {
  return fetch(path).then((res) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
    return res.json() as Promise<T>
  })
}

function formatDuration(seconds?: number | null): string {
  if (seconds == null || Number.isNaN(seconds)) return '--'
  const total = Math.max(0, Math.floor(seconds))
  const mins = Math.floor(total / 60)
  const secs = total % 60
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

function terminalStatus(status?: string) {
  return status === 'complete' || status === 'warning' || status === 'error'
}

function statusClass(status?: string) {
  if (status === 'complete') return 'good'
  if (status === 'warning') return 'warn'
  if (status === 'error') return 'bad'
  return 'live'
}

function objectEntries(obj?: Record<string, number>) {
  if (!obj) return []
  return Object.entries(obj).map(([name, value]) => ({ name, value }))
}

function maxChainSlotForDuration(duration?: number | null) {
  if (duration == null) return 0
  return Math.max(0, Math.floor((duration - GENESIS_DELAY_SECONDS) / SLOT_SECONDS))
}

export default function App() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [runs, setRuns] = useState<RunSummary[]>([])
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [runPickerOpen, setRunPickerOpen] = useState(false)
  const [run, setRun] = useState<RunDetail | null>(null)
  const [slots, setSlots] = useState<SlotSummary[]>([])
  const [selectedSlot, setSelectedSlot] = useState<number | null>(null)
  const [slotDetail, setSlotDetail] = useState<SlotDetail | null>(null)
  const [events, setEvents] = useState<EventRow[]>([])
  const [eventKind, setEventKind] = useState('all')
  const [chain, setChain] = useState<ChainPeer[]>([])
  const [chainSlots, setChainSlots] = useState<number[]>([])
  const [selectedChainSlot, setSelectedChainSlot] = useState<number | null>(null)
  const [displayedChainSlot, setDisplayedChainSlot] = useState<number | null>(null)
  const [drawerTab, setDrawerTab] = useState<'overview' | 'prop' | 'chain' | 'config' | 'files'>(
    'overview'
  )
  const [nodeDownload, setNodeDownload] = useState('')
  const [refreshToken, setRefreshToken] = useState(0)

  const refreshStats = useCallback(async () => {
    const [statsData, runsData] = await Promise.all([
      api<DashboardStats>('/api/stats'),
      api<RunSummary[]>('/api/runs?limit=100')
    ])
    setStats(statsData)
    setRuns(runsData)
    if (!selectedRunId && runsData.length > 0) {
      setSelectedRunId(runsData[0].run_id)
    }
  }, [selectedRunId])

  useEffect(() => {
    refreshStats().catch(console.error)
    const interval = window.setInterval(() => refreshStats().catch(console.error), 2500)
    return () => window.clearInterval(interval)
  }, [refreshStats, refreshToken])

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws`)
    socket.onmessage = () => setRefreshToken((value) => value + 1)
    return () => socket.close()
  }, [])

  useEffect(() => {
    if (!selectedRunId) return
    Promise.all([
      api<RunDetail>(`/api/run/${selectedRunId}`),
      api<{ slots: SlotSummary[] }>(`/api/run/${selectedRunId}/slots`)
    ])
      .then(([runData, slotData]) => {
        setRun(runData)
        setSlots(slotData.slots)
        const currentSlot = runData.current_slot
        const blockSlot = slotData.slots.find(
          (slot) => (slot.block_count ?? 0) > 0 || (slot.n_received ?? 0) > 0
        )?.slot
        const nextSlot =
          slotData.slots.find((slot) => slot.slot === currentSlot)?.slot ??
          blockSlot ??
          slotData.slots[0]?.slot ??
          currentSlot ??
          0
        setSelectedSlot((previous) =>
          previous != null && slotData.slots.some((slot) => slot.slot === previous)
            ? previous
            : nextSlot
        )
      })
      .catch(console.error)
  }, [selectedRunId, refreshToken])

  useEffect(() => {
    setChain([])
    setChainSlots([])
    setSelectedChainSlot(null)
    setDisplayedChainSlot(null)
  }, [selectedRunId])

  useEffect(() => {
    if (!selectedRunId) return
    const params = new URLSearchParams()
    if (selectedChainSlot != null) params.set('slot', String(selectedChainSlot))
    const suffix = params.size ? `?${params.toString()}` : ''
    api<ChainResponse>(`/api/run/${selectedRunId}/chain${suffix}`)
      .then((chainData) => {
        setChain(chainData.peers)
        setChainSlots(chainData.slots)
        setDisplayedChainSlot(chainData.selected_slot)
        setSelectedChainSlot((previous) => {
          if (!chainData.slots.length) return null
          const minSlot = Math.min(...chainData.slots)
          const maxSlot = Math.max(...chainData.slots)
          if (previous != null && previous >= minSlot && previous <= maxSlot) return previous
          return null
        })
        setNodeDownload((existing) => existing || chainData.peers[0]?.peer || '')
      })
      .catch(() => {
        setChain([])
        setChainSlots([])
        setDisplayedChainSlot(null)
      })
  }, [selectedRunId, selectedChainSlot, refreshToken])

  useEffect(() => {
    if (!selectedRunId) return
    const params = new URLSearchParams({ limit: '80' })
    if (eventKind !== 'all') params.set('kind', eventKind)
    api<EventRow[]>(`/api/run/${selectedRunId}/events?${params.toString()}`)
      .then(setEvents)
      .catch(() => setEvents([]))
  }, [selectedRunId, eventKind, refreshToken])

  useEffect(() => {
    if (!selectedRunId || selectedSlot == null) return
    api<SlotDetail>(`/api/run/${selectedRunId}/slot/${selectedSlot}`)
      .then(setSlotDetail)
      .catch(() => setSlotDetail(null))
  }, [selectedRunId, selectedSlot, refreshToken])

  const selectedSummary = runs.find((item) => item.run_id === selectedRunId) ?? run
  const progress = selectedSummary?.progress ?? 0
  const coverageData = useMemo<CoverageDatum[]>(() => {
    const coverageSlots = run?.stats?.attestations?.coverage?.slots ?? []
    return coverageSlots
      .slice(0, 24)
      .map((slot: any) => ({
        slot: `s${slot.slot}`,
        ms: slot.p95_nodes_to_95_attestations_ms ?? slot.max_nodes_to_95_attestations_ms,
        warning: Boolean(slot.warning)
      }))
      .filter((slot: CoverageDatum) => slot.ms != null)
  }, [run])
  const nodeCounts = objectEntries(run?.stats?.node_distribution?.clients)
  const regionCounts = objectEntries(run?.stats?.node_distribution?.regions)
  const bandwidthCounts = objectEntries(run?.stats?.node_distribution?.bandwidths)
  const duration = selectedSummary?.duration_secs ?? run?.metadata?.fuzzer?.duration_secs ?? 0
  const maxSlot = Math.max(maxChainSlotForDuration(duration), selectedSummary?.current_slot ?? 0, 0)
  const chainSlotMin = chainSlots.length ? Math.min(...chainSlots) : 0
  const chainSlotMax = chainSlots.length ? Math.max(...chainSlots) : 0
  const chainSlotValue = displayedChainSlot ?? chainSlotMax

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">SF</div>
          <div>
            <h1>Shadow Fuzzer Monitor</h1>
            <p>Live dashboard for --serve monitoring and historical run analysis</p>
          </div>
        </div>
        <div className="top-actions">
          <span className="pill live-dot">
            <span />
            Live
          </span>
          <div className="run-picker">
            <button className="pill picker-button" onClick={() => setRunPickerOpen(!runPickerOpen)}>
              Run {selectedSummary?.run_index != null ? selectedSummary.run_index + 1 : '--'}
              <ChevronDown size={14} />
            </button>
            {runPickerOpen && (
              <div className="run-menu">
                {runs.map((item) => (
                  <button
                    key={item.run_id}
                    className={clsx('run-menu-item', item.run_id === selectedRunId && 'selected')}
                    onClick={() => {
                      setSelectedRunId(item.run_id)
                      setRunPickerOpen(false)
                    }}
                  >
                    <span>
                      <strong>
                        Run {item.run_index != null ? item.run_index + 1 : '--'} · {item.run_id}
                      </strong>
                      <small>seed {item.seed ?? '--'} · slot {item.current_slot}</small>
                    </span>
                    <em className={statusClass(item.status)}>{item.status}</em>
                  </button>
                ))}
              </div>
            )}
          </div>
          <span className="pill">Port {window.location.port || '8000'}</span>
          <button className="icon-button" onClick={() => setRefreshToken((value) => value + 1)}>
            <RefreshCw size={17} />
          </button>
        </div>
      </header>

      <div className="dashboard">
        <main className="main-grid">
          <section className="card card-pad progress-card">
            <SectionTitle
              title="Simulation Progress"
              subtitle={selectedRunId ?? 'No run selected'}
              badge={selectedSummary?.status ?? 'idle'}
            />
            <div className="progress-layout">
              <div className="timer-panel">
                <div className="row spread muted">
                  <strong>Simulated time</strong>
                  <span>{Math.round(progress * 100)}% complete</span>
                </div>
                <div className="timer">
                  {formatDuration(selectedSummary?.simulated_seconds)}
                  <small>/ {formatDuration(duration)}</small>
                </div>
                <div className="progress-track">
                  <div style={{ width: `${Math.max(2, progress * 100)}%` }} />
                </div>
                <div
                  className="slot-strip"
                  aria-label="slot progress"
                  style={{
                    gridTemplateColumns: `repeat(${maxSlot + 1}, minmax(2px, 1fr))`
                  }}
                >
                  {Array.from({ length: maxSlot + 1 }, (_, index) => (
                    <button
                      key={index}
                      className={clsx(
                        'slot-tick',
                        index <= (selectedSummary?.current_slot ?? 0) && 'done',
                        index === selectedSlot && 'selected'
                      )}
                      onClick={() => setSelectedSlot(index)}
                      title={`slot ${index}`}
                    />
                  ))}
                </div>
                <div className="row spread muted">
                  <span>slot 0</span>
                  <span>slot {selectedSummary?.current_slot ?? 0}</span>
                  <span>slot {maxSlot}</span>
                </div>
              </div>
              <div className="metric-grid compact">
                <Metric label="Current slot" value={`${selectedSummary?.current_slot ?? 0} / ${maxSlot}`} />
                <Metric label="Wall clock" value={formatDuration(selectedSummary?.wall_seconds)} />
                <Metric
                  label="Effective speed"
                  value={
                    selectedSummary?.wall_seconds
                      ? `${((selectedSummary.simulated_seconds || 0) / selectedSummary.wall_seconds).toFixed(2)}x`
                      : '--'
                  }
                />
                <Metric label="Stop time" value={`${duration || '--'}s`} />
                <Metric label="Stage" value={selectedSummary?.stage ?? '--'} />
                <Metric label="Final status" value={selectedSummary?.status ?? '--'} />
              </div>
            </div>
          </section>

          <section className="card card-pad slot-inspector">
            <SectionTitle
              title="Slot Inspector"
              subtitle="select a concrete slot to inspect block propagation and slot stats"
              badge={selectedSlot == null ? undefined : `slot ${selectedSlot}`}
            />
            <div className="slot-buttons">
              {Array.from(
                new Set([
                  ...slots.map((slot) => slot.slot),
                  selectedSummary?.current_slot ?? 0,
                  selectedSlot ?? 0
                ])
              )
                .sort((a, b) => a - b)
                .slice(0, 64)
                .map((slot) => (
                  <button
                    key={slot}
                    className={clsx('slot-button', selectedSlot === slot && 'active')}
                    onClick={() => setSelectedSlot(slot)}
                  >
                    {slot}
                  </button>
                ))}
            </div>
            <div className="slot-detail-grid">
              <div className="panel">
                <div className="panel-heading">
                  <div>
                    <h3>Block Propagation CDF</h3>
                    <p>slot {selectedSlot ?? '--'}</p>
                  </div>
                  <code>{slotDetail?.block?.block_hash ? `0x${slotDetail.block.block_hash.slice(0, 10)}` : ''}</code>
                </div>
                {slotDetail?.state === 'conflict' ? (
                  <ConflictPanel detail={slotDetail} />
                ) : slotDetail?.state === 'ok' && slotDetail.cdf?.length ? (
                  <>
                    <div className="chart-box">
                      <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={slotDetail.cdf}>
                          <CartesianGrid stroke="#e5eaf3" />
                          <XAxis
                            dataKey="latency_ms"
                            type="number"
                            domain={[0, 'dataMax']}
                            tickFormatter={(value) => `${value}ms`}
                            tick={{ fontSize: 11 }}
                          />
                          <YAxis domain={[0, 100]} tickFormatter={(value) => `${value}%`} tick={{ fontSize: 11 }} />
                          <Tooltip formatter={(value) => `${value}%`} labelFormatter={(value) => `${value}ms`} />
                          <Line
                            type="stepAfter"
                            dataKey="percent"
                            stroke="#2563eb"
                            strokeWidth={3}
                            dot={{ r: 3 }}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="muted">
                      {slotDetail.slot_stats?.n_received ?? 0} / {slotDetail.slot_stats?.nodes ?? 0} nodes
                      received the slot {selectedSlot} block.
                    </p>
                  </>
                ) : (
                  <EmptyState message={slotDetail?.error ?? 'No propagation data for this slot yet.'} />
                )}
              </div>
              <div className="panel">
                <div className="panel-heading">
                  <div>
                    <h3>Slot Stats</h3>
                    <p>single block assumption</p>
                  </div>
                  <code>{slotDetail?.block_count ?? 0} block</code>
                </div>
                <div className="metric-grid">
                  <Metric label="Proposer" value={slotDetail?.slot_stats?.proposer ?? '--'} />
                  <Metric label="Published" value={msValue(slotDetail?.slot_stats?.published_ms)} />
                  <Metric label="First receive" value={msValue(slotDetail?.slot_stats?.first_receive_ms)} />
                  <Metric label="Nodes received" value={`${slotDetail?.slot_stats?.n_received ?? 0} / ${slotDetail?.slot_stats?.nodes ?? 0}`} />
                  <Metric label="CDF p50" value={msValue(slotDetail?.slot_stats?.cdf_p50_ms)} />
                  <Metric label="CDF p95" value={msValue(slotDetail?.slot_stats?.cdf_p95_ms)} />
                  <Metric label="Max receive" value={msValue(slotDetail?.slot_stats?.last_receive_ms)} />
                  <Metric
                    label="Attestation coverage"
                    value={
                      slotDetail?.slot_stats?.attestation_coverage
                        ? `${slotDetail.slot_stats.attestation_coverage.n_nodes_reached_threshold}/${slotDetail.slot_stats.attestation_coverage.n_nodes}`
                        : '--'
                    }
                  />
                </div>
              </div>
            </div>
          </section>

          <section className="card card-pad">
            <SectionTitle title="Attestation Coverage By Slot" subtitle="p95, or max reached when p95 is unavailable" />
            {coverageData.length ? (
              <div className="chart-box short">
                <ResponsiveContainer width="100%" height={230}>
                  <BarChart data={coverageData}>
                    <CartesianGrid vertical={false} stroke="#e5eaf3" />
                    <XAxis dataKey="slot" tick={{ fontSize: 11 }} />
                    <YAxis tick={{ fontSize: 11 }} />
                    <Tooltip formatter={(value) => `${value}ms`} />
                    <Bar dataKey="ms" radius={[4, 4, 0, 0]}>
                      {coverageData.map((entry, index) => (
                        <Cell key={entry.slot} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState message="Coverage appears after attestation events are indexed." />
            )}
          </section>

          <section className="card card-pad">
            <SectionTitle title="Block And Chain Health" subtitle="latest complete stats snapshot" badge={healthBadge(run)} />
            <div className="metric-grid">
              <Metric label="Published blocks" value={run?.stats?.blocks?.summary?.n_published ?? 0} />
              <Metric label="Received blocks" value={run?.stats?.blocks?.summary?.n_received ?? 0} />
              <Metric label="Chain slots" value={run?.stats?.chain_status?.summary?.slots_with_data ?? 0} />
              <Metric label="Hosts with status" value={run?.stats?.chain_status?.summary?.hosts_with_data ?? 0} />
            </div>
            {run?.warnings?.length ? (
              <div className="warning-box">
                <AlertTriangle size={16} />
                <span>{run.warnings[0]}</span>
              </div>
            ) : null}
          </section>

          <section className="card card-pad events-card">
            <SectionTitle
              title="Run Events"
              subtitle={selectedRunId ?? 'select a run'}
              badge={`${events.length} rows`}
            />
            <div className="filter-row">
              {EVENT_KINDS.map(([kind, label]) => (
                <button
                  key={kind}
                  className={clsx('filter-chip', eventKind === kind && 'active')}
                  onClick={() => setEventKind(kind)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="event-list">
              {events.length ? (
                events.map((event) => (
                  <div key={event.id} className="event-row">
                    <code>{formatDuration(event.ts_ms / 1000)}</code>
                    <strong>{event.kind.replace(/_/g, ' ')}</strong>
                    <span>{event.message}</span>
                    <em>{event.host ?? 'system'}{event.slot != null ? ` · slot ${event.slot}` : ''}</em>
                  </div>
                ))
              ) : (
                <EmptyState message="No events match the current filter." />
              )}
            </div>
          </section>
        </main>

        <aside className="side">
          <section className="card card-pad drawer-card">
            <SectionTitle
              title="Run Detail Drawer"
              subtitle={selectedRunId ?? 'No run selected'}
              badge={selectedSummary?.status}
            />
            <div className="tabs">
              {(['overview', 'prop', 'chain', 'config', 'files'] as const).map((tab) => (
                <button
                  key={tab}
                  className={clsx(drawerTab === tab && 'active')}
                  onClick={() => setDrawerTab(tab)}
                >
                  {tab}
                </button>
              ))}
            </div>
            {drawerTab === 'overview' && (
              <div className="drawer-pane">
                <KeyValues
                  rows={[
                    ['Status', selectedSummary?.status ?? '--'],
                    ['Runner', run?.metadata?.fuzzer?.runner ?? '--'],
                    ['Run index', selectedSummary?.run_index ?? '--'],
                    ['Seed', selectedSummary?.seed ?? '--'],
                    ['Duration', `${duration || '--'}s`],
                    ['Total nodes', run?.metadata?.simulation?.total_nodes ?? '--'],
                    ['Subnets', run?.metadata?.simulation?.total_subnets ?? '--'],
                    ['Aggregators', run?.metadata?.simulation?.aggregators_per_subnet ?? '--']
                  ]}
                />
                <DistributionPanel title="Node Distribution" data={nodeCounts} />
                <BarList title="Region Distribution" subtitle="Sampled peer locations for this run." data={regionCounts} />
                <BarList title="Bandwidth Tiers" subtitle="Sampled per-node bandwidth tier counts." data={bandwidthCounts} />
              </div>
            )}
            {drawerTab === 'prop' && (
              <div className="drawer-pane">
                <KeyValues
                  rows={[
                    ['Attestation slots', run?.stats?.attestations?.coverage?.summary?.slots_with_data ?? 0],
                    ['Median p50', msValue(run?.stats?.attestations?.coverage?.summary?.median_slot_p50_nodes_to_95_attestations_ms)],
                    ['Median p90', msValue(run?.stats?.attestations?.coverage?.summary?.median_slot_p90_nodes_to_95_attestations_ms)],
                    ['Median p95', msValue(run?.stats?.attestations?.coverage?.summary?.median_slot_p95_nodes_to_95_attestations_ms)],
                    ['Block slots', run?.stats?.blocks?.summary?.n_published ?? 0],
                    ['Events indexed', events.length]
                  ]}
                />
                <EventCountList counts={run?.stats?.event_counts ?? {}} />
              </div>
            )}
            {drawerTab === 'chain' && (
              <div className="drawer-pane">
                {chainSlots.length ? (
                  <div className="chain-slot-selector">
                    <div className="selector-head">
                      <span>Chain status at slot</span>
                      <strong>{selectedChainSlot == null ? 'latest' : `slot ${chainSlotValue}`}</strong>
                    </div>
                    <input
                      type="range"
                      min={chainSlotMin}
                      max={chainSlotMax}
                      value={chainSlotValue}
                      onChange={(event) => setSelectedChainSlot(Number(event.target.value))}
                    />
                    <div className="chain-slot-labels">
                      <span>slot {chainSlotMin}</span>
                      <span>{chain.length ? `${chain.length} peers reported` : 'no peer reports yet'}</span>
                      <span>slot {chainSlotMax}</span>
                    </div>
                    {selectedChainSlot != null ? (
                      <button className="chain-latest-button" onClick={() => setSelectedChainSlot(null)}>
                        Follow latest
                      </button>
                    ) : null}
                  </div>
                ) : null}
                <div className="peer-table">
                  <div className="peer-row header">
                    <span>Peer</span>
                    <span>Head</span>
                    <span>Justified</span>
                    <span>Finalized</span>
                  </div>
                  {chain.length ? (
                    chain.map((peer) => (
                      <div key={peer.peer} className="peer-row">
                        <strong>{peer.peer}</strong>
                        <span>{peer.head_slot ?? '--'}</span>
                        <span>{peer.justified_slot ?? '--'}</span>
                        <span>{peer.finalized_slot ?? '--'}</span>
                      </div>
                    ))
                  ) : (
                    <EmptyState message="No chain status rows are available at this slot yet." />
                  )}
                </div>
              </div>
            )}
            {drawerTab === 'config' && (
              <div className="drawer-pane">
                <pre className="json-view">{JSON.stringify(run?.metadata ?? {}, null, 2)}</pre>
              </div>
            )}
            {drawerTab === 'files' && (
              <div className="drawer-pane">
                <a className="download-row" href={selectedRunId ? `/api/run/${selectedRunId}/shadow.yaml` : '#'}>
                  <FileJson size={18} />
                  <span>
                    <strong>Download shadow.yaml</strong>
                    <small>{selectedRunId}/shadow.yaml</small>
                  </span>
                  <Download size={16} />
                </a>
                <a className="download-row" href={selectedRunId ? `/api/run/${selectedRunId}/logs.zip` : '#'}>
                  <Server size={18} />
                  <span>
                    <strong>Download all logs</strong>
                    <small>{selectedRunId}/shadow.data.zip</small>
                  </span>
                  <Download size={16} />
                </a>
                <div className="node-download">
                  <select value={nodeDownload} onChange={(event) => setNodeDownload(event.target.value)}>
                    {chain.map((peer) => (
                      <option key={peer.peer} value={peer.peer}>
                        {peer.peer}
                      </option>
                    ))}
                  </select>
                  <a
                    className="download-button"
                    href={selectedRunId && nodeDownload ? `/api/run/${selectedRunId}/node/${nodeDownload}/logs.zip` : '#'}
                  >
                    <Download size={16} />
                    Node logs
                  </a>
                </div>
              </div>
            )}
          </section>
        </aside>
      </div>
      <footer>Dashboard data is backed by output_dir/runs.db and per-run Shadow artifacts.</footer>
    </div>
  )
}

function SectionTitle({ title, subtitle, badge }: { title: string; subtitle?: string; badge?: string }) {
  return (
    <div className="section-title">
      <div>
        <h2>{title}</h2>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {badge ? <span className={clsx('status-badge', statusClass(badge))}>{badge}</span> : null}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: any }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="empty-state">
      <Activity size={18} />
      <span>{message}</span>
    </div>
  )
}

function ConflictPanel({ detail }: { detail: SlotDetail }) {
  return (
    <div className="conflict-panel">
      <AlertTriangle size={20} />
      <div>
        <strong>{detail.error}</strong>
        {(detail.blocks ?? []).map((block) => (
          <p key={block.block_id}>
            {block.block_hash ? `0x${String(block.block_hash).slice(0, 12)}` : block.block_id} ·{' '}
            {block.host_count ?? 0} hosts · proposer {block.proposer ?? '--'}
          </p>
        ))}
      </div>
    </div>
  )
}

function KeyValues({ rows }: { rows: Array<[string, any]> }) {
  return (
    <div className="kv-list">
      {rows.map(([key, value]) => (
        <div key={key}>
          <span>{key}</span>
          <strong>{String(value)}</strong>
        </div>
      ))}
    </div>
  )
}

function DistributionPanel({ title, data }: { title: string; data: Array<{ name: string; value: number }> }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  return (
    <div className="overview-section">
      <h3>{title}</h3>
      {data.length ? (
        <div className="donut-row">
          <ResponsiveContainer width={132} height={132}>
            <PieChart>
              <Pie data={data} dataKey="value" innerRadius={42} outerRadius={60} strokeWidth={0}>
                {data.map((item, index) => (
                  <Cell key={item.name} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="legend-list">
            {data.map((item, index) => (
              <div key={item.name}>
                <span style={{ background: COLORS[index % COLORS.length] }} />
                <strong>{item.name}</strong>
                <em>{item.value} nodes</em>
              </div>
            ))}
            <small>{total} total nodes</small>
          </div>
        </div>
      ) : (
        <EmptyState message="No node distribution data yet." />
      )}
    </div>
  )
}

function BarList({
  title,
  subtitle,
  data
}: {
  title: string
  subtitle: string
  data: Array<{ name: string; value: number }>
}) {
  const total = Math.max(1, data.reduce((sum, item) => sum + item.value, 0))
  return (
    <div className="overview-section">
      <h3>{title}</h3>
      <p>{subtitle}</p>
      {data.length ? (
        data.map((item, index) => (
          <div className="bar-row" key={item.name}>
            <span>{item.name}</span>
            <div>
              <i style={{ width: `${(item.value / total) * 100}%`, background: COLORS[index % COLORS.length] }} />
            </div>
            <strong>{item.value}</strong>
          </div>
        ))
      ) : (
        <EmptyState message="No samples recorded." />
      )}
    </div>
  )
}

function EventCountList({ counts }: { counts: Record<string, any> }) {
  const rows = Object.entries(counts).map(([name, value]) => ({
    name,
    count: Number((value as any)?.total ?? 0)
  }))
  return (
    <div className="overview-section">
      <h3>Parser Event Counts</h3>
      {rows.length ? (
        rows.map((row) => (
          <div className="count-row" key={row.name}>
            <span>{row.name.replace(/_/g, ' ')}</span>
            <strong>{row.count}</strong>
          </div>
        ))
      ) : (
        <EmptyState message="No parser event counts yet." />
      )}
    </div>
  )
}

function msValue(value: any) {
  if (value == null || value === '--') return '--'
  const num = Number(value)
  if (!Number.isFinite(num)) return String(value)
  return `${num.toFixed(num >= 100 ? 0 : 1)}ms`
}

function healthBadge(run: RunDetail | null) {
  if (!run) return 'waiting'
  if (run.status === 'error') return 'error'
  if (run.warnings?.length) return 'warning'
  if (terminalStatus(run.status)) return 'healthy'
  return 'running'
}
