import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'

type ReportFile = {
  path: string
  count: number
  lines: number[]
  line_ranges: string[]
  first_timestamp: string | null
  last_timestamp: string | null
  samples: { line: number; text: string }[]
}

type Category = { category: string; severity: string; impact?: string; description?: string; total: number; files: ReportFile[] }
type Impact = { impact: string; severity: string; total: number; categories: string[] }
type Report = {
  source: string
  platform: string
  files_scanned: string[]
  files_skipped: { path: string; reason: string }[]
  notes: string[]
  impacts?: Impact[]
  categories: Category[]
}

type Tab = 'categories' | 'files' | 'notes'
const MAX_UPLOAD = 200 * 1024 * 1024

function download(report: Report, format: 'json' | 'csv') {
  let content: string
  if (format === 'json') {
    content = JSON.stringify(report, null, 2)
  } else {
    const cell = (value: string | number) => {
      const text = String(value)
      return '"' + (/^[\s=+@\-\u0000-\u001f]/.test(text) ? "'" + text : text).replaceAll('"', '""') + '"'
    }
    const rows: (string | number)[][] = [['category', 'severity', 'path', 'line', 'text', 'impact']]
    report.categories.forEach(category => category.files.forEach(file => file.samples.forEach(sample => {
      rows.push([category.category, category.severity, file.path, sample.line, sample.text, category.impact || ''])
    })))
    content = rows.map(row => row.map(cell).join(',')).join('\r\n') + '\r\n'
  }
  const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `support-info-report.${format}`
  anchor.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function CategoryDetails({ category }: { category: Category }) {
  return (
    <details className="category">
      <summary className="category-summary">
        <span className="min-w-0 flex-1 font-semibold">{category.category}</span>
        {category.impact && <span className="tag">{category.impact}</span>}
        <span className={`severity severity-${category.severity}`}>{category.severity || 'unspecified'}</span>
        <span className="min-w-12 text-right font-mono font-semibold">{category.total.toLocaleString()}</span>
      </summary>
      <div className="space-y-4 border-t border-slate-200 bg-slate-50 p-4 sm:p-6">
        {category.description && <p className="text-sm leading-relaxed text-slate-600">{category.description}</p>}
        {category.files.map(file => (
          <article className="rounded-lg border border-slate-200 bg-white p-4" key={file.path}>
            <div className="flex flex-wrap items-start justify-between gap-2">
              <h3 className="min-w-0 break-all font-mono text-sm font-semibold">{file.path}</h3>
              <span className="text-sm text-slate-500">{file.count.toLocaleString()} matches</span>
            </div>
            <p className="mt-3 break-words text-sm text-slate-600">Lines: {file.line_ranges.join(', ')}</p>
            <p className="mt-1 text-sm text-slate-500">{file.first_timestamp ? `${file.first_timestamp} → ${file.last_timestamp}` : 'No timestamps found'}</p>
            <details className="mt-4">
              <summary className="cursor-pointer text-sm font-semibold text-teal-800">Sample lines ({file.samples.length.toLocaleString()})</summary>
              <div className="sample-list mt-3">
                {file.samples.map((sample, index) => <div className="sample-row" key={index}><span className="select-none text-slate-500">{sample.line}</span><code>{sample.text}</code></div>)}
              </div>
            </details>
          </article>
        ))}
      </div>
    </details>
  )
}

function Results({ report }: { report: Report }) {
  const [tab, setTab] = useState<Tab>('categories')
  const total = report.categories.reduce((sum, category) => sum + category.total, 0)
  return (
    <section aria-label="Report results" className="mt-10" aria-live="polite">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div><p className="eyebrow">REPORT</p><h2 className="break-all">{report.source}</h2></div>
        <div className="flex gap-2"><button className="button-secondary" onClick={() => download(report, 'json')}>Download JSON</button><button className="button-secondary" onClick={() => download(report, 'csv')}>Download CSV</button></div>
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[['Platform', report.platform], ['Files scanned', report.files_scanned.length.toLocaleString()], ['Files skipped', report.files_skipped.length.toLocaleString()], ['Error matches', total.toLocaleString()]].map(([label, value]) => (
          <div className="metric" key={label}><p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p><p className="mt-2 text-2xl font-semibold capitalize">{value}</p></div>
        ))}
      </div>
      {!!report.impacts?.length && <div className="panel mt-5">
        <h3 className="font-semibold">Impact areas</h3>
        <p className="mt-1 text-sm text-slate-500">Findings grouped by the part of the endpoint they affect, highest severity first.</p>
        <ul aria-label="Impact areas" className="mt-4 grid gap-3 sm:grid-cols-2">
          {report.impacts.map(impact => (
            <li className="impact" key={impact.impact}>
              <div className="flex items-center gap-3"><span className="min-w-0 flex-1 font-semibold">{impact.impact}</span><span className={`severity severity-${impact.severity}`}>{impact.severity || 'unspecified'}</span><span className="font-mono font-semibold">{impact.total.toLocaleString()}</span></div>
              <p className="mt-2 text-sm text-slate-500">{impact.categories.join(' · ')}</p>
            </li>
          ))}
        </ul>
      </div>}
      <div className="panel mt-5 !p-0 overflow-hidden">
        <div className="flex gap-1 overflow-x-auto border-b border-slate-200 px-4" role="group" aria-label="Report sections">
          {([['categories', `Categories (${report.categories.length})`], ['files', 'Files'], ['notes', `Notes (${report.notes.length})`]] as const).map(([value, label]) => (
            <button key={value} aria-pressed={tab === value} className={`tab ${tab === value ? 'tab-active' : ''}`} onClick={() => setTab(value)}>{label}</button>
          ))}
        </div>
        {tab === 'categories' && <div className="p-4 sm:p-6">
          <p className="mb-4 text-sm text-slate-500">Ordered by match count. Expand a category to inspect its files and matching lines.</p>
          {report.categories.length ? <div className="space-y-3">{report.categories.map(category => <CategoryDetails key={category.category} category={category} />)}</div> : <p className="empty-state">No matching errors found in the scanned files. Review skipped files before drawing conclusions.</p>}
        </div>}
        {tab === 'files' && <div className="space-y-8 p-4 sm:p-6">
          <div><h3 className="mb-3 font-semibold">Skipped files · {report.files_skipped.length}</h3>{report.files_skipped.length ? <ul className="divide-y divide-slate-200">{report.files_skipped.map((file, index) => <li className="py-3" key={index}><p className="break-all font-mono text-sm">{file.path}</p><p className="mt-1 text-sm text-slate-500">{file.reason}</p></li>)}</ul> : <p className="text-sm text-slate-500">No files skipped.</p>}</div>
          <div><h3 className="mb-3 font-semibold">Scanned files · {report.files_scanned.length}</h3><ul className="space-y-2">{report.files_scanned.map((path, index) => <li className="break-all font-mono text-sm text-slate-600" key={index}>{path}</li>)}</ul></div>
        </div>}
        {tab === 'notes' && <div className="p-4 sm:p-6">{report.notes.length ? <ul className="list-inside list-disc space-y-3 text-sm text-slate-600">{report.notes.map((note, index) => <li key={index}>{note}</li>)}</ul> : <p className="text-sm text-slate-500">No additional notes for this report.</p>}</div>}
      </div>
      <p className="mt-4 text-xs leading-relaxed text-slate-500">Counts reflect the analyzer's error patterns, not a complete assessment of package health. Binary log support depends on the tools installed on this computer.</p>
    </section>
  )
}

export function SupportInfo() {
  const [file, setFile] = useState<File | null>(null)
  const [platform, setPlatform] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState<Report | null>(null)

  function choose(next: File | null) {
    setError('')
    setReport(null)
    if (next && (!/\.(zip|tar|tar\.gz)$/i.test(next.name) || !next.size || next.size >= MAX_UPLOAD)) {
      setFile(null)
      setError('Choose a non-empty .zip, .tar, or .tar.gz archive smaller than 200 MB.')
      return
    }
    setFile(next)
  }

  async function analyze(event: FormEvent) {
    event.preventDefault()
    if (!file || busy) return
    setBusy(true)
    setError('')
    setReport(null)
    try {
      const body = new FormData()
      body.append('file', file)
      body.append('platform', platform)
      const response = await fetch('/api/analyze', { method: 'POST', body })
      const data = await response.json().catch(() => { throw new Error('Cannot reach the analyzer. Start the Python server and try again.') })
      if (!response.ok) throw new Error(data.error || 'Analysis failed. Try again.')
      if (!Array.isArray(data.categories) || !Array.isArray(data.files_scanned) || !Array.isArray(data.files_skipped)) throw new Error('The server returned an invalid report.')
      setReport(data)
    } catch (cause) {
      setError(cause instanceof Error && cause.message !== 'Failed to fetch' ? cause.message : 'Cannot reach the analyzer. Start the Python server and try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Link to="/" className="mb-7 inline-flex text-sm font-medium text-slate-500 hover:text-teal-800">← All tools</Link>
      <div className="page-heading">
        <p className="eyebrow">SUPPORT PACKAGE ANALYSIS</p><h1>Support Info</h1>
        <p className="lead">Find recurring errors and conditions that affect the endpoint. Trace every match back to its source.</p>
      </div>
      <form onSubmit={analyze} className="panel" aria-busy={busy}>
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3"><div><h2>Load a support package</h2><p className="mt-1 text-sm text-slate-500">Use a decrypted archive from Windows, macOS, or Linux.</p></div><span className="tag">UP TO 200 MB</span></div>
        <label className={`dropzone ${dragging ? 'dropzone-active' : ''} ${busy ? 'opacity-60' : ''}`}
          onDragOver={event => { event.preventDefault(); if (!busy) setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={event => { event.preventDefault(); setDragging(false); if (!busy) { if (event.dataTransfer.files.length !== 1) { setError('Choose one archive at a time.'); return } choose(event.dataTransfer.files[0]) } }}>
          <input type="file" accept=".zip,.tar,.tar.gz" disabled={busy} aria-label="Support-info archive" onChange={event => choose(event.target.files?.[0] || null)} />
          <span aria-hidden="true" className="mb-3 text-3xl text-teal-700">↥</span>
          <span className="break-all text-center font-semibold">{file ? file.name : 'Drop your support-info archive here'}</span>
          <span className="mt-2 text-center text-sm text-slate-500">{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB · Click to replace` : 'or click to browse · .zip, .tar, .tar.gz'}</span>
        </label>
        <div className="mt-6 flex flex-wrap items-end justify-between gap-5">
          <label className="flex w-full max-w-xs flex-col gap-2 text-sm font-medium" htmlFor="platform">Platform<select id="platform" value={platform} disabled={busy} onChange={event => { setPlatform(event.target.value); setReport(null) }}><option value="auto">Auto-detect</option><option value="windows">Windows</option><option value="macos">macOS</option><option value="linux">Linux</option></select></label>
          <button className="button-primary" type="submit" disabled={!file || busy}>{busy && <span className="spinner" aria-hidden="true" />}{busy ? 'Analyzing package…' : 'Analyze package'}{!busy && <span aria-hidden="true">→</span>}</button>
        </div>
        <p className="mt-5 text-xs leading-relaxed text-slate-500">The archive is processed by your local Python server and removed after analysis. Reports are not saved automatically.</p>
        {busy && <p role="status" className="mt-4 text-sm text-teal-800">Scanning logs and counting matching errors. Large archives may take a few minutes.</p>}
        {error && <div role="alert" className="mt-5 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error}</div>}
      </form>
      {report && <Results report={report} />}
    </>
  )
}
