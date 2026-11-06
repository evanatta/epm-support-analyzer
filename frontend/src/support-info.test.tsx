import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { SupportInfo } from './support-info'

const report = {
  source: 'support-info.zip',
  platform: 'windows',
  files_scanned: ['ProgramData/Agent/Logs/agent.log'],
  files_skipped: [{ path: 'Procmon/capture.pml', reason: 'Export to CSV' }],
  notes: ['Line numbers refer to the scanned log.'],
  impacts: [
    { impact: 'Server connectivity', severity: 'high', total: 3, categories: ['MQTT communication errors', 'TLS/certificate errors'] },
  ],
  categories: [{
    category: 'MQTT communication errors', severity: 'high', impact: 'Server connectivity',
    description: 'The agent cannot keep its server channel open.', total: 2,
    files: [{
      path: 'ProgramData/Agent/Logs/agent.log', count: 2, lines: [2, 3], line_ranges: ['2-3'],
      first_timestamp: '2026-01-01 09:00:01', last_timestamp: '2026-01-01 09:00:02',
      samples: [{ line: 2, text: 'ERROR MQTT connect refused' }, { line: 3, text: 'ERROR MQTT connect refused' }],
    }],
  }, { category: 'TLS/certificate errors', severity: 'medium', total: 1, files: [] }],
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function show() {
  render(<MemoryRouter><SupportInfo /></MemoryRouter>)
}

function choose(name = 'support-info.zip', content = 'archive') {
  fireEvent.change(screen.getByLabelText('Support-info archive'), { target: { files: [new File([content], name)] } })
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: 'Analyze package' }))
}

describe('Support Info', () => {
  it('starts with auto detection and requires an upload', () => {
    show()
    expect((screen.getByLabelText('Platform') as HTMLSelectElement).value).toBe('auto')
    expect((screen.getByRole('button', { name: 'Analyze package' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('rejects empty and unsupported files', () => {
    show()
    choose('support-info.txt')
    expect(screen.getByRole('alert').textContent).toContain('non-empty .zip')
    choose('support-info.zip', '')
    expect((screen.getByRole('button', { name: 'Analyze package' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('uploads the selected platform and presents the report without reordering categories', async () => {
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => report })
    vi.stubGlobal('fetch', fetch)
    show()
    choose()
    fireEvent.change(screen.getByLabelText('Platform'), { target: { value: 'windows' } })
    submit()
    await screen.findByRole('region', { name: 'Report results' })
    expect(fetch.mock.calls[0][0]).toBe('/api/analyze')
    const request = fetch.mock.calls[0][1]
    expect(request.method).toBe('POST')
    expect(request.body.get('platform')).toBe('windows')
    expect(request.body.get('file').name).toBe('support-info.zip')
    const categories = document.querySelectorAll('.category-summary')
    expect(categories[0].textContent).toContain('MQTT communication errors')
    expect(categories[1].textContent).toContain('TLS/certificate errors')
    expect(categories[0].textContent).toContain('Server connectivity')
    const impacts = screen.getByRole('list', { name: 'Impact areas' })
    expect(impacts.textContent).toContain('Server connectivity')
    expect(impacts.textContent).toContain('MQTT communication errors · TLS/certificate errors')
    expect(screen.getByText('The agent cannot keep its server channel open.')).toBeTruthy()
    expect(screen.getByText('Lines: 2-3')).toBeTruthy()
    expect(screen.getByText('2026-01-01 09:00:01 → 2026-01-01 09:00:02')).toBeTruthy()
    expect(screen.getAllByText('ERROR MQTT connect refused')).toHaveLength(2)
    expect(screen.getByRole('button', { name: 'Download JSON' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download CSV' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Files' }))
    expect(screen.getByText('Procmon/capture.pml')).toBeTruthy()
    expect(screen.getByText('Export to CSV')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Notes (1)' }))
    expect(screen.getByText('Line numbers refer to the scanned log.')).toBeTruthy()
  })

  it('shows a loading state and disables repeated requests', async () => {
    let resolve: (value: unknown) => void = () => {}
    vi.stubGlobal('fetch', vi.fn(() => new Promise(done => { resolve = done })))
    show()
    choose()
    submit()
    expect(screen.getByRole('status').textContent).toContain('Scanning logs')
    expect((screen.getByRole('button', { name: 'Analyzing package…' }) as HTMLButtonElement).disabled).toBe(true)
    resolve({ ok: true, json: async () => report })
    await screen.findByRole('region', { name: 'Report results' })
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('shows API errors without rendering a report', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, json: async () => ({ error: 'Archive is not readable.' }) }))
    show()
    choose()
    submit()
    expect((await screen.findByRole('alert')).textContent).toBe('Archive is not readable.')
    expect(screen.queryByRole('region', { name: 'Report results' })).toBeNull()
  })

  it('handles network failures and permits retrying', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    show()
    choose()
    submit()
    expect((await screen.findByRole('alert')).textContent).toContain('Start the Python server')
    await waitFor(() => expect((screen.getByRole('button', { name: 'Analyze package' }) as HTMLButtonElement).disabled).toBe(false))
  })

  it('displays an explicit empty report state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ...report, categories: [] }) }))
    show()
    choose()
    submit()
    expect(await screen.findByText(/No matching errors found/)).toBeTruthy()
  })

  it('renders reports without impact data', async () => {
    const older = { ...report, impacts: undefined, categories: [report.categories[1]] }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => older }))
    show()
    choose()
    submit()
    await screen.findByRole('region', { name: 'Report results' })
    expect(screen.queryByRole('list', { name: 'Impact areas' })).toBeNull()
    expect(document.querySelector('.category-summary .tag')).toBeNull()
  })

  it('accepts a dropped compressed TAR archive', () => {
    show()
    const file = new File(['archive'], 'support-info.tar.gz')
    const input = screen.getByLabelText('Support-info archive')
    fireEvent.drop(input.closest('label')!, { dataTransfer: { files: [file] } })
    expect(screen.getByText('support-info.tar.gz')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Analyze package' }) as HTMLButtonElement).disabled).toBe(false)
  })
})
