import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Link, NavLink, Route, Routes } from 'react-router-dom'
import { SupportInfo } from './support-info'
import './style.css'

function Home() {
  return (
    <>
      <div className="page-heading">
        <p className="eyebrow">WORKSPACE</p>
        <h1>Support tools</h1>
        <p className="lead">From support package to a clear view of the errors.</p>
      </div>
      <Link to="/tools/support-info" className="tool-card group">
        <div className="flex items-start justify-between">
          <span className="tool-icon" aria-hidden="true">▤</span>
          <span className="tag">LOCAL ANALYSIS</span>
        </div>
        <h2>Support Info</h2>
        <p>Load a decrypted Windows, macOS, or Linux support-info zip and see error counts, files, and sample lines.</p>
        <span className="mt-8 inline-flex items-center gap-3 font-semibold text-teal-800">Open tool <span aria-hidden="true" className="transition-transform group-hover:translate-x-1">→</span></span>
      </Link>
      <div className="mt-10 flex flex-wrap gap-6 text-sm text-slate-500">
        <span>Windows · macOS · Linux</span><span>No sign-in required</span><span>Reports stay in this browser until downloaded</span>
      </div>
    </>
  )
}

function App() {
  return (
    <div className="min-h-screen">
      <header className="app-header">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-5 px-6 py-5">
          <Link to="/" className="flex items-center gap-3 font-semibold tracking-tight">
            <span className="brand-mark" aria-hidden="true">E</span>
            <span>EPM Support Analyzer</span>
          </Link>
          <nav aria-label="Main navigation" className="flex items-center gap-6 text-sm">
            <NavLink to="/" end className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>Tools</NavLink>
            <NavLink to="/tools/support-info" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>Support Info</NavLink>
            <span className="hidden items-center gap-2 text-slate-500 sm:flex"><span className="h-2 w-2 rounded-full bg-teal-600" />Local workspace</span>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-10 sm:py-14">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/tools/support-info" element={<SupportInfo />} />
          <Route path="*" element={<div className="panel"><h1>Page not found</h1><Link className="text-teal-800 underline" to="/">Return to tools</Link></div>} />
        </Routes>
      </main>
      <footer className="mx-auto max-w-6xl px-6 pb-8 pt-6 text-xs text-slate-500">EPM Support Analyzer · Local support package analysis</footer>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<StrictMode><BrowserRouter><App /></BrowserRouter></StrictMode>)
