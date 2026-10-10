import Link from 'next/link';

export function Sidebar() {
  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/40 backdrop-blur-md flex flex-col h-screen sticky top-0">
      <div className="h-16 flex items-center px-6 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 glow-text">
          CIPHER01
        </h1>
      </div>
      <nav className="flex-1 p-4 space-y-2">
        <Link href="/" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Dashboard
        </Link>
        <Link href="/firewall" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Firewall Live
        </Link>
        <Link href="/scanner" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Request Scanner
        </Link>
        <Link href="/analytics" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Analytics
        </Link>
        <Link href="/policies" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Policies
        </Link>
        <Link href="/redteam" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Red Team Labs
        </Link>
        <Link href="/evaluation" className="block px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-md transition-colors">
          Evaluation Lab
        </Link>
      </nav>
      <div className="p-4 border-t border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse" />
          <span className="text-xs text-slate-400 font-medium">System Online</span>
        </div>
      </div>
    </aside>
  );
}
