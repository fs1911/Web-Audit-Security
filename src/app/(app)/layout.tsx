import Link from "next/link";
import { requireUserAndOrg } from "@/lib/auth/current";
import { logoutAction } from "@/app/actions/auth";

export const dynamic = "force-dynamic";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, org } = await requireUserAndOrg();
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
          <Link href="/" className="font-semibold text-blue-900">WebAudit Security</Link>
          <nav className="flex flex-wrap gap-4 text-sm text-slate-700">
            <Link href="/">Dashboard</Link>
            <Link href="/sites/new">Website hinzufügen</Link>
            <Link href="/catalog">Prüfkatalog</Link>
            <Link href="/audit">Audit-Log</Link>
            <Link href="/settings">Einstellungen</Link>
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm text-slate-600">
            <span>{user.name} · {org.name} ({org.role})</span>
            <form action={logoutAction}>
              <button className="text-blue-800 underline" type="submit">Abmelden</button>
            </form>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6">{children}</main>
    </div>
  );
}
