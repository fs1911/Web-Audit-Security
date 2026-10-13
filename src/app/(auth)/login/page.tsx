import Link from "next/link";
import { loginAction } from "@/app/actions/auth";
import { ErrorFromQuery } from "@/components/ui";

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return (
    <main className="mx-auto mt-20 max-w-md space-y-6 px-4">
      <div>
        <h1 className="h1">WebAudit Security</h1>
        <p className="text-sm text-slate-600">Technische Sicherheitsprüfung eigener Websites im freigegebenen Umfang.</p>
      </div>
      <ErrorFromQuery error={error} />
      <form action={loginAction} className="card space-y-4">
        <div>
          <label className="label" htmlFor="email">E-Mail</label>
          <input className="input" id="email" name="email" type="email" autoComplete="username" required />
        </div>
        <div>
          <label className="label" htmlFor="password">Passwort</label>
          <input className="input" id="password" name="password" type="password" autoComplete="current-password" required />
        </div>
        <button className="btn w-full justify-center" type="submit">Anmelden</button>
      </form>
      <p className="text-center text-sm text-slate-600">
        Noch kein Konto? <Link className="text-blue-800 underline" href="/register">Registrieren</Link>
      </p>
    </main>
  );
}
