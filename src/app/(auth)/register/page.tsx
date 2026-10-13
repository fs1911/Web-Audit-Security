import Link from "next/link";
import { registerAction } from "@/app/actions/auth";
import { ErrorFromQuery } from "@/components/ui";

export default async function RegisterPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return (
    <main className="mx-auto mt-16 max-w-md space-y-6 px-4">
      <div>
        <h1 className="h1">Konto erstellen</h1>
        <p className="text-sm text-slate-600">Mit dem Konto wird eine Organisation angelegt, in der Sie Eigentümer/in sind.</p>
      </div>
      <ErrorFromQuery error={error} />
      <form action={registerAction} className="card space-y-4">
        <div>
          <label className="label" htmlFor="name">Name</label>
          <input className="input" id="name" name="name" required maxLength={120} />
        </div>
        <div>
          <label className="label" htmlFor="orgName">Organisation</label>
          <input className="input" id="orgName" name="orgName" required maxLength={120} />
        </div>
        <div>
          <label className="label" htmlFor="email">E-Mail</label>
          <input className="input" id="email" name="email" type="email" autoComplete="username" required />
        </div>
        <div>
          <label className="label" htmlFor="password">Passwort</label>
          <input className="input" id="password" name="password" type="password" autoComplete="new-password" minLength={12} required />
          <p className="hint">Mindestens 12 Zeichen.</p>
        </div>
        <button className="btn w-full justify-center" type="submit">Konto erstellen</button>
      </form>
      <p className="text-center text-sm text-slate-600">
        Bereits registriert? <Link className="text-blue-800 underline" href="/login">Anmelden</Link>
      </p>
    </main>
  );
}
