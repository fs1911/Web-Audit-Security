import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WebAudit Security",
  description: "Technische Sicherheitsprüfung eigener Websites im freigegebenen Umfang",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="de-CH">
      <body>{children}</body>
    </html>
  );
}
