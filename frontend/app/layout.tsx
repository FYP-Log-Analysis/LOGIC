import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LOGIC Web Agent",
  description: "Web server log forensics — ingest, analyse, and interpret access/error logs",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
