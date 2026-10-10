import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Sidebar } from '@/components/layout/Sidebar';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'CIPHER01 | AI Firewall',
  description: 'Provider-Neutral AI Firewall Dashboard',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} min-h-screen flex`}>
        <Sidebar />
        <main className="flex-1 flex flex-col h-screen overflow-y-auto">
          {children}
        </main>
      </body>
    </html>
  );
}
