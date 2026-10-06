import type { Metadata } from 'next';
import './globals.css';
import Navbar from '../components/navbar';

export const metadata: Metadata = {
  title: 'VibeSecure',
  description: 'Security for the AI-native software era: scan, understand attack paths, fix, and verify.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen text-slate-900 dark:text-slate-100 antialiased flex">
        {/* Left Sidepanel Navigation */}
        <Navbar />
        
        {/* Main Content Area */}
        <main className="flex-1 min-w-0 overflow-y-auto">
          {children}
        </main>
      </body>
    </html>
  );
}