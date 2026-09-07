import "./globals.css";

export const metadata = {
  title: "Rappor Security controlled public target",
  description: "Synthetic, non-production security validation fixture.",
  generator: "Lovable",
  robots: { index: false, follow: false, archive: false },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
