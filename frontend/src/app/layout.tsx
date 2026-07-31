import React from "react";
import "./globals.css";

export const metadata = {
  title: "AI Code Guardian",
  description: "Multi-language, UST-driven, evidence-grounded code analysis platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="text-slate-100 font-sans antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
