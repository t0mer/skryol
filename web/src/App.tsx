import { Routes, Route } from "react-router-dom";
import { AuthGate } from "./components/AuthGate";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Assets } from "./pages/Assets";
import { AssetDetail } from "./pages/AssetDetail";
import { Compare } from "./pages/Compare";
import { Alerts } from "./pages/Alerts";
import { SettingsPage } from "./pages/Settings";

export default function App() {
  return (
    <AuthGate>
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/assets/:id" element={<AssetDetail />} />
        <Route path="/assets/:id/compare" element={<Compare />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Layout>
    </AuthGate>
  );
}
