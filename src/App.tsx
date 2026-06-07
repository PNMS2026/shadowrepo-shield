import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanHistory from "./pages/ScanHistory";
import ScanResult from "./pages/ScanResult";
import VerifyProof from "./pages/VerifyProof";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/result/:scanId" element={<ScanResult />} />
          <Route path="/verify" element={<VerifyProof />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
