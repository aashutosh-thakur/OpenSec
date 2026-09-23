import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Landing from './pages/Landing';
import AttackSurface from './pages/AttackSurface';
import Dashboard from './pages/Dashboard';
import Vulnerabilities from './pages/Vulnerabilities';
import Scans from './pages/Scans';
import ScanReport from './pages/ScanReport';
import Reports from './pages/Reports';
import RiskPage from './pages/RiskPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"               element={<Landing />} />
        <Route path="/dashboard"      element={<Dashboard />} />
        <Route path="/attack-surface" element={<AttackSurface />} />
        <Route path="/scans"          element={<Scans />} />
        <Route path="/scans/:id"      element={<ScanReport />} />
        <Route path="/scans/:id/risk" element={<RiskPage />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/reports"        element={<Reports />} />

        {/* Catch-all */}
        <Route path="/settings"       element={<Navigate to="/dashboard" replace />} />
        <Route path="*"               element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

