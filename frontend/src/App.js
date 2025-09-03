import React, { useState, useEffect, useCallback } from 'react';
import './App.css';

function App() {
  const [scenarios, setScenarios] = useState([]);
  const [status, setStatus] = useState({});
  const [loading, setLoading] = useState({});
  const [error, setError] = useState(null);

  const apiBaseUrl = 'http://localhost:5001';

  // Fetch all scenarios on initial load
  useEffect(() => {
    fetch(`${apiBaseUrl}/api/scenarios`)
      .then(res => res.json())
      .then(data => setScenarios(data))
      .catch(err => setError(`Failed to fetch scenarios: ${err.message}`));
  }, []);

  const handleAction = useCallback(async (scenarioId, action) => {
    setLoading(prev => ({ ...prev, [scenarioId]: true }));
    setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/scenarios/${scenarioId}/${action}`, { method: 'POST' });
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || `HTTP error! status: ${response.status}`);
      }
      // After an action, refresh the status
      handleStatusRefresh(scenarioId);
    } catch (err) {
      setError(`Action '${action}' failed for ${scenarioId}: ${err.message}`);
    } finally {
      setLoading(prev => ({ ...prev, [scenarioId]: false }));
    }
  }, []);

  const handleStatusRefresh = useCallback(async (scenarioId) => {
    setLoading(prev => ({ ...prev, [scenarioId]: true }));
    setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/scenarios/${scenarioId}/status`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setStatus(prev => ({ ...prev, [scenarioId]: data }));
    } catch (err) {
      setError(`Status refresh failed for ${scenarioId}: ${err.message}`);
    } finally {
      setLoading(prev => ({ ...prev, [scenarioId]: false }));
    }
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Academic Cyber Range</h1>
      </header>
      <main>
        <h2>Available Scenarios</h2>
        {error && <p className="error-message">Error: {error}</p>}
        <div className="scenarios-container">
          {scenarios.map(scenario => (
            <div key={scenario.id} className="scenario-card">
              <h3>{scenario.name}</h3>
              <p>{scenario.description}</p>

              <div className="actions">
                <button onClick={() => handleAction(scenario.id, 'start')} disabled={loading[scenario.id]}>
                  Start
                </button>
                <button onClick={() => handleAction(scenario.id, 'stop')} disabled={loading[scenario.id]}>
                  Stop
                </button>
                <button onClick={() => handleStatusRefresh(scenario.id)} disabled={loading[scenario.id]}>
                  {loading[scenario.id] ? 'Loading...' : 'Refresh Status'}
                </button>
              </div>

              {status[scenario.id] && (
                <div className="status">
                  <h4>Current Status: <span className={status[scenario.id].status}>{status[scenario.id].status}</span></h4>
                  {status[scenario.id].vms && status[scenario.id].vms.length > 0 && (
                    <div className="vm-list">
                      <h5>Virtual Machines:</h5>
                      <ul>
                        {status[scenario.id].vms.map(vm => (
                          <li key={vm.name}>
                            <strong>{vm.name}</strong> - State: {vm.state} - IP: {vm.ip}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}

export default App;
