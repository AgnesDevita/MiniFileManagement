import React, { useState } from 'react';
import { User } from './types/document';
import { apiService } from './services/api';
import Dashboard from './components/Dashboard';

function App() {
  // Directly initialize with a hardcoded non-admin user
  const [user, setUser] = useState<User | null>({
    id: '2',
    email: 'user@dms.com',
    name: 'Regular User',
    role: 'user'
  });

  const handleLogout = () => {
    apiService.clearToken();
    setUser(null);
  };

  // If user is logged out (null), show a simple message or re-enable login
  if (!user) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Logged Out</h2>
          <p className="text-gray-600 mb-4">You have been logged out successfully.</p>
          <button
            onClick={() => setUser({
              id: '2',
              email: 'user@dms.com',
              name: 'Regular User',
              role: 'user'
            })}
            className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors"
          >
            Login Again
          </button>
        </div>
      </div>
    );
  }

  // Directly render Dashboard with the hardcoded user
  return (
    <div className="App">
      <Dashboard user={user} onLogout={handleLogout} />
    </div>
  );
}

export default App;