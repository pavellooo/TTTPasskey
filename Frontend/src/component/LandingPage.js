import React from 'react';
import { useNavigate } from 'react-router-dom';

function LandingPage() {
  const navigate = useNavigate();

  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h1>Welcome to the App</h1>
      <p>Please log in or register to continue.</p>
      <button 
        onClick={() => navigate('/login')} 
        style={{ margin: '10px', padding: '10px 20px', fontSize: '16px' }}
      >
        Login / Register
      </button>
    </div>
  );
}

export default LandingPage;