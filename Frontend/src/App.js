import './App.css';
import { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import Passkey from './component/passkey.js';
import Board from './component/Board';
import ProtectedRoute from './component/ProtectedRoute';
import LandingPage from './component/LandingPage.js';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false); // Authentication state
  return (
    //original code 
/*    <div className="App">
      <Passkey />
    </div> 
    
    //modified code v1
    <Routes>
      <Route path = "/" element = {<Passkey />} />
	  // this looks like a hacked way of invoking authentication 
      <Route path = "/tictactoe" element = {<Board />} />
    </Routes>
  ); */

    //modified code v2, with protected routing and default landing page
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<Passkey setIsAuthenticated={setIsAuthenticated} />} />
      
      <Route
        path="/tictactoe"
        element={
          <ProtectedRoute
            element={<Board />}
            isAuthenticated={isAuthenticated}
          />
        }
      />
    </Routes>
  );
}

export default App;
