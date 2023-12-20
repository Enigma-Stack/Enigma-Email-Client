
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Main from './Main';
import Page1 from './Page1';
import Page2 from './Page2'

//import EmailPage from './EmailPage/EmailPage';

//import EthereumProvider from './EthereumProvider'

const App = () => {
  return (
    
    <Router>
      <Routes>
      {/* <Route path="/" element={<EmailPage/>} /> */}


        <Route path="/" element={<Main />} />
        <Route path="/signup" element={<Page1 />} />
        <Route path="/mail" element={<Page2 />} />
      </Routes>
    </Router>

  );
}

export default App;