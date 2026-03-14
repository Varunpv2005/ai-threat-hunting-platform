import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import SOCDashboard from './SOCDashboard.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <SOCDashboard />
  </StrictMode>
)
